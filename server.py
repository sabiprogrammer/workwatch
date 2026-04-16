"""
WorkWatch Backend Server — Production Ready v2.0
Fixes applied:
  1. Proper error handling on all DB operations (no silent crashes)
  2. EOD report endpoint + auto-email to manager at 5pm daily
  3. Rotating file logger for all server activity
  4. Input validation on all agent payloads
Run: uvicorn server:app --host 0.0.0.0 --port 8000
"""

import os
import re
import json
import sqlite3
import hashlib
import logging
import smtplib
import threading
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from datetime import datetime, date, timedelta
from pathlib import Path
from typing import Optional
from contextlib import contextmanager
from logging.handlers import RotatingFileHandler

from fastapi import FastAPI, HTTPException, Depends, Header
from fastapi.staticfiles import StaticFiles
from fastapi.responses import FileResponse
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, field_validator

# ── LOGGING SETUP (Fix #3) ────────────────────────────────────────────────────
LOG_DIR = Path("logs")
LOG_DIR.mkdir(exist_ok=True)

logger = logging.getLogger("workwatch")
logger.setLevel(logging.INFO)
fh = RotatingFileHandler(LOG_DIR / "server.log", maxBytes=5_000_000, backupCount=7)
fh.setFormatter(logging.Formatter("%(asctime)s [%(levelname)s] %(message)s"))
ch = logging.StreamHandler()
ch.setFormatter(logging.Formatter("[%(levelname)s] %(message)s"))
logger.addHandler(fh)
logger.addHandler(ch)

# ── CONFIG ────────────────────────────────────────────────────────────────────
DB_PATH        = Path("workwatch.db")
STATIC_DIR     = Path("static")
ADMIN_PASSWORD = os.environ.get("ADMIN_PASSWORD", "admin1234")
SECRET_TOKEN   = hashlib.sha256(ADMIN_PASSWORD.encode()).hexdigest()
MAX_SCREENSHOTS_PER_WORKER_PER_DAY = 100

# Email config — set these as environment variables on Render
SMTP_HOST     = os.environ.get("SMTP_HOST", "smtp.gmail.com")
SMTP_PORT     = int(os.environ.get("SMTP_PORT", "587"))
SMTP_USER     = os.environ.get("SMTP_USER", "")       # Gmail sending address
SMTP_PASS     = os.environ.get("SMTP_PASS", "")       # Gmail app password
MANAGER_EMAIL = os.environ.get("MANAGER_EMAIL", "")   # Your oga's email
EOD_HOUR      = int(os.environ.get("EOD_HOUR", "17")) # 5pm default

app = FastAPI(title="WorkWatch Server", version="2.0")
app.add_middleware(CORSMiddleware, allow_origins=["*"], allow_methods=["*"], allow_headers=["*"])

if STATIC_DIR.exists():
    app.mount("/static", StaticFiles(directory=str(STATIC_DIR)), name="static")

logger.info("WorkWatch server v2.0 starting up...")

# ── DATABASE (Fix #1 — proper error handling) ─────────────────────────────────
@contextmanager
def get_db():
    conn = None
    try:
        conn = sqlite3.connect(str(DB_PATH), timeout=15)
        conn.row_factory = sqlite3.Row
        conn.execute("PRAGMA journal_mode=WAL")
        yield conn
        conn.commit()
    except sqlite3.OperationalError as e:
        logger.error(f"Database operational error: {e}")
        if conn:
            conn.rollback()
        raise HTTPException(status_code=503, detail="Database temporarily unavailable")
    except sqlite3.DatabaseError as e:
        logger.error(f"Database error: {e}")
        if conn:
            conn.rollback()
        raise HTTPException(status_code=500, detail="Database error")
    finally:
        if conn:
            conn.close()

def init_db():
    try:
        with get_db() as db:
            db.executescript("""
            CREATE TABLE IF NOT EXISTS heartbeats (
                id        INTEGER PRIMARY KEY AUTOINCREMENT,
                worker    TEXT NOT NULL,
                timestamp TEXT NOT NULL,
                status    TEXT NOT NULL,
                os        TEXT
            );
            CREATE TABLE IF NOT EXISTS activity (
                id              INTEGER PRIMARY KEY AUTOINCREMENT,
                worker          TEXT NOT NULL,
                timestamp       TEXT NOT NULL,
                active_title    TEXT,
                active_process  TEXT,
                idle_seconds    REAL DEFAULT 0,
                keystrokes      INTEGER DEFAULT 0,
                mouse_moves     INTEGER DEFAULT 0,
                recent_urls     TEXT,
                running_apps    TEXT,
                system_info     TEXT
            );
            CREATE TABLE IF NOT EXISTS screenshots (
                id        INTEGER PRIMARY KEY AUTOINCREMENT,
                worker    TEXT NOT NULL,
                timestamp TEXT NOT NULL,
                image_b64 TEXT NOT NULL
            );
            CREATE TABLE IF NOT EXISTS eod_reports (
                id          INTEGER PRIMARY KEY AUTOINCREMENT,
                report_date TEXT NOT NULL,
                generated   TEXT NOT NULL,
                report_json TEXT NOT NULL
            );
            CREATE INDEX IF NOT EXISTS idx_activity_worker_ts    ON activity(worker, timestamp);
            CREATE INDEX IF NOT EXISTS idx_screenshots_worker_ts ON screenshots(worker, timestamp);
            CREATE INDEX IF NOT EXISTS idx_heartbeats_worker     ON heartbeats(worker, timestamp);
            """)
        logger.info("Database initialised OK")
    except Exception as e:
        logger.critical(f"Failed to initialise database: {e}")
        raise

init_db()

# ── INPUT VALIDATION HELPERS (Fix #4) ────────────────────────────────────────
SAFE_NAME = re.compile(r'^[\w\-\.]{1,64}$')

def sanitise_worker(name: str) -> str:
    name = str(name).strip()
    if not SAFE_NAME.match(name):
        name = re.sub(r'[^\w\-\.]', '_', name)[:64]
    return name

def validate_timestamp(ts: str) -> str:
    try:
        dt  = datetime.fromisoformat(ts)
        now = datetime.now()
        if dt > now + timedelta(hours=1):
            return now.isoformat()
        if dt < now - timedelta(days=366):
            return now.isoformat()
        return ts
    except Exception:
        return datetime.now().isoformat()

# ── AUTH ──────────────────────────────────────────────────────────────────────
def verify_admin(authorization: Optional[str] = Header(None)):
    if not authorization or authorization != f"Bearer {SECRET_TOKEN}":
        logger.warning("Unauthorised dashboard access attempt")
        raise HTTPException(status_code=401, detail="Unauthorized")
    return True

# ── MODELS (Fix #4 — with validation) ────────────────────────────────────────
class HeartbeatPayload(BaseModel):
    worker: str
    timestamp: str
    status: str
    os: Optional[str] = None

    @field_validator("status")
    @classmethod
    def check_status(cls, v):
        if v not in ("online", "offline"):
            raise ValueError("status must be online or offline")
        return v

class ActivityPayload(BaseModel):
    worker: str
    timestamp: str
    active_window: Optional[dict] = None
    idle_seconds: Optional[float] = 0
    keystrokes: Optional[int] = 0
    mouse_moves: Optional[int] = 0
    recent_urls: Optional[list] = []
    running_apps: Optional[dict] = {}
    system: Optional[dict] = {}

    @field_validator("idle_seconds")
    @classmethod
    def cap_idle(cls, v):
        return max(0, min(v or 0, 86400))

    @field_validator("keystrokes", "mouse_moves")
    @classmethod
    def cap_counts(cls, v):
        return max(0, min(v or 0, 1_000_000))

class ScreenshotPayload(BaseModel):
    worker: str
    timestamp: str
    image_b64: str

    @field_validator("image_b64")
    @classmethod
    def check_image(cls, v):
        if len(v) > 8_000_000:
            raise ValueError("Screenshot too large")
        return v

# ── AGENT ENDPOINTS ───────────────────────────────────────────────────────────
@app.post("/api/heartbeat")
def receive_heartbeat(payload: HeartbeatPayload):
    worker = sanitise_worker(payload.worker)
    ts     = validate_timestamp(payload.timestamp)
    try:
        with get_db() as db:
            db.execute(
                "INSERT INTO heartbeats (worker, timestamp, status, os) VALUES (?,?,?,?)",
                (worker, ts, payload.status, payload.os)
            )
        if payload.status == "offline":
            logger.info(f"[{worker}] went offline")
        return {"ok": True}
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Heartbeat error for {worker}: {e}")
        raise HTTPException(status_code=500, detail="Failed to record heartbeat")

@app.post("/api/activity")
def receive_activity(payload: ActivityPayload):
    worker = sanitise_worker(payload.worker)
    ts     = validate_timestamp(payload.timestamp)
    w      = payload.active_window or {}
    try:
        with get_db() as db:
            db.execute("""
                INSERT INTO activity
                  (worker, timestamp, active_title, active_process,
                   idle_seconds, keystrokes, mouse_moves,
                   recent_urls, running_apps, system_info)
                VALUES (?,?,?,?,?,?,?,?,?,?)
            """, (
                worker, ts,
                str(w.get("title", ""))[:200],
                str(w.get("process", ""))[:100],
                payload.idle_seconds,
                payload.keystrokes,
                payload.mouse_moves,
                json.dumps(payload.recent_urls or []),
                json.dumps(payload.running_apps or {}),
                json.dumps(payload.system or {}),
            ))
        return {"ok": True}
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Activity error for {worker}: {e}")
        raise HTTPException(status_code=500, detail="Failed to record activity")

@app.post("/api/screenshot")
def receive_screenshot(payload: ScreenshotPayload):
    worker = sanitise_worker(payload.worker)
    ts     = validate_timestamp(payload.timestamp)
    today  = date.today().isoformat()
    try:
        with get_db() as db:
            count = db.execute(
                "SELECT COUNT(*) FROM screenshots WHERE worker=? AND timestamp LIKE ?",
                (worker, f"{today}%")
            ).fetchone()[0]
            if count >= MAX_SCREENSHOTS_PER_WORKER_PER_DAY:
                return {"ok": True, "skipped": "daily limit reached"}
            db.execute(
                "INSERT INTO screenshots (worker, timestamp, image_b64) VALUES (?,?,?)",
                (worker, ts, payload.image_b64)
            )
        return {"ok": True}
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Screenshot error for {worker}: {e}")
        raise HTTPException(status_code=500, detail="Failed to store screenshot")

# ── EOD REPORT BUILDER (Fix #2) ───────────────────────────────────────────────
def build_eod_report(day: str) -> dict:
    try:
        with get_db() as db:
            workers = [r["worker"] for r in db.execute(
                "SELECT DISTINCT worker FROM activity WHERE timestamp LIKE ?",
                (f"{day}%",)
            ).fetchall()]

            summaries = []
            for w in workers:
                rows = db.execute("""
                    SELECT idle_seconds, keystrokes, mouse_moves,
                           active_process, active_title, timestamp
                    FROM activity WHERE worker=? AND timestamp LIKE ?
                    ORDER BY timestamp
                """, (w, f"{day}%")).fetchall()

                if not rows:
                    continue

                total_mins       = len(rows)
                idle_mins        = sum(1 for r in rows if (r["idle_seconds"] or 0) > 120)
                active_mins      = total_mins - idle_mins
                total_keys       = sum(r["keystrokes"] or 0 for r in rows)
                total_moves      = sum(r["mouse_moves"] or 0 for r in rows)
                productivity_pct = round((active_mins / max(total_mins, 1)) * 100)

                app_counts = {}
                for r in rows:
                    proc = (r["active_process"] or "Unknown").replace(".exe", "")
                    app_counts[proc] = app_counts.get(proc, 0) + 1
                top_apps = sorted(app_counts.items(), key=lambda x: x[1], reverse=True)[:5]

                first_seen = rows[0]["timestamp"].split("T")[1][:5]  if rows else "—"
                last_seen  = rows[-1]["timestamp"].split("T")[1][:5] if rows else "—"

                ss_count = db.execute(
                    "SELECT COUNT(*) FROM screenshots WHERE worker=? AND timestamp LIKE ?",
                    (w, f"{day}%")
                ).fetchone()[0]

                # Concern flags — what your oga cares about most
                flags = []
                if productivity_pct < 30:
                    flags.append("⚠️ Very low productivity")
                if idle_mins > active_mins:
                    flags.append("⚠️ More idle than active time")
                social = {"facebook", "youtube", "whatsapp", "instagram", "twitter", "tiktok", "netflix"}
                social_found = [a for a, _ in top_apps if any(s in a.lower() for s in social)]
                if social_found:
                    flags.append(f"⚠️ Non-work apps: {', '.join(social_found)}")

                summaries.append({
                    "worker":           w,
                    "active_minutes":   active_mins,
                    "idle_minutes":     idle_mins,
                    "total_minutes":    total_mins,
                    "productivity_pct": productivity_pct,
                    "keystrokes":       total_keys,
                    "mouse_moves":      total_moves,
                    "top_apps":         top_apps,
                    "screenshot_count": ss_count,
                    "first_seen":       first_seen,
                    "last_seen":        last_seen,
                    "flags":            flags,
                })

        summaries.sort(key=lambda x: x["productivity_pct"], reverse=True)
        office_avg = round(sum(s["productivity_pct"] for s in summaries) / max(len(summaries), 1))
        return {
            "date":       day,
            "generated":  datetime.now().isoformat(),
            "total_pcs":  len(summaries),
            "office_avg": office_avg,
            "summaries":  summaries,
        }
    except Exception as e:
        logger.error(f"EOD report build error for {day}: {e}")
        return {"date": day, "error": str(e), "summaries": []}

def send_eod_email(report: dict):
    if not SMTP_USER or not MANAGER_EMAIL:
        logger.warning("Email not configured. Set SMTP_USER, SMTP_PASS, MANAGER_EMAIL env vars on Render.")
        return

    day       = report["date"]
    avg       = report.get("office_avg", 0)
    summaries = report.get("summaries", [])

    rows_html = ""
    for s in summaries:
        color  = "#00c853" if s["productivity_pct"] >= 70 else "#ffd740" if s["productivity_pct"] >= 40 else "#ff5252"
        flags  = "<br>".join(s.get("flags", [])) or "✅ No issues"
        apps   = ", ".join(a for a, _ in s["top_apps"][:3]) or "—"
        rows_html += f"""
        <tr>
          <td style="padding:10px 14px;border-bottom:1px solid #eee;font-weight:600">{s['worker']}</td>
          <td style="padding:10px 14px;border-bottom:1px solid #eee;text-align:center">
            <span style="background:{color};color:#000;padding:3px 10px;border-radius:20px;font-weight:700;font-size:13px">{s['productivity_pct']}%</span>
          </td>
          <td style="padding:10px 14px;border-bottom:1px solid #eee;text-align:center">{s['active_minutes']}m</td>
          <td style="padding:10px 14px;border-bottom:1px solid #eee;text-align:center">{s['idle_minutes']}m</td>
          <td style="padding:10px 14px;border-bottom:1px solid #eee;text-align:center">{s['first_seen']} – {s['last_seen']}</td>
          <td style="padding:10px 14px;border-bottom:1px solid #eee;font-size:12px">{apps}</td>
          <td style="padding:10px 14px;border-bottom:1px solid #eee;font-size:12px;color:#e53935">{flags}</td>
        </tr>"""

    html = f"""<html><body style="font-family:Arial,sans-serif;background:#f5f5f5;padding:20px">
    <div style="max-width:900px;margin:0 auto;background:#fff;border-radius:12px;overflow:hidden;box-shadow:0 2px 12px rgba(0,0,0,.1)">
      <div style="background:#0a0c10;padding:28px 32px">
        <h1 style="color:#00e5ff;margin:0;font-size:22px">WorkWatch</h1>
        <p style="color:#6b7280;margin:6px 0 0;font-size:13px">End-of-Day Report — {day}</p>
      </div>
      <div style="padding:24px 32px;border-bottom:1px solid #eee">
        <table><tr>
          <td style="padding-right:40px"><div style="font-size:11px;color:#888;letter-spacing:1px">TOTAL PCs</div><div style="font-size:28px;font-weight:700">{report.get('total_pcs',0)}</div></td>
          <td style="padding-right:40px"><div style="font-size:11px;color:#888;letter-spacing:1px">OFFICE AVG</div><div style="font-size:28px;font-weight:700;color:{'#00c853' if avg>=70 else '#ffd740' if avg>=40 else '#ff5252'}">{avg}%</div></td>
          <td><div style="font-size:11px;color:#888;letter-spacing:1px">TOP PERFORMER</div><div style="font-size:18px;font-weight:700">{summaries[0]['worker'] if summaries else '—'}</div></td>
        </tr></table>
      </div>
      <div style="padding:0 32px 28px">
        <table style="width:100%;border-collapse:collapse;margin-top:20px">
          <thead><tr style="background:#f9f9f9">
            <th style="padding:10px 14px;text-align:left;font-size:11px;color:#888;letter-spacing:1px">WORKER</th>
            <th style="padding:10px 14px;font-size:11px;color:#888;letter-spacing:1px">SCORE</th>
            <th style="padding:10px 14px;font-size:11px;color:#888;letter-spacing:1px">ACTIVE</th>
            <th style="padding:10px 14px;font-size:11px;color:#888;letter-spacing:1px">IDLE</th>
            <th style="padding:10px 14px;font-size:11px;color:#888;letter-spacing:1px">HOURS</th>
            <th style="padding:10px 14px;text-align:left;font-size:11px;color:#888;letter-spacing:1px">TOP APPS</th>
            <th style="padding:10px 14px;text-align:left;font-size:11px;color:#888;letter-spacing:1px">FLAGS</th>
          </tr></thead>
          <tbody>{rows_html}</tbody>
        </table>
      </div>
      <div style="background:#f9f9f9;padding:16px 32px;font-size:12px;color:#aaa;text-align:center">
        WorkWatch — Auto-generated at {datetime.now().strftime('%H:%M')} | Log in to dashboard for screenshots &amp; full logs
      </div>
    </div></body></html>"""

    try:
        msg = MIMEMultipart("alternative")
        msg["Subject"] = f"WorkWatch EOD Report — {day} | Office Avg: {avg}%"
        msg["From"]    = SMTP_USER
        msg["To"]      = MANAGER_EMAIL
        msg.attach(MIMEText(html, "html"))
        with smtplib.SMTP(SMTP_HOST, SMTP_PORT) as smtp:
            smtp.starttls()
            smtp.login(SMTP_USER, SMTP_PASS)
            smtp.send_message(msg)
        logger.info(f"EOD email sent to {MANAGER_EMAIL} for {day}")
    except Exception as e:
        logger.error(f"Failed to send EOD email: {e}")

def eod_scheduler():
    """Background thread — fires EOD report at EOD_HOUR every day."""
    import time
    last_run_date = None
    while True:
        time.sleep(60)
        now   = datetime.now()
        today = date.today().isoformat()
        if now.hour == EOD_HOUR and now.minute == 0 and last_run_date != today:
            last_run_date = today
            logger.info(f"Auto-generating EOD report for {today}...")
            try:
                report = build_eod_report(today)
                with get_db() as db:
                    db.execute(
                        "INSERT INTO eod_reports (report_date, generated, report_json) VALUES (?,?,?)",
                        (today, datetime.now().isoformat(), json.dumps(report))
                    )
                send_eod_email(report)
                logger.info(f"EOD report done: {len(report.get('summaries',[]))} workers")
            except Exception as e:
                logger.error(f"EOD scheduler error: {e}")

threading.Thread(target=eod_scheduler, daemon=True).start()
logger.info(f"EOD scheduler running — reports fire at {EOD_HOUR}:00 daily")

# ── ADMIN / DASHBOARD API ─────────────────────────────────────────────────────
@app.get("/api/workers")
def get_workers(_: bool = Depends(verify_admin)):
    cutoff = (datetime.now() - timedelta(minutes=3)).isoformat()
    try:
        with get_db() as db:
            workers = db.execute("SELECT DISTINCT worker FROM heartbeats").fetchall()
            result  = []
            for row in workers:
                w    = row["worker"]
                last = db.execute(
                    "SELECT status, timestamp FROM heartbeats WHERE worker=? ORDER BY timestamp DESC LIMIT 1",
                    (w,)
                ).fetchone()
                is_online = last and last["status"] == "online" and last["timestamp"] >= cutoff
                result.append({"worker": w, "online": bool(is_online), "last_seen": last["timestamp"] if last else None})
        return result
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"get_workers error: {e}")
        raise HTTPException(status_code=500, detail="Failed to fetch workers")

@app.get("/api/dashboard/summary")
def dashboard_summary(target_date: Optional[str] = None, _: bool = Depends(verify_admin)):
    day = target_date or date.today().isoformat()
    try:
        return build_eod_report(day).get("summaries", [])
    except Exception as e:
        logger.error(f"dashboard_summary error: {e}")
        raise HTTPException(status_code=500, detail="Failed to generate summary")

@app.get("/api/eod-report")
def get_eod_report(target_date: Optional[str] = None, _: bool = Depends(verify_admin)):
    day = target_date or date.today().isoformat()
    try:
        with get_db() as db:
            cached = db.execute(
                "SELECT report_json FROM eod_reports WHERE report_date=? ORDER BY generated DESC LIMIT 1",
                (day,)
            ).fetchone()
        if cached:
            return json.loads(cached["report_json"])
        return build_eod_report(day)
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"get_eod_report error: {e}")
        raise HTTPException(status_code=500, detail="Failed to fetch EOD report")

@app.post("/api/eod-report/send")
def trigger_eod_email(target_date: Optional[str] = None, _: bool = Depends(verify_admin)):
    """Manually trigger the EOD email right now."""
    day    = target_date or date.today().isoformat()
    report = build_eod_report(day)
    send_eod_email(report)
    return {"ok": True, "date": day, "workers": len(report.get("summaries", []))}

@app.get("/api/screenshots/{worker}")
def get_screenshots(worker: str, target_date: Optional[str] = None, _: bool = Depends(verify_admin)):
    day    = target_date or date.today().isoformat()
    worker = sanitise_worker(worker)
    try:
        with get_db() as db:
            rows = db.execute("""
                SELECT id, timestamp, image_b64 FROM screenshots
                WHERE worker=? AND timestamp LIKE ? ORDER BY timestamp DESC
            """, (worker, f"{day}%")).fetchall()
        return [{"id": r["id"], "timestamp": r["timestamp"], "image": r["image_b64"]} for r in rows]
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"get_screenshots error for {worker}: {e}")
        raise HTTPException(status_code=500, detail="Failed to fetch screenshots")

@app.get("/api/activity/{worker}")
def get_worker_activity(worker: str, target_date: Optional[str] = None, _: bool = Depends(verify_admin)):
    day    = target_date or date.today().isoformat()
    worker = sanitise_worker(worker)
    try:
        with get_db() as db:
            rows = db.execute("""
                SELECT timestamp, active_title, active_process,
                       idle_seconds, keystrokes, mouse_moves, recent_urls
                FROM activity WHERE worker=? AND timestamp LIKE ? ORDER BY timestamp
            """, (worker, f"{day}%")).fetchall()
        return [{
            "timestamp":   r["timestamp"],
            "title":       r["active_title"],
            "process":     r["active_process"],
            "idle":        r["idle_seconds"],
            "keystrokes":  r["keystrokes"],
            "mouse_moves": r["mouse_moves"],
            "urls":        json.loads(r["recent_urls"] or "[]"),
        } for r in rows]
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"get_activity error for {worker}: {e}")
        raise HTTPException(status_code=500, detail="Failed to fetch activity")

@app.get("/api/login")
def login(password: str):
    if hashlib.sha256(password.encode()).hexdigest() == SECRET_TOKEN:
        logger.info("Manager dashboard login successful")
        return {"token": SECRET_TOKEN}
    logger.warning("Failed login attempt")
    raise HTTPException(status_code=401, detail="Wrong password")

@app.get("/api/health")
def health_check():
    """Agents call this on startup to confirm server is reachable."""
    return {"status": "ok", "time": datetime.now().isoformat(), "version": "2.0"}

@app.get("/")
def serve_dashboard():
    return FileResponse(str(STATIC_DIR / "index.html"))

# ── RUN ───────────────────────────────────────────────────────────────────────
if __name__ == "__main__":
    import uvicorn
    port = int(os.environ.get("PORT", 8000))
    logger.info(f"Starting on port {port}")
    uvicorn.run("server:app", host="0.0.0.0", port=port, reload=False)
