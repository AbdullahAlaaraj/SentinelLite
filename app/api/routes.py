from fastapi import APIRouter, UploadFile, File
from fastapi.responses import HTMLResponse, RedirectResponse
from datetime import datetime

from app.db.database import cursor, conn
from app.parsers.linux_auth import parse_linux_auth
from app.rules.registry import run_rules

router = APIRouter()


def ensure_uploads_table():
    cursor.execute("""
    CREATE TABLE IF NOT EXISTS uploads (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        filename TEXT,
        uploaded_at TEXT,
        parsed_lines INTEGER
    )
    """)
    conn.commit()


ensure_uploads_table()


def navbar():
    return """
    <div class="navbar">
        <a href="/">Home</a>
        <a href="/">Upload Log</a>
        <a href="/alerts">Alerts</a>
        <a href="/logs">Logs</a>
    </div>
    """


def styles():
    return """
    <style>
        body {
            font-family: Arial, sans-serif;
            background: #020617;
            color: white;
            margin: 0;
            padding: 40px;
        }

        .navbar {
            position: absolute;
            top: 25px;
            right: 50px;
        }

        .navbar a {
            margin-left: 25px;
            color: #38bdf8;
            text-decoration: none;
            font-weight: bold;
            transition: 0.2s;
        }

        .navbar a:hover {
            color: white;
        }

        .hero {
            margin-top: 80px;
            margin-bottom: 40px;
        }

        .hero h1 {
            font-size: 42px;
            margin-bottom: 10px;
        }

        .hero p {
            color: #94a3b8;
            font-size: 18px;
        }

        .grid {
            display: grid;
            grid-template-columns: repeat(4, 1fr);
            gap: 20px;
            margin-top: 40px;
        }

        .metric {
            background: #0f172a;
            padding: 25px;
            border-radius: 14px;
            border: 1px solid #1e293b;
            text-align: center;
        }

        .metric h2 {
            color: #38bdf8;
            font-size: 28px;
            margin: 0;
        }

        .metric p {
            color: #94a3b8;
        }

        .card {
            background: #0f172a;
            padding: 25px;
            border-radius: 14px;
            border: 1px solid #1e293b;
            margin-top: 25px;
        }

        button {
            padding: 12px 20px;
            background: #38bdf8;
            border: none;
            border-radius: 8px;
            font-weight: bold;
            cursor: pointer;
        }

        button:hover {
            background: #0ea5e9;
        }

        table {
            width: 100%;
            border-collapse: collapse;
            background: #0f172a;
            margin-top: 30px;
            border-radius: 12px;
            overflow: hidden;
        }

        th, td {
            padding: 14px;
            border: 1px solid #1e293b;
            text-align: left;
        }

        th {
            background: #1e293b;
        }

        .high {
            color: #ef4444;
            font-weight: bold;
        }

        .status {
            color: #22c55e;
            font-weight: bold;
        }

        .upload-box {
            border: 2px dashed #38bdf8;
            padding: 35px;
            border-radius: 12px;
            text-align: center;
            margin: 20px 0;
            background: #020617;
        }

        .upload-box input {
            color: white;
            padding: 10px;
        }

        .upload-note {
            color: #64748b;
            margin-top: 15px;
        }
    </style>
    """


@router.get("/", response_class=HTMLResponse)
def home():
    cursor.execute("SELECT COUNT(*) FROM uploads")
    uploads = cursor.fetchone()[0]

    cursor.execute("SELECT COUNT(*) FROM alerts")
    alerts = cursor.fetchone()[0]

    return f"""
    <html>
    <head>
        <title>SentinelLite Dashboard</title>
        {styles()}
    </head>
    <body>

        {navbar()}

        <div class="hero">
            <h1>SentinelLite</h1>
            <p>SIEM-inspired authentication log analysis platform</p>
        </div>

        <div class="grid">
            <div class="metric">
                <h2>{uploads}</h2>
                <p>Uploads</p>
            </div>
            <div class="metric">
                <h2>{alerts}</h2>
                <p>Alerts</p>
            </div>
            <div class="metric">
                <h2>1</h2>
                <p>Detection Rules</p>
            </div>
            <div class="metric">
                <h2 class="status">ACTIVE</h2>
                <p>System Status</p>
            </div>
        </div>

        <div class="card">
            <h2>Upload Authentication Log</h2>
            <p style="color:#94a3b8;">
                Select a Linux authentication log file for threat analysis
            </p>

            <form action="/upload-log" enctype="multipart/form-data" method="post">
                <div class="upload-box">
                    <input name="file" type="file">
                    <p class="upload-note">Supported: .log / .txt</p>
                </div>

                <button type="submit">Analyze Log</button>
            </form>
        </div>

        <div class="card">
            <h2>Platform Overview</h2>
            <p>
                Analyze uploaded authentication logs, detect brute-force activity,
                persist security alerts, and review historical ingestion events.
            </p>
        </div>

    </body>
    </html>
    """


@router.post("/upload-log")
async def upload_log(file: UploadFile = File(...)):
    contents = await file.read()
    lines = contents.decode("utf-8").splitlines()

    parsed_logs = []

    for line in lines:
        parsed = parse_linux_auth(line)
        if parsed:
            parsed_logs.append(parsed)

    upload_time = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    cursor.execute(
        "INSERT INTO uploads (filename, uploaded_at, parsed_lines) VALUES (?, ?, ?)",
        (file.filename, upload_time, len(parsed_logs))
    )

    alerts = run_rules(parsed_logs)

    for alert in alerts:
        cursor.execute(
            "INSERT INTO alerts (timestamp, rule, severity, source_ip, description) VALUES (?, ?, ?, ?, ?)",
            (
                upload_time,
                alert["rule"],
                alert["severity"],
                alert["source_ip"],
                alert["description"]
            )
        )

    conn.commit()

    return RedirectResponse(url="/alerts", status_code=303)


@router.get("/alerts", response_class=HTMLResponse)
def alerts():
    cursor.execute("SELECT * FROM alerts")
    rows = cursor.fetchall()

    html = f"""
    <html>
    <head>
        <title>Alerts</title>
        {styles()}
    </head>
    <body>
        {navbar()}
        <div class="hero">
            <h1>Security Alerts</h1>
        </div>

        <table>
            <tr>
                <th>ID</th>
                <th>Timestamp</th>
                <th>Rule</th>
                <th>Severity</th>
                <th>Source IP</th>
                <th>Description</th>
            </tr>
    """

    for row in rows:
        html += f"""
        <tr>
            <td>{row[0]}</td>
            <td>{row[1]}</td>
            <td>{row[2]}</td>
            <td class="high">{row[3]}</td>
            <td>{row[4]}</td>
            <td>{row[5]}</td>
        </tr>
        """

    html += "</table></body></html>"
    return html


@router.get("/logs", response_class=HTMLResponse)
def logs():
    cursor.execute("SELECT * FROM uploads")
    rows = cursor.fetchall()

    html = f"""
    <html>
    <head>
        <title>Upload History</title>
        {styles()}
    </head>
    <body>
        {navbar()}
        <div class="hero">
            <h1>Upload History</h1>
        </div>

        <table>
            <tr>
                <th>ID</th>
                <th>Filename</th>
                <th>Upload Time</th>
                <th>Parsed Lines</th>
            </tr>
    """

    for row in rows:
        html += f"""
        <tr>
            <td>{row[0]}</td>
            <td>{row[1]}</td>
            <td>{row[2]}</td>
            <td>{row[3]}</td>
        </tr>
        """

    html += "</table></body></html>"
    return html


@router.get("/stats")
def stats():
    cursor.execute("SELECT COUNT(*) FROM alerts")
    count = cursor.fetchone()[0]
    return {"alerts": count}


@router.get("/rules")
def rules():
    return ["BruteForceRule"]