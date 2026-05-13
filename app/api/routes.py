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


@router.get("/", response_class=HTMLResponse)
def home():
    return """
    <html>
        <head>
            <title>SentinelLite Dashboard</title>
            <style>
                body {
                    font-family: Arial;
                    background: #0f172a;
                    color: white;
                    padding: 40px;
                }

                .navbar {
                    position: absolute;
                    top: 20px;
                    right: 40px;
                }

                .navbar a {
                    margin-left: 20px;
                    color: #38bdf8;
                    text-decoration: none;
                    font-weight: bold;
                }

                .card {
                    background: #1e293b;
                    padding: 20px;
                    margin: 20px 0;
                    border-radius: 10px;
                }

                button {
                    padding: 10px;
                    background: #38bdf8;
                    border: none;
                    cursor: pointer;
                }

                a {
                    color: #38bdf8;
                    text-decoration: none;
                }
            </style>
        </head>
        <body>

            <div class="navbar">
                <a href="/">Home</a>
                <a href="/">Upload Log</a>
                <a href="/alerts">Alerts</a>
                <a href="/logs">Logs</a>
            </div>

            <h1>SentinelLite Dashboard</h1>

            <div class="card">
                <h2>Upload Log File</h2>
                <form action="/upload-log" enctype="multipart/form-data" method="post">
                    <input name="file" type="file">
                    <button type="submit">Upload</button>
                </form>
            </div>

            <div class="card">
                <a href="/alerts">View Alerts</a>
            </div>

            <div class="card">
                <a href="/logs">View Upload History</a>
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
        (
            file.filename,
            upload_time,
            len(parsed_logs)
        )
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

    html = """
    <html>
    <head>
        <title>SentinelLite Alerts</title>
        <style>
            body {
                font-family: Arial;
                background: #0f172a;
                color: white;
                padding: 40px;
            }

            .navbar {
                position: absolute;
                top: 20px;
                right: 40px;
            }

            .navbar a {
                margin-left: 20px;
                color: #38bdf8;
                text-decoration: none;
                font-weight: bold;
            }

            table {
                width: 100%;
                border-collapse: collapse;
                background: #1e293b;
                margin-top: 40px;
            }

            th, td {
                padding: 12px;
                border: 1px solid #334155;
                text-align: left;
            }

            th {
                background: #334155;
            }

            .high {
                color: red;
                font-weight: bold;
            }
        </style>
    </head>
    <body>

        <div class="navbar">
            <a href="/">Home</a>
            <a href="/">Upload Log</a>
            <a href="/alerts">Alerts</a>
            <a href="/logs">Logs</a>
        </div>

        <h1>SentinelLite Alerts</h1>

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
                <td class='high'>{row[3]}</td>
                <td>{row[4]}</td>
                <td>{row[5]}</td>
            </tr>
        """

    html += """
        </table>
    </body>
    </html>
    """

    return html


@router.get("/logs", response_class=HTMLResponse)
def logs():
    cursor.execute("SELECT * FROM uploads")
    rows = cursor.fetchall()

    html = """
    <html>
    <head>
        <title>SentinelLite Upload History</title>
        <style>
            body {
                font-family: Arial;
                background: #0f172a;
                color: white;
                padding: 40px;
            }

            .navbar {
                position: absolute;
                top: 20px;
                right: 40px;
            }

            .navbar a {
                margin-left: 20px;
                color: #38bdf8;
                text-decoration: none;
                font-weight: bold;
            }

            table {
                width: 100%;
                border-collapse: collapse;
                background: #1e293b;
                margin-top: 40px;
            }

            th, td {
                padding: 12px;
                border: 1px solid #334155;
                text-align: left;
            }

            th {
                background: #334155;
            }
        </style>
    </head>
    <body>

        <div class="navbar">
            <a href="/">Home</a>
            <a href="/">Upload Log</a>
            <a href="/alerts">Alerts</a>
            <a href="/logs">Logs</a>
        </div>

        <h1>Uploaded Logs</h1>

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

    html += """
        </table>
    </body>
    </html>
    """

    return html


@router.get("/stats")
def stats():
    cursor.execute("SELECT COUNT(*) FROM alerts")
    count = cursor.fetchone()[0]

    return {"alerts": count}


@router.get("/rules")
def rules():
    return ["BruteForceRule"]