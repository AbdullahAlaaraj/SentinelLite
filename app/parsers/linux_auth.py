import re


def parse_linux_auth(line: str):
    pattern = r"(\w+\s+\d+\s+\d+:\d+:\d+).*Failed password for (\w+) from ([0-9.]+)"

    match = re.search(pattern, line)

    if not match:
        return None

    return {
        "timestamp": match.group(1),
        "username": match.group(2),
        "source_ip": match.group(3),
        "status": "failed",
        "event_type": "ssh_login"
    }