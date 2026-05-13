from app.rules.base import BaseRule


class BruteForceRule(BaseRule):
    name = "Brute Force Detection"

    def evaluate(self, logs):
        failed_logs = [log for log in logs if log["status"] == "failed"]

        if len(failed_logs) >= 5:
            return {
                "rule": self.name,
                "severity": "HIGH",
                "source_ip": failed_logs[0]["source_ip"],
                "description": f"{len(failed_logs)} failed SSH logins detected"
            }

        return None