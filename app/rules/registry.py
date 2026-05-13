from app.rules.brute_force import BruteForceRule


RULES = [
    BruteForceRule()
]


def run_rules(logs):
    alerts = []

    for rule in RULES:
        result = rule.evaluate(logs)

        if result:
            alerts.append(result)

    return alerts