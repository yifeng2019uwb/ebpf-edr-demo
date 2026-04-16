#!/usr/bin/env python3
"""
EDR Agent — reads bpftrace JSON output from stdin, matches events against
detection rules, prints alerts, and appends to alerts/alert.log.
"""

import sys
import json
import yaml
import os
import datetime

RULES_PATH = os.path.join(os.path.dirname(__file__), "../rules/rules.yaml")
ALERTS_LOG = os.path.join(os.path.dirname(__file__), "../alerts/alert.log")


def load_rules(path):
    with open(path, "r") as f:
        return yaml.safe_load(f)


def is_suppressed(event, baseline):
    for entry in baseline.get("suppress", []):
        parent_match = entry.get("parent", "") in event.get("parent", "")
        path_val = entry.get("path_contains", "")
        path_match = path_val == "" or path_val in event.get("path", "")
        if parent_match and path_match:
            return True
    return False


def match_rule(event, rule):
    condition = rule.get("condition", {})

    if "parent_contains" in condition:
        parent = event.get("parent", "")
        if not any(p in parent for p in condition["parent_contains"]):
            return False
        if "path_contains" in condition:
            path = event.get("path", "")
            if not any(p in path for p in condition["path_contains"]):
                return False

    if "path_startswith" in condition:
        path = event.get("path", "")
        if not any(path.startswith(p) for p in condition["path_startswith"]):
            return False

    return True


def format_alert(event, rule):
    timestamp = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    return (
        f"[{timestamp}] ALERT "
        f"severity={rule['severity']} "
        f"rule={rule['name']} "
        f"pid={event.get('pid', '?')} "
        f"parent={event.get('parent', '?')} "
        f"path={event.get('path', '?')}"
    )


def write_log(alert_line):
    os.makedirs(os.path.dirname(ALERTS_LOG), exist_ok=True)
    with open(ALERTS_LOG, "a") as f:
        f.write(alert_line + "\n")


def main():
    config = load_rules(RULES_PATH)
    rules = config.get("rules", [])
    baseline = config.get("baseline", {})

    print("[EDR Agent] Started — reading bpftrace events from stdin...")

    for line in sys.stdin:
        line = line.strip()
        if not line:
            continue

        try:
            event = json.loads(line)
        except json.JSONDecodeError:
            continue

        if is_suppressed(event, baseline):
            continue

        for rule in rules:
            if match_rule(event, rule):
                alert = format_alert(event, rule)
                print(alert)
                write_log(alert)
                break


if __name__ == "__main__":
    main()
