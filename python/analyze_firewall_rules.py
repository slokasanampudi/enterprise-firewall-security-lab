import csv
import ipaddress

RULES_FILE = "data/firewall_rules.csv"
REPORT_FILE = "reports/firewall_rule_risk_report.csv"


def analyze_rule(rule):
    score = 0
    reasons = []

    src_zone = rule["src_zone"]
    dest_ip = rule["dest_ip"]
    dest_port = int(rule["dest_port"])
    action = rule["action"]
    temporary = rule["temporary"].lower() == "true"

    if action == "ALLOW" and src_zone == "internet":
        score += 40
        reasons.append("Allows traffic from the Internet")

    if action == "ALLOW" and src_zone == "internet" and dest_port == 22:
        score += 30
        reasons.append("Exposes SSH to the Internet")

    if action == "ALLOW" and temporary:
        score += 20
        reasons.append("Temporary firewall rule is enabled")

    if (
        action == "ALLOW"
        and src_zone == "internet"
        and ipaddress.ip_address(dest_ip).is_private
    ):
        score += 10
        reasons.append("Internet traffic can reach an internal IP")

    if score >= 80:
        risk = "CRITICAL"
    elif score >= 50:
        risk = "HIGH"
    elif score >= 20:
        risk = "MEDIUM"
    else:
        risk = "LOW"

    if not reasons:
        reasons.append("No significant exposure detected")

    return score, risk, reasons


results = []

with open(RULES_FILE, newline="") as file:
    reader = csv.DictReader(file)

    for rule in reader:
        score, risk, reasons = analyze_rule(rule)

        results.append({
            "rule_id": rule["rule_id"],
            "rule_name": rule["rule_name"],
            "risk": risk,
            "score": score,
            "reasons": "; ".join(reasons)
        })

        print(f"\nRule {rule['rule_id']} - {rule['rule_name']}")
        print(f"Risk: {risk}")
        print(f"Score: {score}")
        print(f"Reason: {'; '.join(reasons)}")


with open(REPORT_FILE, "w", newline="") as file:
    fieldnames = ["rule_id", "rule_name", "risk", "score", "reasons"]
    writer = csv.DictWriter(file, fieldnames=fieldnames)

    writer.writeheader()
    writer.writerows(results)


print(f"\nReport saved to {REPORT_FILE}")
