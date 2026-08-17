import csv
import random
from datetime import datetime, timedelta
from pathlib import Path

random.seed(42)

output_file = (
    Path(__file__).resolve().parents[1]
    / "data"
    / "firewall_logs.csv"
)

events = []


def add_event(action, src_ip, src_zone, dest_ip,
              dest_zone, port, protocol, rule_id, message):

    timestamp = datetime.now() - timedelta(
        minutes=random.randint(0, 720)
    )

    events.append({
        "timestamp": timestamp.strftime("%Y-%m-%d %H:%M:%S"),
        "device": "STREAMNET-FW01",
        "action": action,
        "src_ip": src_ip,
        "src_zone": src_zone,
        "dest_ip": dest_ip,
        "dest_zone": dest_zone,
        "dest_port": port,
        "protocol": protocol,
        "rule_id": rule_id,
        "bytes": random.randint(500, 50000),
        "message": message
    })


# Normal employee HTTPS traffic
for _ in range(350):
    add_event(
        "ALLOW",
        f"10.0.10.{random.randint(10, 80)}",
        "employee",
        "10.0.20.10",
        "server",
        443,
        "TCP",
        101,
        "Approved HTTPS traffic"
    )

# Normal DNS traffic
for _ in range(80):
    add_event(
        "ALLOW",
        f"10.0.10.{random.randint(10, 80)}",
        "employee",
        "10.0.20.53",
        "server",
        53,
        "UDP",
        102,
        "Approved DNS traffic"
    )

# Blocked external SSH attempts
for _ in range(45):
    add_event(
        "DENY",
        f"198.51.100.{random.randint(10, 200)}",
        "internet",
        "10.0.20.10",
        "server",
        22,
        "TCP",
        201,
        "External SSH attempt blocked"
    )

# Dangerous temporary firewall rule
for _ in range(15):
    add_event(
        "ALLOW",
        f"203.0.113.{random.randint(10, 200)}",
        "internet",
        "10.0.20.10",
        "server",
        22,
        "TCP",
        999,
        "External SSH allowed by temporary rule"
    )

# Legitimate administrator SSH
for _ in range(10):
    add_event(
        "ALLOW",
        "10.0.10.50",
        "admin",
        "10.0.20.10",
        "server",
        22,
        "TCP",
        103,
        "Approved administrator SSH"
    )


events.sort(key=lambda event: event["timestamp"])

with open(output_file, "w", newline="") as file:
    writer = csv.DictWriter(
        file,
        fieldnames=events[0].keys()
    )
    writer.writeheader()
    writer.writerows(events)


print(f"Created {len(events)} firewall events")
print(f"Saved to: {output_file}")

