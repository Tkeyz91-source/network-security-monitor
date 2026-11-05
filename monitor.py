import csv
from collections import Counter, defaultdict
from pathlib import Path

BASE_DIR = Path(__file__).resolve().parent
DATA_FILE = BASE_DIR / "data" / "network_traffic.csv"
REPORT_DIR = BASE_DIR / "reports"
REPORT_FILE = REPORT_DIR / "network_security_report.txt"

def analyze_network():
    if not DATA_FILE.exists():
        print("Error: Network traffic data file not found.")
        return

    source_counts = Counter()
    blocked_counts = Counter()
    alerts = []
    total_connections = 0
    total_bytes = 0

    with DATA_FILE.open("r", newline="") as file:
        reader = csv.DictReader(file)

        for row in reader:
            total_connections += 1

            source_ip = row["source_ip"]
            destination_ip = row["destination_ip"]
            status = row["connection_status"].lower()
            traffic_bytes = int(row["bytes"])

            source_counts[source_ip] += 1
            total_bytes += traffic_bytes

            if status == "blocked":
                blocked_counts[source_ip] += 1

            if traffic_bytes > 50000:
                alerts.append(
                    f"[HIGH TRAFFIC] {source_ip} transferred "
                    f"{traffic_bytes} bytes to {destination_ip}"
                )

    for source_ip, count in blocked_counts.items():
        if count >= 3:
            alerts.append(
                f"[REPEATED BLOCKED CONNECTIONS] "
                f"{source_ip}: {count} attempts"
            )

    REPORT_DIR.mkdir(exist_ok=True)

    report = [
        "===== NETWORK SECURITY MONITORING REPORT =====",
        f"Total connections: {total_connections}",
        f"Total traffic: {total_bytes} bytes",
        "",
        "CONNECTIONS BY SOURCE IP"
    ]

    for source_ip, count in source_counts.most_common():
        report.append(f"{source_ip}: {count} connections")

    report.extend(["", "BLOCKED CONNECTIONS"])

    if blocked_counts:
        for source_ip, count in blocked_counts.items():
            report.append(f"{source_ip}: {count} blocked attempts")
    else:
        report.append("No blocked connections recorded.")

    report.extend(["", "SECURITY ALERTS"])

    if alerts:
        report.extend(alerts)
    else:
        report.append("No alerts detected.")

    report.append("")
    report.append("Note: Results are based on simulated network data.")

    report_text = "\n".join(report)

    REPORT_FILE.write_text(report_text, encoding="utf-8")

    print(report_text)
    print(f"\nReport saved to: {REPORT_FILE}")


if __name__ == "__main__":
    analyze_network()
