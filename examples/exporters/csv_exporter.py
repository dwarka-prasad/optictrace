#!/usr/bin/env python3
"""Example OpticTrace output plugin: convert governed records to CSV.

The plugin contract is one JSON record per stdin line — write to any
destination you like (Kafka, S3, a SIEM, a data warehouse...). Records are
already governed: restricted routes carry no payloads and redacted fields
arrive masked, so plugins can never see raw sensitive data.

Wire it up in optic.yaml:

    telemetry:
      exporters:
        - name: csv-archive
          type: command
          command: ["python3", "examples/exporters/csv_exporter.py", "api_traffic.csv"]

stderr is forwarded into the agent's log — use it for plugin diagnostics.
"""

import csv
import json
import sys

FIELDS = [
    "time", "service", "method", "path", "route", "status",
    "duration_ms", "source", "req_bytes", "resp_bytes",
    "matched_rules", "labels",
]


def main() -> None:
    out_path = sys.argv[1] if len(sys.argv) > 1 else "optictrace_export.csv"
    with open(out_path, "a", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=FIELDS, extrasaction="ignore")
        if f.tell() == 0:
            writer.writeheader()
        shipped = 0
        for line in sys.stdin:  # one governed JSON record per line
            try:
                record = json.loads(line)
            except json.JSONDecodeError as exc:
                print(f"skipping malformed line: {exc}", file=sys.stderr)
                continue
            record["matched_rules"] = " ".join(record.get("matched_rules") or [])
            record["labels"] = json.dumps(record.get("labels") or {})
            writer.writerow(record)
            f.flush()
            shipped += 1
        print(f"csv_exporter: shipped {shipped} records to {out_path}", file=sys.stderr)


if __name__ == "__main__":
    main()
