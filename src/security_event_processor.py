import json
import re
import os
from collections import defaultdict
from datetime import datetime, timezone
from service_desk_integration import create_ticket
from security_rules_dict import rule_dictionary

class SecurityEventProcessor:
    """
    A processor for ingesting, normalizing, and applying rules to security events 
    from multiple sources including JSON files and log files.
    """

    def __init__(self):
        """
        Initialize the processor with empty normalized events list and a default 
        rule dictionary for aggregation and alerts.
        """
        self.normalized_events = []
        self.aggregation_window = defaultdict(list)
        # Use the imported rule dictionary
        self.rule_dictionary = rule_dictionary

    # --- Ingest functions ---
    def ingest_json(self, file_path, nested=False):
        """
        Load events from a JSON file.
        Args:
            file_path (str): Path to the JSON file.
            nested (bool): Whether the event is nested inside a JSON object.
        Returns:
            list: List of event dictionaries.
        """
        with open(file_path) as f:
            data = json.load(f)
        events = []
        for e in data:
            if nested:
                event_data = e.get("event", {})
                events.append({
                    "timestamp": e.get("time"),
                    "host_or_source": e.get("host"),
                    "event_type": event_data.get("message"),
                    "user": event_data.get("user"),
                    "severity": event_data.get("severity"),
                    "raw_source": e.get("source")
                })
            else:
                events.append(e)
        return events

    def ingest_logs(self, file_path):
        """
        Load semi-structured events from a log file using regex.
        Args:            file_path (str): Path to the log file.
        Returns:            list: List of event dictionaries.
        """
        events = []
        log_regex = re.compile(
            r"(?P<date>\d+-\d+-\d+) (?P<time>\d+:\d+:\d+) (?P<host>\S+) "
            r"(?P<severity>\S+) (?P<event_type>\S+) user=(?P<user>\S+) token=(?P<token>\S+)"
        )
        with open(file_path) as f:
            for line in f:
                line = line.strip()
                match = log_regex.match(line)
                if match:
                    data = match.groupdict()
                    dt_str = f"{data['date']} {data['time']}"
                    events.append({
                        "timestamp": dt_str,
                        "host_or_source": data["host"],
                        "event_type": data["event_type"],
                        "user": data["user"],
                        "severity": data["severity"],
                        "token": data["token"],
                        "raw_source": "LogFile"
                    })
        return events

    # --- Normalization ---

    def normalize(self, events):
        """
        Normalize events to a consistent schema, map severities, and convert timestamps to UTC.
        Args:            events (list): List of raw event dictionaries.
        Returns:            list: List of normalized event dictionaries.
        """
        severity_mapping = {
            "INFO": "Low",
            "WARN": "Medium",
            "ERROR": "High",
            "High": "High",
            "Medium": "Medium",
            "Low": "Low",
            "Critical": "Critical"
        }
        normalized = []
        for e in events:
            try:
                raw_ts = e.get("timestamp") or e.get("time")
                # Convert epoch integer to UTC ISO
                if isinstance(raw_ts, int):
                    dt_utc = datetime.fromtimestamp(raw_ts, tz=timezone.utc)
                # Convert ISO string (with or without offset) to UTC
                else:
                    dt = datetime.fromisoformat(str(raw_ts))
                    dt_utc = dt.astimezone(timezone.utc)

                norm_event = {
                    "id": e.get("id", f"{e.get('host_or_source', e.get('host'))}_{raw_ts}"),
                    "timestamp": dt_utc.isoformat(),
                    "host_or_source": e.get("host_or_source") or e.get("host"),
                    "event_type": e.get("event_type") or e.get("event", {}).get("message"),
                    "severity": severity_mapping.get(e.get("severity") or e.get("event", {}).get("severity"), "Medium"),
                    "user": e.get("user") or e.get("event", {}).get("user"),
                    "raw_source": e.get("raw_source") or e.get("source")
                }
                normalized.append(norm_event)
            except Exception as err:
                print(f"Skipping malformed record: {err}")
        self.normalized_events.extend(normalized)
        return normalized
    # --- Rule Processing ---
    def process_rules(self):
        """
        Apply rules from the rule dictionary to detect aggregated or alert-worthy events.
        Returns:            list: List of triggered ticket or alert messages.
        """
        triggered = []
        # Count events per type
        event_counts = defaultdict(list)
        for e in self.normalized_events:
            etype = e["event_type"]
            if etype in self.rule_dictionary:
                event_counts[etype].append(e)

        for etype, events in event_counts.items():
            rule = self.rule_dictionary[etype]
            if rule["action"] == "aggregate" and len(events) >= rule.get("threshold", 1):
                triggered.append(f"[{rule['ticket_type']} Ticket] Aggregated {len(events)} events of type '{etype}'")
            elif rule["action"] == "alert":
                for ev in events:
                    triggered.append(f"[{rule['ticket_type']} Ticket] Alert triggered for '{etype}' on host {ev['host_or_source']}")

        return triggered

    # --- Output ---
    def write_normalized(self, output_file="normalized_events.json"):
        """
        Write the normalized events to a JSON file.
        Args:            output_file (str): Path to output JSON file.
        """
        with open(output_file, "w") as f:
            json.dump(self.normalized_events, f, indent=2)
        print(f"Normalized events written to {output_file}")



    def generate_summary_report(self, output_file="summary_report.json"):
        summary = {
            "total_events": len(self.normalized_events),
            "by_severity": {},
            "top_event_types": {},
            "alerts_triggered": self.process_rules()
        }

        for e in self.normalized_events:
            sev = e["severity"]
            summary["by_severity"][sev] = summary["by_severity"].get(sev, 0) + 1

            et = e["event_type"]
            summary["top_event_types"][et] = summary["top_event_types"].get(et, 0) + 1

        with open(output_file, "w") as f:
            json.dump(summary, f, indent=2)

        print(f"Summary report written to {output_file}")

# --- Main Execution ---
if __name__ == "__main__":
    """
    Main workflow:
    1. Load JSON datasets and messy logs
    2. Normalize all events
    3. Write normalized output
    4. Apply rule dictionary to detect alerts/aggregations
    """
    processor = SecurityEventProcessor()

    # --- Dynamically determine project root and data folder ---
    BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))  # project root
    DATA_DIR = os.path.join(BASE_DIR, "log_data")

    # --- Ingest events ---
    av_events = processor.ingest_json(os.path.join(DATA_DIR, "events_av.json"))
    splunk_events = processor.ingest_json(os.path.join(DATA_DIR, "events_splunk.json"), nested=True)
    log_events = processor.ingest_logs(os.path.join(DATA_DIR, "messy_logs.log"))

    # --- Normalize all events ---
    processor.normalize(av_events)
    processor.normalize(splunk_events)
    processor.normalize(log_events)

    # --- Write normalized JSON consistently in log_data/ ---
    normalized_path = os.path.join(DATA_DIR, "normalized_events.json")
    processor.write_normalized(normalized_path)

    # --- Generate summary report in same folder ---
    summary_path = os.path.join(DATA_DIR, "summary_report.json")
    processor.generate_summary_report(summary_path)

    # --- Process rule dictionary ---
    tickets = processor.process_rules()
    print("\nTriggered Tickets / Alerts:")
    for t in tickets:
        print(t)