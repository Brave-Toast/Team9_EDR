import logging
import json
from datetime import datetime

class ECSFormatter(logging.Formatter):
    """
    Formats log records as a single line of JSON, conforming to the
    Elastic Common Schema (ECS).
    """
    def format(self, record):
        # Start with the base ECS structure
        ecs_log = {
            "@timestamp": datetime.utcfromtimestamp(record.created).isoformat() + "Z",
            "log": {"level": record.levelname.lower(), "logger": record.name},
            "message": record.getMessage(),
            "ecs": {"version": "8.4"}, # Specify ECS version
        }

        # If the original log message was a dictionary, map its fields to ECS
        if isinstance(record.msg, dict):
            original_msg = record.msg
            ecs_log["message"] = original_msg.get("message", ecs_log["message"])

            # Event fields
            event = {}
            if original_msg.get("event_type"):
                event["kind"] = "alert"
                event["category"] = "security"
                event["type"] = original_msg.get("event_type").lower()
            if original_msg.get("monitor"):
                event["module"] = original_msg.get("monitor").lower()
            if original_msg.get("action"):
                event["action"] = original_msg.get("action")
            if original_msg.get("severity"):
                # ECS severity is a number, but we can use a keyword too
                event["severity"] = original_msg.get("severity")
            if event:
                ecs_log["event"] = event

            # Map context fields (host, process, user)
            if original_msg.get("host"):
                ecs_log["host"] = original_msg.get("host")
            if original_msg.get("process"):
                ecs_log["process"] = original_msg.get("process")
            if original_msg.get("user"):
                ecs_log["user"] = original_msg.get("user")

            # Place all other details under a custom field to avoid conflicts
            if original_msg.get("details"):
                ecs_log["custom"] = {"details": original_msg.get("details")}

        return json.dumps(ecs_log)

class HumanReadableFormatter(logging.Formatter):
    """
    Formats log records for easy reading in a terminal with color.
    """

    COLORS = {
        "INFO": "\x1b[34m",     # Blue
        "WARNING": "\x1b[33m",  # Yellow
        "ERROR": "\x1b[31m",    # Red
        "CRITICAL": "\x1b[41m\x1b[37m", # White text on Red background
        "RESET": "\x1b[0m"
    }

    def format(self, record):
        log_object = {}
        if isinstance(record.msg, dict):
            log_object.update(record.msg)
            if 'message' not in log_object:
                log_object['message'] = str(record.msg)
        else:
            log_object['message'] = record.getMessage()

        level_name = record.levelname
        color = self.COLORS.get(level_name, self.COLORS["RESET"])
        
        event_type = log_object.get("event_type", "LOG")
        title = f"[{level_name}] {event_type}"
        
        output = []
        output.append(f"{color}{'=' * 70}{self.COLORS['RESET']}")
        output.append(f"{color}{title.center(70)}{self.COLORS['RESET']}")
        output.append(f"{color}{'=' * 70}{self.COLORS['RESET']}")

        output.append(f"Timestamp: {datetime.fromtimestamp(record.created).strftime('%Y-%m-%d %H:%M:%S')}")
        output.append(f"Monitor:   {log_object.get('monitor', 'N/A')}")
        output.append(f"Message:   {log_object.get('message', 'N/A')}")
        
        if log_object.get("severity"):
            output.append(f"Severity:  {log_object.get('severity')}")
        if log_object.get("action"):
            output.append(f"Action:    {log_object.get('action')}")

        details = log_object.get("details")
        if details and isinstance(details, dict):
            output.append("Details:")
            for key, value in details.items():
                output.append(f"  -> {key:<12}: {value}")
        
        output.append("\n")

        return "\n".join(output)
