from datetime import datetime

def log_event(msg):
    with open("scanner.log", "a") as f:
        f.write(f"[{datetime.now()}] {msg}\n")

