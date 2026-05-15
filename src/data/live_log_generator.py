"""
Real-time log generator that continuously produces realistic logs.
Simulates a live log stream by appending new entries to a CSV file.
"""

import csv
import os
import time
from datetime import datetime, timedelta
from pathlib import Path
from typing import Generator
import random
from faker import Faker

fake = Faker()


def generate_realistic_log_entry() -> dict:
    """Generate a single realistic log entry simulating HTTP requests."""
    
    # Normal patterns (70% of logs)
    is_anomalous = random.random() < 0.25  # 25% anomalies
    
    if is_anomalous:
        # Anomalous patterns
        anomaly_types = [
            "sql_injection",
            "brute_force",
            "port_scan",
            "ddos",
            "unauthorized_access",
            "malware_detection",
        ]
        anomaly_type = random.choice(anomaly_types)
        
        if anomaly_type == "sql_injection":
            parameters = f"id=1' OR '1'='1&data={fake.word()}"
            status_code = random.choice([400, 403])
            response_time = random.randint(5000, 15000)
        elif anomaly_type == "brute_force":
            parameters = f"user={fake.user_name()}&attempt={random.randint(1, 100)}"
            status_code = random.choice([401, 403])
            response_time = random.randint(100, 500)
        elif anomaly_type == "port_scan":
            parameters = f"port={random.randint(1, 65535)}&scan_type=syn"
            status_code = 500
            response_time = random.randint(1000, 3000)
        elif anomaly_type == "ddos":
            parameters = f"burst=true&packets={random.randint(1000, 10000)}"
            status_code = 503
            response_time = random.randint(10000, 30000)
        elif anomaly_type == "unauthorized_access":
            parameters = f"resource=/admin&token=invalid"
            status_code = 401
            response_time = random.randint(200, 1000)
        else:  # malware_detection
            parameters = f"file={fake.file_name()}&size={random.randint(1, 100)}MB"
            status_code = 403
            response_time = random.randint(2000, 5000)
        
        frequency = random.randint(1, 5)  # Low frequency for anomalies
    else:
        # Normal patterns
        status_code = random.choice([200, 200, 200, 201, 304])  # Mostly 200s
        response_time = random.randint(50, 500)
        
        endpoints = [
            "/api/users",
            "/api/products",
            "/api/orders",
            "/api/health",
            "/static/images",
            "/static/css",
            "/login",
            "/logout",
            "/dashboard",
        ]
        parameters = random.choice(endpoints)
        frequency = random.randint(5, 50)  # High frequency for normal
    
    # Realistic values
    ip_address = fake.ipv4()
    method = random.choice(["GET", "GET", "GET", "POST", "PUT", "DELETE"])
    user_agent = random.choice([
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64)",
        "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7)",
        "curl/7.68.0",
        "python-requests/2.28.0",
    ])
    response_size = random.randint(100, 50000) if status_code == 200 else random.randint(100, 1000)
    
    return {
        "timestamp": datetime.now().isoformat(),
        "ip_address": ip_address,
        "method": method,
        "endpoint": parameters.split("&")[0] if "&" in parameters else parameters,
        "parameters": parameters,
        "status_code": status_code,
        "response_time_ms": response_time,
        "response_size_bytes": response_size,
        "user_agent": user_agent,
        "frequency": frequency,
        "is_anomaly": is_anomalous,
    }


def continuous_log_generator(
    output_file: str,
    log_interval: float = 2.0,
    batch_size: int = 1,
) -> Generator[dict, None, None]:
    """
    Continuously generate and append logs to a CSV file.
    
    Args:
        output_file: Path to output CSV file
        log_interval: Seconds between log batches
        batch_size: Number of logs to generate per batch
    """
    output_path = Path(output_file)
    output_path.parent.mkdir(parents=True, exist_ok=True)
    
    # Initialize CSV with header if it doesn't exist
    file_exists = output_path.exists()
    
    while True:
        batch = [generate_realistic_log_entry() for _ in range(batch_size)]
        
        for log_entry in batch:
            # Append to CSV
            with open(output_path, "a", newline="") as f:
                if not file_exists or f.tell() == 0:
                    writer = csv.DictWriter(f, fieldnames=log_entry.keys())
                    writer.writeheader()
                    file_exists = True
                else:
                    writer = csv.DictWriter(f, fieldnames=log_entry.keys())
                
                writer.writerow(log_entry)
            
            yield log_entry
        
        time.sleep(log_interval)


def start_background_generator(
    output_file: str = "src/data/live_logs.csv",
    log_interval: float = 2.0,
    batch_size: int = 1,
):
    """Start log generator in a background thread."""
    import threading
    
    def generator_worker():
        try:
            for _ in continuous_log_generator(output_file, log_interval, batch_size):
                pass
        except KeyboardInterrupt:
            print("Log generator stopped.")
        except Exception as e:
            print(f"Error in log generator: {e}")
    
    thread = threading.Thread(target=generator_worker, daemon=True)
    thread.start()
    return thread


if __name__ == "__main__":
    # Run standalone: python -m src.data.live_log_generator
    output_file = "src/data/live_logs.csv"
    print(f"Starting real-time log generator, writing to {output_file}")
    print("Press Ctrl+C to stop.")
    
    try:
        for i, log_entry in enumerate(continuous_log_generator(output_file, log_interval=2.0)):
            if (i + 1) % 5 == 0:
                print(f"Generated {i + 1} logs...")
    except KeyboardInterrupt:
        print("\nLog generator stopped.")
