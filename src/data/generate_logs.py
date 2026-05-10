from __future__ import annotations

import argparse
import random
from datetime import datetime

from faker import Faker


def generate_log(anomaly_rate: float = 0.02) -> str:
    faker = Faker()
    timestamp = datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S")
    if random.random() < anomaly_rate:
        return f"{timestamp} ERROR Connection timeout to database cluster-{random.randint(10, 99)}"
    return f"{timestamp} INFO User {faker.random_int(1000, 9999)} logged in from 192.168.1.{random.randint(1, 254)}"


def main() -> None:
    parser = argparse.ArgumentParser(description="Generate synthetic log lines")
    parser.add_argument("--rate", type=int, default=10)
    parser.add_argument("--anomaly_rate", type=float, default=0.02)
    args = parser.parse_args()

    for _ in range(args.rate):
        print(generate_log(args.anomaly_rate))


if __name__ == "__main__":
    main()
