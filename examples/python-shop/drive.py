"""Drive realistic traffic through the shop.

Coverage, not volume: every rule in optic.yaml needs traffic that actually
triggers it. Orders from several tenants across regions and plans, catalog
reads that 404, a product that goes out of stock, charges large enough to
decline, and logins whose bodies must never be recorded.
"""

from __future__ import annotations

import argparse
import json
import random
import urllib.error
import urllib.request

STOREFRONT = "http://127.0.0.1:8101"
CATALOG = "http://127.0.0.1:8102"
PAYMENTS = "http://127.0.0.1:8103"

TENANTS = [
    ("acme-corp", "ap-south-1", "platinum"),
    ("globex", "eu-west-1", "gold"),
    ("initech", "us-east-2", "silver"),
]
SKUS = ["SKU-100", "SKU-200", "SKU-300", "SKU-400"]
CHANNELS = ["web", "mobile", "partner"]


def post(url, payload, headers=None):
    body = json.dumps(payload).encode()
    req = urllib.request.Request(
        url, data=body, method="POST",
        headers={"Content-Type": "application/json", **(headers or {})},
    )
    try:
        with urllib.request.urlopen(req, timeout=15) as r:
            return r.status, json.loads(r.read() or b"{}")
    except urllib.error.HTTPError as e:
        return e.code, json.loads(e.read() or b"{}")


def get(url, headers=None):
    req = urllib.request.Request(url, headers=headers or {})
    try:
        with urllib.request.urlopen(req, timeout=15) as r:
            return r.status, json.loads(r.read() or b"{}")
    except urllib.error.HTTPError as e:
        return e.code, {}


def order(tenant, region, plan, sku, qty=1):
    channel = random.choice(CHANNELS)
    return post(
        f"{STOREFRONT}/api/v1/orders?channel={channel}",
        {
            "sku": sku,
            "qty": qty,
            "customer": {"name": "Ada Lovelace", "email": "ada@example.com"},
            # Card data that must never appear in telemetry.
            "card": {"number": "4111111111111111", "cvv": "123", "holder": "A LOVELACE"},
        },
        {
            "X-Tenant-ID": tenant,
            "X-Region": region,
            "X-Plan": plan,
            "Authorization": "Bearer topsecret123",
        },
    )


def main(rounds: int):
    stats = {"orders": 0, "confirmed": 0, "failed": 0, "catalog": 0, "logins": 0}
    for r in range(rounds):
        for tenant, region, plan in TENANTS:
            hdr = {"X-Tenant-ID": tenant, "X-Region": region}

            # Browsing before buying — the sampled hot path.
            for sku in random.sample(SKUS, 2):
                get(f"{CATALOG}/api/v1/catalog/{sku}", hdr)
                stats["catalog"] += 1
            # A 404 that sampling must not be allowed to discard.
            get(f"{CATALOG}/api/v1/catalog/SKU-DOES-NOT-EXIST", hdr)
            stats["catalog"] += 1

            # The order itself: storefront -> catalog -> payments.
            code, _ = order(tenant, region, plan, random.choice(["SKU-100", "SKU-400"]))
            stats["orders"] += 1
            stats["confirmed" if code == 200 else "failed"] += 1

            # An out-of-stock product: a 409 the application decided on.
            order(tenant, region, plan, "SKU-300")
            stats["orders"] += 1
            stats["failed"] += 1

            # A big order, large enough that payments sometimes declines.
            code, _ = order(tenant, region, plan, "SKU-200", qty=3)
            stats["orders"] += 1
            stats["confirmed" if code == 200 else "failed"] += 1

            # Credentials — nothing here may be captured.
            post(f"{PAYMENTS}/api/v1/login",
                 {"username": "ada", "password": "hunter2"}, hdr)
            stats["logins"] += 1

    print("  traffic: " + "  ".join(f"{k}={v}" for k, v in stats.items()))


if __name__ == "__main__":
    ap = argparse.ArgumentParser()
    ap.add_argument("--rounds", type=int, default=6)
    a = ap.parse_args()
    print(f"==> Driving {a.rounds} round(s) of shop traffic")
    main(a.rounds)
