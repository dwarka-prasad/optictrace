"""Catalog service — product lookups. The hot, sampled read path."""

from __future__ import annotations

import asyncio
import random

from fastapi import FastAPI, HTTPException

from instrument import instrument

app = FastAPI()
log = instrument(app, "catalog")

CATALOG = {
    "SKU-100": {"name": "Mechanical keyboard", "price": 129.00, "stock": 42},
    "SKU-200": {"name": "27\" monitor", "price": 349.00, "stock": 7},
    "SKU-300": {"name": "Desk lamp", "price": 39.50, "stock": 0},
    "SKU-400": {"name": "USB-C dock", "price": 189.00, "stock": 15},
}


@app.get("/api/v1/catalog/{sku}")
async def get_product(sku: str):
    log.debug("catalog lookup", extra={"sku": sku})
    product = CATALOG.get(sku)
    if product is None:
        # An error worth keeping even though this route is sampled at 40% —
        # that is what keep_errors is for.
        log.warning("unknown sku requested", extra={"sku": sku})
        raise HTTPException(status_code=404, detail="no such product")

    # A slow tail on one product, so keep_slower_than has something to rescue
    # and the latency percentiles are not a flat line.
    if sku == "SKU-200" and random.random() < 0.3:
        await asyncio.sleep(0.25)
        log.warning("slow catalog read", extra={"sku": sku, "reason": "cold cache"})

    if product["stock"] == 0:
        log.info("product out of stock", extra={"sku": sku})
    return {"sku": sku, **product}


@app.get("/api/v1/health")
async def health():
    # Deliberately ungoverned by optic.yaml — this is what `optictrace scan`
    # and `suggest` exist to notice.
    return {"ok": True, "service": "catalog"}
