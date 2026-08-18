"""Storefront — the public API. Makes REAL downstream calls to catalog and
payments, so one order becomes a three-service trace.

The only OpticTrace-specific thing in this file is `outbound_headers()`, which
carries THIS hop's span to the next one. Forwarding the inbound header
unchanged would make the downstream calls siblings of this request rather than
children, and the tree would flatten into a list.
"""

from __future__ import annotations

import os

import httpx
from fastapi import FastAPI
from fastapi.responses import JSONResponse
from pydantic import BaseModel

from instrument import instrument, outbound_headers

CATALOG = os.environ.get("CATALOG_URL", "http://127.0.0.1:8102")
PAYMENTS = os.environ.get("PAYMENTS_URL", "http://127.0.0.1:8103")

app = FastAPI()
log = instrument(app, "storefront")


class Card(BaseModel):
    number: str
    cvv: str
    holder: str = ""


class Customer(BaseModel):
    name: str
    email: str


class OrderRequest(BaseModel):
    sku: str
    qty: int = 1
    customer: Customer
    card: Card


@app.post("/api/v1/orders")
async def create_order(order: OrderRequest):
    log.info(
        "order received",
        extra={"sku": order.sku, "qty": order.qty, "customer": order.customer.email},
    )

    async with httpx.AsyncClient(timeout=10.0) as client:
        # --- real call #1: catalog ---------------------------------------
        r = await client.get(
            f"{CATALOG}/api/v1/catalog/{order.sku}",
            headers=outbound_headers({"X-Tenant-ID": "internal"}),
        )
        if r.status_code == 404:
            log.warning("order rejected: unknown sku", extra={"sku": order.sku})
            return JSONResponse(status_code=404, content={"error": "unknown sku"})
        product = r.json()
        log.debug("catalog resolved", extra={"sku": order.sku, "price": product["price"]})

        if product["stock"] < order.qty:
            log.warning(
                "insufficient stock",
                extra={"sku": order.sku, "wanted": order.qty, "have": product["stock"]},
            )
            return JSONResponse(status_code=409, content={"error": "out of stock"})

        total = round(product["price"] * order.qty, 2)

        # --- real call #2: payments --------------------------------------
        pay = await client.post(
            f"{PAYMENTS}/api/v1/payments/charge",
            headers=outbound_headers({"X-Tenant-ID": "internal", "Content-Type": "application/json"}),
            json={
                "amount": total,
                "card": order.card.model_dump(),
                "order_ref": f"ord-{order.sku}",
            },
        )
        result = pay.json()

    if pay.status_code != 200:
        log.error(
            "order failed at payment",
            extra={"sku": order.sku, "total": total, "reason": result.get("reason", "")},
        )
        return JSONResponse(status_code=pay.status_code, content={"error": "payment failed", **result})

    log.info("order placed", extra={"sku": order.sku, "total": total, "charge": result["charge_id"]})
    return {
        "order_id": f"ord_{result['charge_id']}",
        "sku": order.sku,
        "qty": order.qty,
        "total": total,
        "status": "confirmed",
        "customer": order.customer.model_dump(),
    }


@app.get("/api/v1/health")
async def health():
    return {"ok": True, "service": "storefront"}
