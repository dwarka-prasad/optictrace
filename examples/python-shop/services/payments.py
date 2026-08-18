"""Payments service — the leg that handles card data."""

from __future__ import annotations

import asyncio
import random

from fastapi import FastAPI
from fastapi.responses import JSONResponse
from pydantic import BaseModel

from instrument import instrument

app = FastAPI()
log = instrument(app, "payments")


class Card(BaseModel):
    number: str
    cvv: str
    holder: str = ""


class ChargeRequest(BaseModel):
    amount: float
    currency: str = "USD"
    card: Card
    order_ref: str = ""


@app.post("/api/v1/payments/charge")
async def charge(req: ChargeRequest):
    # A real service logs like this while debugging and forgets to take it
    # out. The line is stored REDACTED — that is the point of running logs
    # through the same policy as payloads.
    log.debug("charging card %s for %.2f", req.card.number, req.amount)
    log.info("charge requested", extra={"amount": req.amount, "order_ref": req.order_ref})

    await asyncio.sleep(random.uniform(0.01, 0.05))

    # Large orders decline sometimes; a gateway blips occasionally.
    if req.amount > 900 and random.random() < 0.5:
        log.error("charge declined", extra={"reason": "limit_exceeded", "amount": req.amount})
        return JSONResponse(
            status_code=402,
            content={"status": "declined", "reason": "limit_exceeded"},
        )
    if random.random() < 0.06:
        log.error("payment gateway unreachable", extra={"gateway": "acquirer-eu"})
        return JSONResponse(status_code=502, content={"status": "error", "reason": "gateway"})

    log.info("charge captured", extra={"amount": req.amount})
    return {"status": "captured", "charge_id": f"ch_{random.randint(10000, 99999)}", "amount": req.amount}


@app.post("/api/v1/login")
async def login(payload: dict):
    # Nothing here may be captured — but the tenant label still resolves, so
    # the request is still attributable for billing.
    log.info("login attempt", extra={"user": payload.get("username", "")})
    return {"token": "session-token-abc123"}


@app.get("/api/v1/health")
async def health():
    return {"ok": True, "service": "payments"}
