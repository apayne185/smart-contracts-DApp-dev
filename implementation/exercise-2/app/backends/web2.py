"""
Web2 backend: talks to the Flask server over HTTP.

User identity is passed via the X-User header. This is trivially spoofable —
that's the point of the exercise: web2 requires trusting a central server and
its auth layer; web3 replaces that trust with a signature on every action.
"""
import os
from typing import Any

import requests

from .base import Backend


class Web2Backend(Backend):
    mode = "web2"

    def __init__(self, base_url: str | None = None):
        self.base = base_url or os.environ.get("WEB2_URL", "http://127.0.0.1:5000")
        users = requests.get(f"{self.base}/users", timeout=5).json()
        self._users = {u["name"]: u for u in users}
        if not self._users:
            raise RuntimeError("No users seeded in web2 DB")
        self._active = next(iter(self._users))

    # ---- identity -----------------------------------------------------
    def list_users(self) -> list[str]:
        return list(self._users)

    def active_user(self) -> str:
        return self._active

    def set_active_user(self, user: str) -> None:
        if user not in self._users:
            raise ValueError(f"unknown user {user}")
        self._active = user

    def is_admin(self) -> bool:
        return bool(self._users[self._active]["is_admin"])

    # ---- helpers ------------------------------------------------------
    def _headers(self) -> dict[str, str]:
        return {"X-User": self._active, "Content-Type": "application/json"}

    def _ok(self, resp: requests.Response):
        if resp.status_code >= 400:
            try:
                err = resp.json().get("error", resp.text)
            except Exception:
                err = resp.text
            raise RuntimeError(f"HTTP {resp.status_code}: {err}")
        return resp.json() if resp.content else None

    # ---- reads --------------------------------------------------------
    def list_events(self) -> list[dict[str, Any]]:
        return self._ok(requests.get(f"{self.base}/events", timeout=5))

    def tickets_of(self, user: str) -> list[dict[str, Any]]:
        return self._ok(requests.get(f"{self.base}/tickets/of/{user}", timeout=5))

    def list_listings(self) -> list[dict[str, Any]]:
        return self._ok(requests.get(f"{self.base}/listings", timeout=5))

    # ---- actions ------------------------------------------------------
    def create_event(self, name: str, price_wei: int, total_supply: int, event_date: int) -> int:
        r = requests.post(f"{self.base}/events", json={
            "name": name, "price_wei": price_wei,
            "total_supply": total_supply, "event_date": event_date,
        }, headers=self._headers(), timeout=5)
        return self._ok(r)["id"]

    def set_event_active(self, event_id: int, active: bool) -> None:
        self._ok(requests.post(
            f"{self.base}/events/{event_id}/active",
            json={"active": active}, headers=self._headers(), timeout=5,
        ))

    def update_price(self, event_id: int, new_price_wei: int) -> None:
        self._ok(requests.post(
            f"{self.base}/events/{event_id}/price",
            json={"price_wei": new_price_wei}, headers=self._headers(), timeout=5,
        ))

    def buy_ticket(self, event_id: int, price_wei: int) -> int:
        # price_wei ignored; server enforces the face price. Kept for parity.
        r = requests.post(f"{self.base}/events/{event_id}/buy",
                          headers=self._headers(), timeout=5)
        return self._ok(r)["ticket_id"]

    def transfer_ticket(self, ticket_id: int, to_user: str) -> None:
        self._ok(requests.post(
            f"{self.base}/tickets/{ticket_id}/transfer",
            json={"to": to_user}, headers=self._headers(), timeout=5,
        ))

    def list_for_resale(self, ticket_id: int, price_wei: int) -> None:
        self._ok(requests.post(
            f"{self.base}/tickets/{ticket_id}/list",
            json={"price_wei": price_wei}, headers=self._headers(), timeout=5,
        ))

    def cancel_listing(self, ticket_id: int) -> None:
        self._ok(requests.post(
            f"{self.base}/tickets/{ticket_id}/cancel",
            headers=self._headers(), timeout=5,
        ))

    def buy_resale(self, ticket_id: int, price_wei: int) -> None:
        self._ok(requests.post(
            f"{self.base}/tickets/{ticket_id}/buy",
            headers=self._headers(), timeout=5,
        ))
