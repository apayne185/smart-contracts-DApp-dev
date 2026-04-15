"""
Web3 backend: talks to the TicketOffice contract on a local Ganache chain
using web3.py with locally-signed transactions.
"""
import json
import os
from typing import Any

from eth_account import Account
from web3 import Web3

from .base import Backend


GANACHE_URL = os.environ.get("GANACHE_URL", "http://127.0.0.1:8545")


def _project_root() -> str:
    here = os.path.dirname(os.path.abspath(__file__))
    return os.path.dirname(os.path.dirname(here))  # .../exercise-2


def _load_keys() -> list[dict[str, str]]:
    keys_path = os.path.join(_project_root(), "apps", "keys.json")
    env = os.environ.get("PRIVATE_KEYS", "").strip()
    if os.path.exists(keys_path):
        with open(keys_path) as f:
            raw = json.load(f)
        out = []
        for item in raw:
            pk = item["privateKey"]
            out.append({"address": Account.from_key(pk).address, "privateKey": pk})
        return out
    if env:
        out = []
        for pk in [k.strip() for k in env.split(",") if k.strip()]:
            out.append({"address": Account.from_key(pk).address, "privateKey": pk})
        return out
    raise RuntimeError("No keys configured (app/keys.json or PRIVATE_KEYS env).")


class Web3Backend(Backend):
    mode = "web3"

    def __init__(self):
        self.w3 = Web3(Web3.HTTPProvider(GANACHE_URL))
        if not self.w3.is_connected():
            raise RuntimeError(f"Cannot reach Ganache at {GANACHE_URL}")
        self.chain_id = self.w3.eth.chain_id

        root = _project_root()
        with open(os.path.join(root, "deployed-address.txt")) as f:
            addr = f.read().strip()
        with open(os.path.join(root, "TicketOffice.abi.json")) as f:
            abi = json.load(f)
        self.contract = self.w3.eth.contract(
            address=Web3.to_checksum_address(addr), abi=abi
        )
        self.owner_addr = self.contract.functions.owner().call()

        self._keys = _load_keys()
        self._by_addr = {k["address"].lower(): k["privateKey"] for k in self._keys}
        self._active = self._keys[0]["address"]

    # ---- identity -----------------------------------------------------
    def list_users(self) -> list[str]:
        return [k["address"] for k in self._keys]

    def active_user(self) -> str:
        return self._active

    def set_active_user(self, user: str) -> None:
        if user.lower() not in self._by_addr:
            raise ValueError(f"unknown address {user}")
        self._active = Web3.to_checksum_address(user)

    def is_admin(self) -> bool:
        return self._active.lower() == self.owner_addr.lower()

    # ---- helpers ------------------------------------------------------
    def _send(self, fn, value_wei: int = 0):
        sender = Web3.to_checksum_address(self._active)
        pk = self._by_addr[sender.lower()]
        tx = fn.build_transaction({
            "from": sender,
            "value": value_wei,
            "nonce": self.w3.eth.get_transaction_count(sender),
            "gas": 800_000,
            "gasPrice": self.w3.to_wei("2", "gwei"),
            "chainId": self.chain_id,
        })
        signed = self.w3.eth.account.sign_transaction(tx, pk)
        tx_hash = self.w3.eth.send_raw_transaction(signed.raw_transaction)
        rcpt = self.w3.eth.wait_for_transaction_receipt(tx_hash)
        if rcpt.status != 1:
            raise RuntimeError("Transaction reverted")
        return rcpt

    # ---- reads --------------------------------------------------------
    def list_events(self) -> list[dict[str, Any]]:
        ids = self.contract.functions.allEventIds().call()
        out = []
        for eid in ids:
            _, name, price, supply, sold, edate, active = self.contract.functions.getEvent(eid).call()
            out.append({
                "id": eid, "name": name, "price_wei": price,
                "total_supply": supply, "sold": sold,
                "event_date": edate, "active": int(active),
            })
        return out

    def tickets_of(self, user: str) -> list[dict[str, Any]]:
        addr = Web3.to_checksum_address(user)
        ids = self.contract.functions.ticketsOf(addr).call()
        out = []
        for tid in ids:
            _, eid, _own = self.contract.functions.getTicket(tid).call()
            _, name, *_ = self.contract.functions.getEvent(eid).call()
            out.append({"id": tid, "event_id": eid, "event_name": name})
        return out

    def list_listings(self) -> list[dict[str, Any]]:
        # Scan all issued tickets; ok for demo scale.
        total = self.contract.functions.nextTicketId().call() - 1
        out = []
        for tid in range(1, total + 1):
            price, active = self.contract.functions.getListing(tid).call()
            if active:
                _, eid, seller = self.contract.functions.getTicket(tid).call()
                _, ename, *_ = self.contract.functions.getEvent(eid).call()
                out.append({
                    "ticket_id": tid, "price_wei": price, "seller": seller,
                    "event_id": eid, "event_name": ename,
                })
        return out

    # ---- actions ------------------------------------------------------
    def create_event(self, name: str, price_wei: int, total_supply: int, event_date: int) -> int:
        rcpt = self._send(
            self.contract.functions.createEvent(name, price_wei, total_supply, event_date)
        )
        evs = self.contract.events.EventCreated().process_receipt(rcpt)
        return int(evs[0]["args"]["id"]) if evs else 0

    def set_event_active(self, event_id: int, active: bool) -> None:
        self._send(self.contract.functions.setEventActive(event_id, active))

    def update_price(self, event_id: int, new_price_wei: int) -> None:
        self._send(self.contract.functions.updatePrice(event_id, new_price_wei))

    def buy_ticket(self, event_id: int, price_wei: int) -> int:
        rcpt = self._send(self.contract.functions.buyTicket(event_id), value_wei=price_wei)
        evs = self.contract.events.TicketPurchased().process_receipt(rcpt)
        return int(evs[0]["args"]["ticketId"]) if evs else 0

    def transfer_ticket(self, ticket_id: int, to_user: str) -> None:
        self._send(self.contract.functions.transferTicket(
            ticket_id, Web3.to_checksum_address(to_user)
        ))

    def list_for_resale(self, ticket_id: int, price_wei: int) -> None:
        self._send(self.contract.functions.listForResale(ticket_id, price_wei))

    def cancel_listing(self, ticket_id: int) -> None:
        self._send(self.contract.functions.cancelListing(ticket_id))

    def buy_resale(self, ticket_id: int, price_wei: int) -> None:
        self._send(self.contract.functions.buyResale(ticket_id), value_wei=price_wei)
