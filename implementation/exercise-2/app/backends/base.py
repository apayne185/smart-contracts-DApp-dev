"""
Abstract backend for the ticket office frontend.

Both the web2 (Flask+SQLite) and web3 (Solidity) versions implement this
interface so the Tkinter UI does not need to know which world it's talking to.

Amounts are always integer wei; the UI converts to/from ETH for display.
"""
from abc import ABC, abstractmethod
from typing import Any


class Backend(ABC):
    mode: str = "abstract"

    # ---- identity ----------------------------------------------------
    @abstractmethod
    def list_users(self) -> list[str]: ...
    @abstractmethod
    def active_user(self) -> str: ...
    @abstractmethod
    def set_active_user(self, user: str) -> None: ...
    @abstractmethod
    def is_admin(self) -> bool: ...

    # ---- reads -------------------------------------------------------
    @abstractmethod
    def list_events(self) -> list[dict[str, Any]]: ...
    @abstractmethod
    def tickets_of(self, user: str) -> list[dict[str, Any]]: ...
    @abstractmethod
    def list_listings(self) -> list[dict[str, Any]]: ...

    # ---- actions -----------------------------------------------------
    @abstractmethod
    def create_event(self, name: str, price_wei: int, total_supply: int, event_date: int) -> int: ...
    @abstractmethod
    def set_event_active(self, event_id: int, active: bool) -> None: ...
    @abstractmethod
    def update_price(self, event_id: int, new_price_wei: int) -> None: ...
    @abstractmethod
    def buy_ticket(self, event_id: int, price_wei: int) -> int: ...
    @abstractmethod
    def transfer_ticket(self, ticket_id: int, to_user: str) -> None: ...
    @abstractmethod
    def list_for_resale(self, ticket_id: int, price_wei: int) -> None: ...
    @abstractmethod
    def cancel_listing(self, ticket_id: int) -> None: ...
    @abstractmethod
    def buy_resale(self, ticket_id: int, price_wei: int) -> None: ...
