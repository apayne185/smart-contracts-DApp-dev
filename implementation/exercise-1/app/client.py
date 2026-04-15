"""
Vending Machine dApp - Python Tkinter client (ganache + signed transactions).
 connects to Ganache at http://127.0.0.1:8545,
 reads deploed address from `../deployed-address.txt`  and  ABI from  ../VendingMachine.abi.json`
 sends transactions signed locally w ganache private key.
"""

import json
import os
import tkinter as tk
from tkinter import ttk, messagebox, simpledialog

from web3 import Web3
from eth_account import Account


GANACHE_URL = os.environ.get("GANACHE_URL", "http://127.0.0.1:8545")
BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
ADDR_FILE = os.path.join(BASE_DIR, "deployed-address.txt")
ABI_FILE  = os.path.join(BASE_DIR, "VendingMachine.abi.json")
KEYS_FILE = os.path.join(os.path.dirname(os.path.abspath(__file__)), "keys.json")


def load_keys():
    # load list of {address,  privateKey} objects.
    if os.path.exists(KEYS_FILE):
        with open(KEYS_FILE) as f:
            data = json.load(f)
        out = []
        for item in data:
            pk = item["privateKey"]
            acct = Account.from_key(pk)
            out.append({"address": acct.address, "privateKey": pk})
        return out

    env = os.environ.get("PRIVATE_KEYS", "").strip()
    if env:
        out = []
        for pk in [k.strip() for k in env.split(",") if k.strip()]:
            acct = Account.from_key(pk)
            out.append({"address": acct.address, "privateKey": pk})
        return out

    raise RuntimeError(
        "No keys configured. Create app/keys.json (see app/keys.example.json) "
        "or set PRIVATE_KEYS env var."
    )


class VendingApp(tk.Tk):
    def __init__(self):
        super().__init__()
        self.title("Vending Machine dApp")
        self.geometry("860x580")

        # --- web3 setup ---
        self.w3 = Web3(Web3.HTTPProvider(GANACHE_URL))
        if not self.w3.is_connected():
            messagebox.showerror("Connection", f"Cannot reach Ganache at {GANACHE_URL}")
            raise SystemExit(1)
        self.chain_id = self.w3.eth.chain_id

        # keys
        try:
            self.keys = load_keys()
        except Exception as e:
            messagebox.showerror("Keys", str(e))
            raise SystemExit(1)

        # contract
        with open(ADDR_FILE) as f:
            addr = f.read().strip()
        with open(ABI_FILE) as f:
            abi = json.load(f)
        self.contract = self.w3.eth.contract(
            address=Web3.to_checksum_address(addr), abi=abi
        )
        self.owner_addr = self.contract.functions.owner().call()

        addresses = [k["address"] for k in self.keys]
        self.active = tk.StringVar(value=addresses[0])

        self._build_ui(addresses)
        self.refresh()

    def _build_ui(self, addresses):
        top = ttk.Frame(self, padding=8)
        top.pack(fill=tk.X)

        ttk.Label(top, text="Active wallet:").pack(side=tk.LEFT)
        self.acct_combo = ttk.Combobox(
            top, textvariable=self.active, values=addresses, width=52, state="readonly"
        )
        self.acct_combo.pack(side=tk.LEFT, padx=6)
        self.acct_combo.bind("<<ComboboxSelected>>", lambda _e: self.refresh())

        ttk.Button(top, text="Refresh", command=self.refresh).pack(side=tk.LEFT, padx=4)
        self.admin_lbl = ttk.Label(top, text="", foreground="darkgreen")
        self.admin_lbl.pack(side=tk.LEFT, padx=10)
        self.bal_lbl = ttk.Label(top, text="")
        self.bal_lbl.pack(side=tk.RIGHT)

        mid = ttk.Frame(self, padding=8)
        mid.pack(fill=tk.BOTH, expand=True)

        cols = ("id", "name", "price_eth", "stock", "owned")
        self.tree = ttk.Treeview(mid, columns=cols, show="headings", height=10)
        for c, w in zip(cols, (50, 180, 140, 100, 100)):
            self.tree.heading(c, text=c)
            self.tree.column(c, width=w, anchor=tk.CENTER)
        self.tree.pack(fill=tk.BOTH, expand=True, side=tk.LEFT)

        side = ttk.Frame(mid, padding=6)
        side.pack(side=tk.RIGHT, fill=tk.Y)
        ttk.Label(side, text="Quantity:").pack(anchor=tk.W)
        self.qty_var = tk.IntVar(value=1)
        ttk.Spinbox(side, from_=1, to=999, textvariable=self.qty_var, width=6).pack(anchor=tk.W)
        ttk.Button(side, text="Buy selected", command=self.buy).pack(fill=tk.X, pady=6)

        ttk.Separator(side, orient="horizontal").pack(fill=tk.X, pady=6)
        ttk.Label(side, text="Admin actions").pack(anchor=tk.W)
        self.btn_add     = ttk.Button(side, text="Add product",       command=self.add_product)
        self.btn_restock = ttk.Button(side, text="Restock selected",  command=self.restock)
        self.btn_price   = ttk.Button(side, text="Update price",      command=self.update_price)
        self.btn_wd      = ttk.Button(side, text="Withdraw",          command=self.withdraw)
        for b in (self.btn_add, self.btn_restock, self.btn_price, self.btn_wd):
            b.pack(fill=tk.X, pady=2)

        self.status = tk.StringVar(value="Ready.")
        ttk.Label(self, textvariable=self.status, relief=tk.SUNKEN, anchor=tk.W).pack(
            fill=tk.X, side=tk.BOTTOM
        )

    #helpers

    def is_admin(self) -> bool:
        return self.active.get().lower() == self.owner_addr.lower()

    def set_status(self, msg: str):
        self.status.set(msg)
        self.update_idletasks()

    def active_key(self) -> str:
        a = self.active.get().lower()
        for k in self.keys:
            if k["address"].lower() == a:
                return k["privateKey"]
        raise RuntimeError("Private key not found for active account.")

    def send(self, fn, value_wei: int = 0) -> dict:
        """Build, sign, and send a transaction; return the receipt."""
        sender = Web3.to_checksum_address(self.active.get())
        pk = self.active_key()
        nonce = self.w3.eth.get_transaction_count(sender)
        tx = fn.build_transaction({
            "from":     sender,
            "value":    value_wei,
            "nonce":    nonce,
            "gas":      500_000,
            "gasPrice": self.w3.to_wei("2", "gwei"),
            "chainId":  self.chain_id,
        })
        signed = self.w3.eth.account.sign_transaction(tx, pk)
        tx_hash = self.w3.eth.send_raw_transaction(signed.raw_transaction)
        self.set_status(f"Tx sent: {tx_hash.hex()} — waiting…")
        rcpt = self.w3.eth.wait_for_transaction_receipt(tx_hash)
        if rcpt.status != 1:
            raise RuntimeError("Transaction reverted")
        self.set_status(
            f"Tx confirmed in block {rcpt.blockNumber} (gas used {rcpt.gasUsed})"
        )
        return rcpt

    def selected_id(self):
        sel = self.tree.selection()
        if not sel:
            messagebox.showwarning("Select", "Pick a product row first.")
            return None
        return int(self.tree.item(sel[0])["values"][0])

    def refresh(self):
        try:
            self.admin_lbl.config(
                text=("ADMIN" if self.is_admin() else "user")
                + f"  |  owner={self.owner_addr[:10]}…"
            )
            admin_state = tk.NORMAL if self.is_admin() else tk.DISABLED
            for b in (self.btn_add, self.btn_restock, self.btn_price, self.btn_wd):
                b.config(state=admin_state)

            user = Web3.to_checksum_address(self.active.get())
            bal = self.w3.eth.get_balance(user)
            self.bal_lbl.config(text=f"balance: {Web3.from_wei(bal, 'ether')} ETH")

            self.tree.delete(*self.tree.get_children())
            ids = self.contract.functions.allProductIds().call()
            for pid in ids:
                _id, name, price, stock = self.contract.functions.getProduct(pid).call()
                owned = self.contract.functions.balanceOf(user, pid).call()
                self.tree.insert(
                    "", tk.END,
                    values=(_id, name, f"{Web3.from_wei(price, 'ether')} ETH", stock, owned),
                )
            self.set_status(f"Loaded {len(ids)} product(s).")
        except Exception as e:
            messagebox.showerror("Refresh failed", str(e))

    # handlers        
    def buy(self):
        pid = self.selected_id()
        if pid is None:
            return
        qty = int(self.qty_var.get())
        if qty <= 0:
            messagebox.showwarning("Quantity", "Quantity must be positive.")
            return
        try:
            _id, name, price, stock = self.contract.functions.getProduct(pid).call()
            if qty > stock:
                messagebox.showerror("Stock", f"Only {stock} in stock.")
                return
            cost = price * qty
            if not messagebox.askyesno(
                "Confirm",
                f"Buy {qty} x {name} for {Web3.from_wei(cost, 'ether')} ETH?",
            ):
                return
            rcpt = self.send(self.contract.functions.purchase(pid, qty), value_wei=cost)
            # Decode the ProductPurchased event
            evs = self.contract.events.ProductPurchased().process_receipt(rcpt)
            if evs:
                a = evs[0]["args"]
                self.set_status(
                    f"Purchased: buyer={a['buyer'][:10]}… id={a['id']} qty={a['qty']} "
                    f"paid={Web3.from_wei(a['totalPaid'], 'ether')} ETH"
                )
            self.refresh()
        except Exception as e:
            messagebox.showerror("Purchase failed", str(e))

    def add_product(self):
        name = simpledialog.askstring("Add product", "Name:", parent=self)
        if not name:
            return
        price_eth = simpledialog.askstring("Add product", "Price in ETH (e.g. 0.01):", parent=self)
        stock = simpledialog.askinteger("Add product", "Initial stock:", parent=self, minvalue=0)
        if price_eth is None or stock is None:
            return
        try:
            self.send(
                self.contract.functions.addProduct(name, Web3.to_wei(price_eth, "ether"), stock)
            )
            self.refresh()
        except Exception as e:
            messagebox.showerror("Add failed", str(e))

    def restock(self):
        pid = self.selected_id()
        if pid is None:
            return
        qty = simpledialog.askinteger("Restock", "Units to add:", parent=self, minvalue=1)
        if not qty:
            return
        try:
            self.send(self.contract.functions.restock(pid, qty))
            self.refresh()
        except Exception as e:
            messagebox.showerror("Restock failed", str(e))

    def update_price(self):
        pid = self.selected_id()
        if pid is None:
            return
        price_eth = simpledialog.askstring("Update price", "New price ETH:", parent=self)
        if not price_eth:
            return
        try:
            self.send(
                self.contract.functions.updatePrice(pid, Web3.to_wei(price_eth, "ether"))
            )
            self.refresh()
        except Exception as e:
            messagebox.showerror("Price update failed", str(e))

    def withdraw(self):
        try:
            self.send(self.contract.functions.withdraw())
            messagebox.showinfo("Withdraw", "Funds withdrawn to owner.")
            self.refresh()
        except Exception as e:
            messagebox.showerror("Withdraw failed", str(e))


if __name__ == "__main__":
    VendingApp().mainloop()
