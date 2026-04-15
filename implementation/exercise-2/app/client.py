"""
Shared Tkinter frontend for Ticket Office
    python app/client.py --mode web2       # talks to Flask at :5000
    python app/client.py --mode web3        # talks to TicketOffice on Ganache

both use same UI frontend, the trust layer underneath is not identical 
"""   


import argparse
import tkinter as tk
from datetime import datetime
from tkinter import ttk, messagebox, simpledialog


def wei_to_eth_str(w: int) -> str:
    #display as ETH for web3 parity
    return f"{int(w) / 1e18:.6f}"


def eth_to_wei(s: str) -> int:
    return int(round(float(s) * 1e18))


def fmt_date(ts: int) -> str:
    if not ts:
        return "-"
    try:
        return datetime.utcfromtimestamp(int(ts)).strftime("%Y-%m-%d")
    except Exception:
        return str(ts)


class TicketApp(tk.Tk):
    def __init__(self, backend):
        super().__init__()
        self.be = backend
        self.title(f"Ticket Office dApp  [{backend.mode}]")
        self.geometry("1040x640")

        self.active = tk.StringVar(value=self.be.active_user())
        self._build_ui()
        self.refresh_all()

    def _build_ui(self):
        top = ttk.Frame(self, padding=8); top.pack(fill=tk.X)
        ttk.Label(top, text=f"Mode: {self.be.mode}").pack(side=tk.LEFT, padx=4)
        ttk.Label(top, text="Active user:").pack(side=tk.LEFT, padx=(16, 2))
        self.combo = ttk.Combobox(
            top, textvariable=self.active, values=self.be.list_users(),
            width=52, state="readonly",
        )
        self.combo.pack(side=tk.LEFT, padx=4)
        self.combo.bind("<<ComboboxSelected>>", lambda _e: self._switch_user())
        ttk.Button(top, text="Refresh", command=self.refresh_all).pack(side=tk.LEFT, padx=4)
        self.admin_lbl = ttk.Label(top, text="", foreground="darkgreen")
        self.admin_lbl.pack(side=tk.LEFT, padx=10)

        nb = ttk.Notebook(self); nb.pack(fill=tk.BOTH, expand=True, padx=8, pady=4)


        # events tab
        f_ev = ttk.Frame(nb); nb.add(f_ev, text="Events")
        cols = ("id", "name", "price_eth", "supply", "sold", "active", "date")
        self.ev_tree = ttk.Treeview(f_ev, columns=cols, show="headings", height=10)
        for c, w in zip(cols, (50, 200, 120, 80, 80, 80, 120)):
            self.ev_tree.heading(c, text=c)
            self.ev_tree.column(c, width=w, anchor=tk.CENTER)
        self.ev_tree.pack(fill=tk.BOTH, expand=True, side=tk.LEFT)

        ev_side = ttk.Frame(f_ev, padding=6); ev_side.pack(side=tk.RIGHT, fill=tk.Y)
        ttk.Button(ev_side, text="Buy ticket", command=self.buy_ticket).pack(fill=tk.X, pady=2)
        ttk.Separator(ev_side).pack(fill=tk.X, pady=6)
        ttk.Label(ev_side, text="Admin").pack(anchor=tk.W)
        self.btn_create = ttk.Button(ev_side, text="Create event",  command=self.create_event)
        self.btn_price  = ttk.Button(ev_side, text="Update price",  command=self.update_price)
        self.btn_pause  = ttk.Button(ev_side, text="Toggle active", command=self.toggle_active)
        for b in (self.btn_create, self.btn_price, self.btn_pause):
            b.pack(fill=tk.X, pady=2)




        # my rickets tab
        f_my = ttk.Frame(nb); nb.add(f_my, text="My Tickets")
        mcols = ("id", "event_id", "event_name")
        self.my_tree = ttk.Treeview(f_my, columns=mcols, show="headings", height=10)
        for c, w in zip(mcols, (60, 80, 300)):
            self.my_tree.heading(c, text=c)
            self.my_tree.column(c, width=w, anchor=tk.CENTER)  

        self.my_tree.pack(fill=tk.BOTH, expand=True, side=tk.LEFT)
        my_side = ttk.Frame(f_my, padding=6); my_side.pack(side=tk.RIGHT, fill=tk.Y)
        ttk.Button(my_side, text="Transfer",       command=self.transfer).pack(fill=tk.X, pady=2)
        ttk.Button(my_side, text="List for resale", command=self.list_resale).pack(fill=tk.X, pady=2)
        ttk.Button(my_side, text="Cancel listing", command=self.cancel_listing).pack(fill=tk.X, pady=2)


        # market tab
        f_mk = ttk.Frame(nb); nb.add(f_mk, text="Resale Market")
        kcols = ("ticket_id", "event_name", "seller", "price_eth")
        self.mk_tree = ttk.Treeview(f_mk, columns=kcols, show="headings", height=10)
        for c, w in zip(kcols, (90, 220, 280, 140)):
            self.mk_tree.heading(c, text=c)
            self.mk_tree.column(c, width=w, anchor=tk.CENTER)
        self.mk_tree.pack(fill=tk.BOTH, expand=True, side=tk.LEFT)
        mk_side = ttk.Frame(f_mk, padding=6); mk_side.pack(side=tk.RIGHT, fill=tk.Y)
        ttk.Button(mk_side, text="Buy listed ticket", command=self.buy_resale).pack(fill=tk.X, pady=2)

        self.status = tk.StringVar(value="Ready.")
        ttk.Label(self, textvariable=self.status, relief=tk.SUNKEN, anchor=tk.W).pack(
            fill=tk.X, side=tk.BOTTOM
        )

    # helpers 
    def _switch_user(self):
        try:
            self.be.set_active_user(self.active.get())
            self.refresh_all()
        except Exception as e:
            messagebox.showerror("Switch user", str(e))

    def set_status(self, msg: str):
        self.status.set(msg); self.update_idletasks()

    def _selected_id(self, tree, col=0):
        sel = tree.selection()
        if not sel:
            messagebox.showwarning("Select", "Pick a row first."); return None
        return int(tree.item(sel[0])["values"][col])

    def refresh_all(self):
        try:
            is_admin = self.be.is_admin()
            self.admin_lbl.config(text=("ADMIN" if is_admin else "user"))
            state = tk.NORMAL if is_admin else tk.DISABLED
            for b in (self.btn_create, self.btn_price, self.btn_pause):
                b.config(state=state)

            # events
            self.ev_tree.delete(*self.ev_tree.get_children())
            for e in self.be.list_events():
                self.ev_tree.insert("", tk.END, values=(
                    e["id"], e["name"], wei_to_eth_str(e["price_wei"]),
                    e["total_supply"], e["sold"],
                    "yes" if e.get("active") else "no",
                    fmt_date(e.get("event_date", 0)),
                ))

            # my tickets
            self.my_tree.delete(*self.my_tree.get_children())
            for t in self.be.tickets_of(self.be.active_user()):
                self.my_tree.insert("", tk.END, values=(
                    t["id"], t["event_id"], t.get("event_name", ""),
                ))

            # market
            self.mk_tree.delete(*self.mk_tree.get_children())
            for l in self.be.list_listings():
                self.mk_tree.insert("", tk.END, values=(
                    l["ticket_id"], l.get("event_name", l.get("event_id")),
                    l["seller"], wei_to_eth_str(l["price_wei"]),
                ))
            self.set_status("Refreshed.")
        except Exception as e:
            messagebox.showerror("Refresh failed", str(e))    





    # event tab actions 
    def buy_ticket(self):
        eid = self._selected_id(self.ev_tree)
        if eid is None:
            return
        try:
            event = next(e for e in self.be.list_events() if e["id"] == eid)
            if not event.get("active"):
                messagebox.showerror("Event", "Event is inactive."); return
            if event["sold"] >= event["total_supply"]:
                messagebox.showerror("Event", "Sold out."); return
            if not messagebox.askyesno(
                "Confirm",
                f"Buy 1 x {event['name']} for {wei_to_eth_str(event['price_wei'])} ETH?",
            ):
                return
            self.set_status("Buying ticket…")
            tid = self.be.buy_ticket(eid, event["price_wei"])
            self.set_status(f"Bought ticket id={tid}")
            self.refresh_all()
        except Exception as e:
            messagebox.showerror("Buy failed", str(e))  


    def create_event(self):
        name = simpledialog.askstring("Create event", "Name:", parent=self)
        if not name: return
        price_eth = simpledialog.askstring("Create event", "Face price (ETH):", parent=self)
        supply = simpledialog.askinteger("Create event", "Total supply:", parent=self, minvalue=1)
        date_str = simpledialog.askstring(
            "Create event", "Event date YYYY-MM-DD (optional):", parent=self
        )
        if price_eth is None or supply is None:
            return
        try:
            ts = 0
            if date_str:
                ts = int(datetime.strptime(date_str, "%Y-%m-%d").timestamp())
            self.be.create_event(name, eth_to_wei(price_eth), supply, ts)
            self.refresh_all()
        except Exception as e:
            messagebox.showerror("Create failed", str(e))  


    def update_price(self):
        eid = self._selected_id(self.ev_tree)
        if eid is None: return
        new_price = simpledialog.askstring("Update price", "New price (ETH):", parent=self)
        if not new_price: return
        try:
            self.be.update_price(eid, eth_to_wei(new_price))
            self.refresh_all()
        except Exception as e:
            messagebox.showerror("Update failed", str(e))  



    def toggle_active(self):
        eid = self._selected_id(self.ev_tree)
        if eid is None: return
        try:
            event = next(e for e in self.be.list_events() if e["id"] == eid)
            self.be.set_event_active(eid, not event.get("active"))
            self.refresh_all()
        except Exception as e:
            messagebox.showerror("Toggle failed", str(e)) 


    # my tickets
    def transfer(self):
        tid = self._selected_id(self.my_tree)
        if tid is None: return
        to = simpledialog.askstring("Transfer", "Recipient (username or address):", parent=self)
        if not to: return
        try:
            self.be.transfer_ticket(tid, to)
            self.refresh_all()
        except Exception as e:
            messagebox.showerror("Transfer failed", str(e))

    def list_resale(self):
        tid = self._selected_id(self.my_tree)
        if tid is None: return
        price = simpledialog.askstring("List", "Resale price (ETH):", parent=self)
        if not price: return
        try:
            self.be.list_for_resale(tid, eth_to_wei(price))
            self.refresh_all()
        except Exception as e:
            messagebox.showerror("List failed", str(e))

    def cancel_listing(self):
        tid = self._selected_id(self.my_tree)
        if tid is None: return
        try:
            self.be.cancel_listing(tid)
            self.refresh_all()
        except Exception as e:
            messagebox.showerror("Cancel failed", str(e))  
            

    # market actions 
    def buy_resale(self):
        tid = self._selected_id(self.mk_tree)
        if tid is None: return
        try:
            listing = next(l for l in self.be.list_listings() if l["ticket_id"] == tid)
            if not messagebox.askyesno(
                "Confirm",
                f"Buy ticket #{tid} for {wei_to_eth_str(listing['price_wei'])} ETH?",
            ):
                return
            self.set_status("Buying resale…")
            self.be.buy_resale(tid, listing["price_wei"])
            self.set_status(f"Bought resale ticket #{tid}")
            self.refresh_all()
        except Exception as e:
            messagebox.showerror("Buy failed", str(e))


def build_backend(mode: str):
    if mode == "web2":
        from backends.web2 import Web2Backend
        return Web2Backend()
    if mode == "web3":
        from backends.web3_backend import Web3Backend
        return Web3Backend()
    raise SystemExit(f"Unknown mode: {mode}")


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--mode", choices=("web2", "web3"), default="web2")
    args = ap.parse_args()
    app = TicketApp(build_backend(args.mode))
    app.mainloop()


if __name__ == "__main__":
    import os, sys
    sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
    main()
