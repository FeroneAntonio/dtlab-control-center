"""Native, non-echoing credential prompt for the local Windows collector."""

from __future__ import annotations

import argparse
import tkinter as tk
from collections.abc import Callable, Sequence
from functools import partial
from tkinter import messagebox, ttk

from dtlab.collector.credentials import (
    CredentialError,
    save_esxi_password,
    save_new_ui_token,
    save_token,
)


def _save_with_dialog(
    root: tk.Tk,
    value: str,
    save: Callable[[str], None],
    success_message: str,
) -> bool:
    try:
        save(value)
    except CredentialError as exc:
        messagebox.showerror("DTLab Control Center", str(exc), parent=root)
        return False
    messagebox.showinfo("DTLab Control Center", success_message, parent=root)
    return True


def prompt_secret(*, kind: str, username: str | None = None) -> bool:
    root = tk.Tk()
    root.title("DTLab Control Center · credenziale locale")
    root.geometry("520x250")
    root.resizable(False, False)
    root.attributes("-topmost", True)

    frame = ttk.Frame(root, padding=24)
    frame.pack(fill="both", expand=True)
    ttk.Label(
        frame,
        text=(
            "Password VMware ESXi"
            if kind == "esxi"
            else (
                "Token API Cisco Cyber Vision New UI · Auditor"
                if kind == "cybervision-new-ui"
                else "Token API Cisco Cyber Vision Classic read-only"
            )
        ),
        font=("Segoe UI", 14, "bold"),
    ).pack(anchor="w")
    ttk.Label(
        frame,
        text=(
            f"Account: {username}. La password viene salvata solo nel vault di Windows."
            if kind == "esxi"
            else (
                "Usare un token New UI con ruolo Auditor. Il valore non entra nei file "
                "del progetto."
                if kind == "cybervision-new-ui"
                else "Usare un token Classic con permesso API Read. Il valore non "
                "entra nei file del progetto."
            )
        ),
        wraplength=465,
    ).pack(anchor="w", pady=(8, 14))

    secret = tk.StringVar()
    entry = ttk.Entry(frame, textvariable=secret, show="•", width=60)
    entry.pack(fill="x")
    entry.focus_set()

    saved = False

    def submit() -> None:
        nonlocal saved
        if kind == "esxi":
            account = username or ""
            save = partial(save_esxi_password, account)
            success = "Password ESXi salvata nel vault di Windows."
        elif kind == "cybervision-new-ui":
            save = save_new_ui_token
            success = "Token Cisco New UI Auditor salvato nel vault di Windows."
        else:
            save = save_token
            success = "Token Cisco Classic read-only salvato nel vault di Windows."
        if _save_with_dialog(root, secret.get(), save, success):
            saved = True
            secret.set("")
            root.destroy()

    buttons = ttk.Frame(frame)
    buttons.pack(fill="x", pady=(18, 0))
    ttk.Button(buttons, text="Annulla", command=root.destroy).pack(side="right")
    ttk.Button(buttons, text="Salva nel vault", command=submit).pack(
        side="right", padx=(0, 8)
    )
    root.bind("<Return>", lambda _event: submit())
    root.bind("<Escape>", lambda _event: root.destroy())
    root.mainloop()
    return saved


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Prompt credenziali locale DTLab.")
    parser.add_argument(
        "kind",
        choices=("esxi", "cybervision", "cybervision-new-ui"),
    )
    parser.add_argument("--username")
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    args = _parser().parse_args(argv)
    if args.kind == "esxi" and not args.username:
        raise SystemExit("--username è obbligatorio per ESXi")
    return 0 if prompt_secret(kind=args.kind, username=args.username) else 1


if __name__ == "__main__":
    raise SystemExit(main())
