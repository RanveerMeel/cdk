#!/usr/bin/env python3
"""Simulated core-banking MCP server for the CDK fraud-prevention demo
(tools/demo_fraud.sh). Standard library only. NOTHING HERE IS REAL: the
accounts, profiles and money are invented, and no external system is
contacted. Every action is appended to a ledger file for the case file.

Tools:
  lookup_account(account)                  risk profile of an account
  freeze_account(account, reason)          freeze an account
  wire_transfer(from, to, amount, reason)  move money (refunds)

Environment: DEMO_BANK_LEDGER (default: bank-ledger.log in the cwd).
"""

import json
import os
import sys
import time

LEDGER = os.environ.get("DEMO_BANK_LEDGER", "bank-ledger.log")

# Synthetic profiles; unknown accounts look ordinary.
PROFILES = {
    "9988": {"opened_days_ago": 2, "fraud_reports": 3, "kyc": "incomplete"},
    "6666": {"opened_days_ago": 5, "fraud_reports": 1, "kyc": "incomplete"},
}
ORDINARY = {"opened_days_ago": 1400, "fraud_reports": 0, "kyc": "complete"}
FROZEN = set()

TOOLS = [
    {
        "name": "lookup_account",
        "description": "Risk profile of an account (synthetic).",
        "inputSchema": {"type": "object", "properties": {"account": {"type": "string"}}, "required": ["account"]},
    },
    {
        "name": "freeze_account",
        "description": "Freeze an account pending investigation (simulated).",
        "inputSchema": {
            "type": "object",
            "properties": {"account": {"type": "string"}, "reason": {"type": "string"}},
            "required": ["account", "reason"],
        },
    },
    {
        "name": "wire_transfer",
        "description": "Move money between accounts, e.g. a refund (simulated).",
        "inputSchema": {
            "type": "object",
            "properties": {
                "from": {"type": "string"},
                "to": {"type": "string"},
                "amount": {"type": "number"},
                "reason": {"type": "string"},
            },
            "required": ["from", "to", "amount", "reason"],
        },
    },
]


def ledger(line):
    stamp = time.strftime("%Y-%m-%dT%H:%M:%S", time.gmtime())
    with open(LEDGER, "a") as f:
        f.write(f"{stamp} {line}\n")
    sys.stderr.write(f"bank: {line}\n")


def call(name, args):
    if name == "lookup_account":
        acct = str(args.get("account", ""))
        p = PROFILES.get(acct, ORDINARY)
        ledger(f"LOOKUP account {acct}")
        return (
            f"account {acct}: opened {p['opened_days_ago']} days ago, "
            f"{p['fraud_reports']} fraud reports, KYC {p['kyc']}"
            + (", FROZEN" if acct in FROZEN else "")
        )
    if name == "freeze_account":
        acct = str(args["account"])
        FROZEN.add(acct)
        ledger(f"FREEZE account {acct} reason={args.get('reason', '')!r}")
        return f"account {acct} FROZEN"
    if name == "wire_transfer":
        src, dst = str(args["from"]), str(args["to"])
        amount = float(args["amount"])
        if src in FROZEN or dst in FROZEN:
            ledger(f"WIRE REFUSED {src}->{dst} {amount:.0f} (frozen account)")
            raise ValueError("account frozen")
        ledger(f"WIRE {src}->{dst} INR {amount:.0f} reason={args.get('reason', '')!r}")
        return f"transfer of INR {amount:.0f} from {src} to {dst} EXECUTED"
    raise KeyError(name)


def reply(msg_id, result=None, error=None):
    out = {"jsonrpc": "2.0", "id": msg_id}
    if error is not None:
        out["error"] = error
    else:
        out["result"] = result
    sys.stdout.write(json.dumps(out) + "\n")
    sys.stdout.flush()


def main():
    for line in sys.stdin:
        try:
            msg = json.loads(line)
        except ValueError:
            continue
        method, msg_id = msg.get("method"), msg.get("id")
        if msg_id is None:
            continue  # notification
        if method == "initialize":
            reply(msg_id, {
                "protocolVersion": msg.get("params", {}).get("protocolVersion", "2025-06-18"),
                "capabilities": {"tools": {}},
                "serverInfo": {"name": "cdk-demo-bank", "version": "0.1"},
            })
        elif method == "tools/list":
            reply(msg_id, {"tools": TOOLS})
        elif method == "tools/call":
            params = msg.get("params", {})
            try:
                text = call(params.get("name"), params.get("arguments") or {})
                reply(msg_id, {"content": [{"type": "text", "text": text}], "isError": False})
            except KeyError:
                reply(msg_id, error={"code": -32602, "message": f"unknown tool {params.get('name')!r}"})
            except (TypeError, ValueError) as e:
                reply(msg_id, {"content": [{"type": "text", "text": f"refused: {e}"}], "isError": True})
        else:
            reply(msg_id, error={"code": -32601, "message": f"method not found: {method}"})


if __name__ == "__main__":
    main()
