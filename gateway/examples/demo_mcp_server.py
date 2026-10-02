#!/usr/bin/env python3
"""Minimal MCP server (stdio, JSON-RPC 2.0, newline-delimited) for testing
the CDK gateway. Standard library only. Tools are deliberately neutral:

  echo(text)        returns text unchanged
  word_count(text)  returns the number of words
  utc_time()        returns the current UTC time (ISO 8601)
  sleep(seconds)    waits, then returns "slept" (tests time-outs; max 30 s)
"""

import json
import sys
import time
from datetime import datetime, timezone

TOOLS = [
    {
        "name": "echo",
        "description": "Return the given text unchanged.",
        "inputSchema": {"type": "object", "properties": {"text": {"type": "string"}}, "required": ["text"]},
    },
    {
        "name": "word_count",
        "description": "Count the words in the given text.",
        "inputSchema": {"type": "object", "properties": {"text": {"type": "string"}}, "required": ["text"]},
    },
    {
        "name": "utc_time",
        "description": "Current UTC time.",
        "inputSchema": {"type": "object", "properties": {}},
    },
    {
        "name": "sleep",
        "description": "Wait the given number of seconds (max 30), then return.",
        "inputSchema": {"type": "object", "properties": {"seconds": {"type": "number"}}},
    },
]


def call(name, args):
    if name == "echo":
        return str(args.get("text", ""))
    if name == "word_count":
        return str(len(str(args.get("text", "")).split()))
    if name == "utc_time":
        return datetime.now(timezone.utc).replace(microsecond=0).isoformat()
    if name == "sleep":
        time.sleep(min(float(args.get("seconds", 1)), 30))
        return "slept"
    raise KeyError(name)


def reply(msg_id, result=None, error=None):
    out = {"jsonrpc": "2.0", "id": msg_id}
    if error is not None:
        out["error"] = error
    else:
        out["result"] = result
    sys.stdout.write(json.dumps(out) + "\n")
    sys.stdout.flush()


for line in sys.stdin:
    try:
        msg = json.loads(line)
    except json.JSONDecodeError:
        continue
    method, msg_id = msg.get("method"), msg.get("id")
    if msg_id is None:
        continue  # notification (e.g. notifications/initialized)
    if method == "initialize":
        reply(msg_id, {
            "protocolVersion": msg.get("params", {}).get("protocolVersion", "2025-06-18"),
            "capabilities": {"tools": {}},
            "serverInfo": {"name": "cdk-demo-mcp", "version": "0.1"},
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
            # A tool-level failure: reported in the result, not as a protocol error.
            reply(msg_id, {"content": [{"type": "text", "text": f"bad arguments: {e}"}], "isError": True})
    else:
        reply(msg_id, error={"code": -32601, "message": f"method not found: {method}"})
