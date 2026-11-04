#!/usr/bin/env python3
"""GAMA Shard MVP MCP wrapper (stdio JSON-RPC 2.0).

Runs on the machine that hosts opencode; talks HTTP to the Shard MVP service
(SHARD_URL, default http://127.0.0.1:7150).

Token resolution (first non-empty wins):
  1. SHARD_TOKEN env
  2. SHARD_TOKEN_FILE env
  3. ~/.shard-token

Ops CLI (for smoke tests, never used by MCP clients):
  python3 shard_mcp.py --call shard_health '{}'
  python3 shard_mcp.py --call shard_exec '{"key":"itest-1","cmd":"echo hi"}'
"""
import json
import os
import re
import sys
import time
import urllib.error
import urllib.request
from urllib.parse import quote

VERSION = "0.2"
URL = os.environ.get("SHARD_URL", "http://127.0.0.1:7150").rstrip("/")
TOKEN_ENV = os.environ.get("SHARD_TOKEN", "").strip()
TOKEN_FILES = [p for p in (
    os.environ.get("SHARD_TOKEN_FILE"),
    os.path.expanduser("~/.shard-token"),
) if p]
KEY_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$")


def _envnum(name, default):
    try:
        return float(os.environ.get(name, default))
    except (TypeError, ValueError):
        return float(default)


T_HEALTH = _envnum("SHARD_TIMEOUT_HEALTH", 10)
T_LIST = _envnum("SHARD_TIMEOUT_LIST", 15)
T_OPEN = _envnum("SHARD_TIMEOUT_OPEN", 300)
T_SUSPEND = _envnum("SHARD_TIMEOUT_SUSPEND", 300)
T_RESUME = _envnum("SHARD_TIMEOUT_RESUME", 300)
T_BACKUP = _envnum("SHARD_TIMEOUT_BACKUP", 600)
T_FORK = _envnum("SHARD_TIMEOUT_FORK", 300)
T_EXEC_DEFAULT = _envnum("SHARD_TIMEOUT_EXEC", 20)


def token():
    if TOKEN_ENV:
        return TOKEN_ENV
    for path in TOKEN_FILES:
        try:
            with open(path) as fh:
                value = fh.read().strip()
            if value:
                return value
        except OSError:
            continue
    return ""


def _key(value, field="key"):
    value = (value or "").strip() if isinstance(value, str) else ""
    if not KEY_RE.match(value):
        raise ValueError(
            "%s mora biti 1-64 znaka [A-Za-z0-9._-] i poceti slovom ili brojem" % field
        )
    return value


def _json(raw):
    try:
        return json.loads(raw.decode("utf-8", "replace"))
    except Exception:
        return None


def _ms(t0):
    return round((time.time() - t0) * 1000, 1)


def http(path, body=None, timeout=None, op="", method=None):
    """HTTP call that always returns a JSON-serializable dict (never raises for IO)."""
    t0 = time.time()
    method = method or ("POST" if body is not None else "GET")
    data = None if body is None else json.dumps(body).encode()
    req = urllib.request.Request(URL + path, data=data, method=method)
    req.add_header("Content-Type", "application/json")
    req.add_header("Accept", "application/json")
    tok = token()
    if tok:
        req.add_header("X-Token", tok)
    try:
        with urllib.request.urlopen(req, timeout=timeout or 30) as resp:
            raw = resp.read()
    except urllib.error.HTTPError as exc:
        raw = exc.read() or b""
        obj = _json(raw)
        msg = obj.get("err") if isinstance(obj, dict) else None
        return {
            "ok": False,
            "http_status": exc.code,
            "err": msg or ("HTTP %s" % exc.code),
            "body": raw.decode("utf-8", "replace")[:800],
            "endpoint": op,
            "wrapper_ms": _ms(t0),
        }
    except urllib.error.URLError as exc:
        return {
            "ok": False,
            "err": "transport: %s" % getattr(exc, "reason", exc),
            "endpoint": op,
            "wrapper_ms": _ms(t0),
        }
    except (TimeoutError, OSError) as exc:
        return {
            "ok": False,
            "err": "transport: %s" % exc,
            "endpoint": op,
            "wrapper_ms": _ms(t0),
        }
    obj = _json(raw)
    if obj is None:
        return {
            "ok": False,
            "err": "non-json response",
            "body": raw[:800].decode("utf-8", "replace"),
            "endpoint": op,
            "wrapper_ms": _ms(t0),
        }
    if isinstance(obj, dict):
        obj.setdefault("endpoint", op)
    return obj


def op_health(_args):
    return http("/health", None, T_HEALTH, "health")


def op_list(_args):
    return http("/v1/workspaces", None, T_LIST, "list")


def op_open(args):
    key = _key(args.get("key"))
    return http("/v1/workspaces/open", {"key": key}, T_OPEN, "open")


def op_exec(args):
    key = _key(args.get("key"))
    cmd = args.get("cmd")
    if not isinstance(cmd, str) or not cmd.strip():
        raise ValueError("cmd je obavezan (neprazan string)")
    try:
        timeout = float(args.get("timeout", T_EXEC_DEFAULT))
    except (TypeError, ValueError):
        timeout = T_EXEC_DEFAULT
    if timeout <= 0:
        timeout = T_EXEC_DEFAULT
    timeout = min(timeout, 120.0)
    path = "/v1/workspaces/%s/exec" % quote(key, safe="")
    return http(path, {"cmd": cmd, "timeout": timeout}, max(30.0, timeout + 25), "exec")


def op_suspend(args):
    key = _key(args.get("key"))
    path = "/v1/workspaces/%s/suspend" % quote(key, safe="")
    return http(path, {}, T_SUSPEND, "suspend")


def op_resume(args):
    key = _key(args.get("key"))
    path = "/v1/workspaces/%s/resume" % quote(key, safe="")
    return http(path, {}, T_RESUME, "resume")


def op_backup(args):
    key = _key(args.get("key"))
    path = "/v1/workspaces/%s/backup" % quote(key, safe="")
    return http(path, {}, T_BACKUP, "backup")


def op_fork(args):
    key = _key(args.get("key"))
    new_key = _key(args.get("new_key"), "new_key")
    path = "/v1/workspaces/%s/fork" % quote(key, safe="")
    return http(path, {"key": new_key}, T_FORK, "fork")


def op_delete(args):
    key = _key(args.get("key"))
    path = "/v1/workspaces/%s" % quote(key, safe="")
    return http(path, None, T_SUSPEND, "delete", method="DELETE")


def op_gc(_args):
    return http("/v1/gc", {}, T_BACKUP, "gc")


OPS = {
    "shard_health": op_health,
    "shard_list": op_list,
    "shard_open": op_open,
    "shard_exec": op_exec,
    "shard_suspend": op_suspend,
    "shard_resume": op_resume,
    "shard_backup": op_backup,
    "shard_fork": op_fork,
    "shard_delete": op_delete,
    "shard_gc": op_gc,
}

TOOLS = [
    {
        "name": "shard_health",
        "description": "Health of Shard MVP microVM service (returns ok, workspaces, vms states).",
        "inputSchema": {"type": "object", "properties": {}},
    },
    {
        "name": "shard_list",
        "description": "List registered workspaces and their states.",
        "inputSchema": {"type": "object", "properties": {}},
    },
    {
        "name": "shard_open",
        "description": "Open (or resume) a persistent Firecracker microVM workspace. Cold open ~2-3s.",
        "inputSchema": {
            "type": "object",
            "properties": {"key": {"type": "string", "description": "Workspace key [A-Za-z0-9._-]"}},
            "required": ["key"],
        },
    },
    {
        "name": "shard_exec",
        "description": "Run a shell command inside a workspace. NOTE: run `sync` before suspend if writes must survive; unknown keys auto-create a workspace.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "key": {"type": "string"},
                "cmd": {"type": "string"},
                "timeout": {"type": "number", "description": "Seconds, server vsock caps ~20s; max 120"},
            },
            "required": ["key", "cmd"],
        },
    },
    {
        "name": "shard_suspend",
        "description": "Stop a workspace and write a zstd backup (cold mode: kill VM + backup rootfs). Run sync in guest first.",
        "inputSchema": {
            "type": "object",
            "properties": {"key": {"type": "string"}},
            "required": ["key"],
        },
    },
    {
        "name": "shard_resume",
        "description": "Resume a suspended workspace (cold mode: cold boot from its disk).",
        "inputSchema": {
            "type": "object",
            "properties": {"key": {"type": "string"}},
            "required": ["key"],
        },
    },
    {
        "name": "shard_backup",
        "description": "Create/refresh a zstd backup of the workspace rootfs under $SHARD_BASE/backups/<key>.",
        "inputSchema": {
            "type": "object",
            "properties": {"key": {"type": "string"}},
            "required": ["key"],
        },
    },
    {
        "name": "shard_fork",
        "description": "Fork a workspace from its current disk into a new key and boot it.",
        "inputSchema": {
            "type": "object",
            "properties": {"key": {"type": "string"}, "new_key": {"type": "string"}},
            "required": ["key", "new_key"],
        },
    },
    {
        "name": "shard_delete",
        "description": "Delete a workspace (stops VM, removes its disk and backup). Irreversible.",
        "inputSchema": {
            "type": "object",
            "properties": {"key": {"type": "string"}},
            "required": ["key"],
        },
    },
    {
        "name": "shard_gc",
        "description": "Run backup GC (keep days/count) and reap orphan Firecracker processes.",
        "inputSchema": {"type": "object", "properties": {}},
    },
]


def call_tool(name, args):
    fn = OPS.get(name)
    if fn is None:
        return {"ok": False, "err": "nepoznat alat: %s" % name, "endpoint": name}
    if args is None:
        args = {}
    if not isinstance(args, dict):
        return {"ok": False, "err": "arguments mora biti JSON objekat", "endpoint": name}
    try:
        return fn(args)
    except ValueError as exc:
        return {"ok": False, "err": str(exc), "endpoint": name}
    except Exception as exc:  # defensive: never crash the stdio server
        return {
            "ok": False,
            "err": "%s: %s" % (type(exc).__name__, exc),
            "endpoint": name,
        }


def send(obj):
    sys.stdout.write(json.dumps(obj, ensure_ascii=False) + "\n")
    sys.stdout.flush()


def _result(mid, result):
    send({"jsonrpc": "2.0", "id": mid, "result": result})


def _error(mid, code, message):
    send({"jsonrpc": "2.0", "id": mid, "error": {"code": code, "message": message}})


def main():
    for line in sys.stdin:
        line = line.strip()
        if not line:
            continue
        try:
            msg = json.loads(line)
        except Exception:
            _error(None, -32700, "parse error")
            continue
        mid = msg.get("id")
        method = msg.get("method")
        params = msg.get("params") or {}
        if method == "initialize":
            _result(mid, {
                "protocolVersion": params.get("protocolVersion", "2024-11-05"),
                "capabilities": {"tools": {}, "resources": {}},
                "serverInfo": {"name": "gama-shard-mvp", "version": VERSION},
                "instructions": (
                    "Shard MVP microVM workspaces. Call shard_health first. Keys are "
                    "[A-Za-z0-9._-]. Run `sync` inside the VM before shard_suspend; "
                    "exec on an unknown key auto-creates a workspace. "
                    "Backups go to $SHARD_BASE/backups/<key>."
                ),
            })
        elif method == "ping":
            _result(mid, {})
        elif method == "tools/list":
            _result(mid, {"tools": TOOLS})
        elif method == "tools/call":
            name = params.get("name")
            args = params.get("arguments")
            payload = call_tool(name, args)
            _result(mid, {
                "content": [{"type": "text", "text": json.dumps(payload, ensure_ascii=False)}],
                "isError": not bool(payload.get("ok")),
            })
        elif method == "resources/list":
            _result(mid, {"resources": []})
        elif method == "prompts/list":
            _result(mid, {"prompts": []})
        elif method in ("notifications/initialized", "notifications/cancelled"):
            continue
        elif mid is not None:
            _error(mid, -32601, "nepoznat method: %s" % method)


if __name__ == "__main__":
    if len(sys.argv) > 2 and sys.argv[1] == "--call":
        try:
            call_args = json.loads(sys.argv[3]) if len(sys.argv) > 3 else {}
        except Exception as exc:
            print(json.dumps({"ok": False, "err": "bad json args: %s" % exc}))
            sys.exit(2)
        out = call_tool(sys.argv[2], call_args)
        print(json.dumps(out, ensure_ascii=False))
        sys.exit(0 if out.get("ok") else 1)
    main()
