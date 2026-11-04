# gama-shard

Persistent **Firecracker microVM workspaces**: cold open ~2.3 s, warm exec ~10 ms,
suspend/resume with snapshot backup, HTTP API and an MCP wrapper (stdio).

## Requirements
- Linux with `/dev/kvm` (AMD-V/VMX), `/dev/net/tun` optional
- Firecracker v1.17 (`/opt/fc/release-v1.17.0-x86_64/firecracker-v1.17.0-x86_64`)
- kernel with vsock (`/opt/fc/vmlinux.bin`)
- ext4 rootfs with the guest agent installed (`SHARD_TEMPLATE`)

## Configure (env)
| var | default |
|---|---|
| `SHARD_BASE` | `/var/lib/shard-mvp` |
| `SHARD_TEMPLATE` | `$SHARD_BASE/rootfs.ext4` |
| `SHARD_WS` | `/dev/shm/shard-mvp/ws` |
| `SHARD_TOKEN_FILE` | `$SHARD_BASE/token` (or `SHARD_TOKEN`) |
| `SHARD_PORT` | `7150` |
| `SHARD_POOL` | `1` (prewarmed VMs) |

## Run
```bash
export SHARD_TOKEN=$(head -c24 /dev/urandom | base64)
python3 shard_mvp.py
curl -H "X-Token: $SHARD_TOKEN" localhost:7150/health
```
MCP (stdio): `SHARD_URL=http://127.0.0.1:7150 SHARD_TOKEN=... python3 shard_mcp.py`
CLI smoke: `python3 shard_mcp.py --call shard_health '{}'`

## API (selected)
`GET /health`, `/stats`, `/metrics` · `POST /v1/workspaces/<key>/open|exec|suspend|resume|delete|backup`
`POST /v1/workspaces/<key>/fork` · `GET /v1/workspaces`

## Measured (MI250X lab host, 2026-11-02)
- cold boot **2.39 s**, snapshot load **2.4 ms**
- warm exec **10.3 ms** (min/med/max 10.3/10.4/10.7 over 10 tasks), 3 concurrent tasks isolated
- guest `uname -r` 4.14.174; `ls /root` empty (isolation); no network in guest by default

## Tests
```bash
python3 -m unittest discover -s tests -v   # offline unit tests
```
MCP wrapper is tested with `--call shard_health` against a running service.
Related: https://github.com/gamai-io/crossnode-bench (DOI 10.5281/zenodo.23933835). Apache-2.0.
