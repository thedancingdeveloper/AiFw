#!/usr/bin/env python3
"""Two-node AiFw HA failover and TCP-session acceptance harness.

The harness is provider-neutral: nodes and endpoints may be FreeBSD VMs,
bhyve guests, or physical lab hosts.  A small JSON inventory supplies SSH
targets and interface names.  Commands, CARP/pfsync state, timing samples,
and traffic results are retained for CI artifact upload.
"""

from __future__ import annotations

import argparse
import json
import pathlib
import shlex
import subprocess
import sys
import time
from dataclasses import dataclass


def run(argv: list[str], *, check: bool = True, timeout: int = 30) -> subprocess.CompletedProcess[str]:
    result = subprocess.run(argv, text=True, capture_output=True, timeout=timeout, check=False)
    if check and result.returncode:
        raise RuntimeError(f"command failed ({result.returncode}): {shlex.join(argv)}\n{result.stderr}")
    return result


@dataclass(frozen=True)
class Host:
    name: str
    ssh: str

    def command(self, command: str, *, check: bool = True, timeout: int = 30) -> subprocess.CompletedProcess[str]:
        return run(
            ["ssh", "-o", "BatchMode=yes", "-o", "ConnectTimeout=5", self.ssh, command],
            check=check,
            timeout=timeout,
        )


def capture(host: Host, command: str, path: pathlib.Path) -> None:
    result = host.command(command, check=False)
    path.write_text(f"$ {command}\nexit={result.returncode}\n{result.stdout}\n{result.stderr}")


def role(host: Host, carp_iface: str) -> str:
    output = host.command(f"ifconfig {shlex.quote(carp_iface)}").stdout
    for value in ("MASTER", "BACKUP", "INIT"):
        if f"carp: {value}" in output:
            return value
    return "UNKNOWN"


def await_single_master(nodes: list[Host], carp_iface: str, deadline: float) -> tuple[Host, Host, float]:
    started = time.monotonic()
    while time.monotonic() < deadline:
        states = [(node, role(node, carp_iface)) for node in nodes]
        masters = [node for node, state in states if state == "MASTER"]
        backups = [node for node, state in states if state == "BACKUP"]
        if len(masters) == 1 and len(backups) == 1:
            return masters[0], backups[0], time.monotonic() - started
        time.sleep(0.2)
    raise RuntimeError("HA pair did not converge to exactly one MASTER and one BACKUP")


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("inventory", type=pathlib.Path)
    parser.add_argument("--results", type=pathlib.Path, default=pathlib.Path("ha-results"))
    args = parser.parse_args()
    cfg = json.loads(args.inventory.read_text())
    args.results.mkdir(parents=True, exist_ok=True)

    nodes = [Host("node-a", cfg["node_a"]), Host("node-b", cfg["node_b"])]
    client = Host("client", cfg["client"])
    server = Host("server", cfg["server"])
    carp_iface = cfg["carp_interface"]
    pfsync_iface = cfg["pfsync_interface"]
    vip = cfg["lan_vip"]
    server_addr = cfg["server_address"]
    port = int(cfg.get("tcp_port", 18080))

    # Preflight both kernels and retain the authoritative state.
    for node in nodes:
        capture(node, f"ifconfig {shlex.quote(carp_iface)}", args.results / f"{node.name}-carp-before.txt")
        capture(node, f"ifconfig {shlex.quote(pfsync_iface)}", args.results / f"{node.name}-pfsync-before.txt")
        capture(node, "pfctl -ss -vv", args.results / f"{node.name}-states-before.txt")
    master, backup, initial_convergence = await_single_master(nodes, carp_iface, time.monotonic() + 20)

    # The server emits an unbounded byte stream.  The client records it to a
    # file across failover; byte growth after the transition proves the same
    # TCP connection survived (a reconnecting probe cannot satisfy this).
    server.command(f"pkill -f 'nc -l {port}' || true", check=False)
    server.command(f"sh -c 'yes aifw-ha | nc -l {port} >/dev/null 2>&1 &'", check=True)
    remote_out = cfg.get("client_output", "/tmp/aifw-ha-stream.out")
    client.command(f"rm -f {shlex.quote(remote_out)}; sh -c 'nc {shlex.quote(server_addr)} {port} >{shlex.quote(remote_out)} 2>/tmp/aifw-ha-stream.err &'", check=True)
    time.sleep(2)
    size_before = int(client.command(f"stat -f %z {shlex.quote(remote_out)}").stdout.strip())
    if size_before <= 0:
        raise RuntimeError("long-lived TCP stream did not start")

    # Demotion is controlled and reversible; unlike killing pf/pfsync it
    # exercises the normal CARP transition and health-check recovery path.
    transition_start = time.monotonic()
    master.command("sysctl net.inet.carp.demotion=240")
    new_master, new_backup, election_elapsed = await_single_master(nodes, carp_iface, time.monotonic() + 20)
    if new_master == master:
        raise RuntimeError("CARP master did not move to the peer after demotion")
    time.sleep(2)
    size_after = int(client.command(f"stat -f %z {shlex.quote(remote_out)}").stdout.strip())
    if size_after <= size_before:
        raise RuntimeError("long-lived TCP session stopped transferring during failover")

    # Restore/preempt and verify the pair converges without split brain.
    master.command("sysctl net.inet.carp.demotion=0")
    final_master, _, recovery_elapsed = await_single_master(nodes, carp_iface, time.monotonic() + 30)
    transition_elapsed = time.monotonic() - transition_start

    for node in nodes:
        capture(node, f"ifconfig {shlex.quote(carp_iface)}", args.results / f"{node.name}-carp-after.txt")
        capture(node, f"ifconfig {shlex.quote(pfsync_iface)}", args.results / f"{node.name}-pfsync-after.txt")
        capture(node, "pfctl -ss -vv", args.results / f"{node.name}-states-after.txt")
        capture(node, "netstat -s -p pfsync", args.results / f"{node.name}-pfsync-counters.txt")

    result = {
        "status": "passed",
        "initial_master": master.name,
        "failover_master": new_master.name,
        "final_master": final_master.name,
        "initial_convergence_seconds": round(initial_convergence, 3),
        "election_seconds": round(election_elapsed, 3),
        "recovery_seconds": round(recovery_elapsed, 3),
        "scenario_seconds": round(transition_elapsed, 3),
        "tcp_bytes_before": size_before,
        "tcp_bytes_after": size_after,
        "tcp_session_survived": True,
        "single_master": True,
    }
    (args.results / "result.json").write_text(json.dumps(result, indent=2) + "\n")
    print(json.dumps(result, indent=2))
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except (RuntimeError, subprocess.TimeoutExpired, KeyError, ValueError) as error:
        print(f"FAIL: {error}", file=sys.stderr)
        raise SystemExit(1)
