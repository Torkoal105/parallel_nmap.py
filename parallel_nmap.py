#!/usr/bin/env python3
"""
parallel_nmap.py

usage - parallel normal tcp (normal):
sudo python3 parallel_nmap.py -t 192.168.100.0/24 -a "-sV -sT -T5 -p- --host-timeout 30s --max-rtt-timeout 30s --initial-rtt-timeout 30s"

usage - parallel normal udp (slow):
sudo python3 parallel_nmap.py -t 192.168.100.0/24 -a "-sV -sU -T5 -p- --host-timeout 30s --max-rtt-timeout 30s --initial-rtt-timeout 30s"

usage - parallel disruptive tcp (fast):
sudo python3 parallel_nmap.py -t 192.168.100.0/24 -a "-sV -sT -p- --host-timeout 30s --max-rtt-timeout 30s --initial-rtt-timeout 30s --min-parallelism 50000 --max-rtt-timeout 1500ms --min-rate 4500"

usage - parallel disruptive udp (normal):
sudo python3 parallel_nmap.py -t 192.168.100.0/24 -a "-sV -sU -p- --host-timeout 30s --max-rtt-timeout 30s --initial-rtt-timeout 30s --min-parallelism 50000 --max-rtt-timeout 1500ms --min-rate 4500"

-p- = all 65535 ports
-sV = version discovery
-sT = tcp
-T5 = speed up
--host-timeout 30s = speed up
--max-rtt-timeout 30s = speed up
--initial-rtt-timeout 30s = speed up

--min-parallelism 50000 = speed up (disruptive) (inaccurate)
--max-rtt-timeout 1500ms = speed up (disruptive) (inaccurate)
--min-rate 4500 = speed up (disruptive) (inaccurate)
"""

"""
Discover live hosts with `nmap -sn` (ping scan), then scan every host
concurrently (one nmap process per host, launched in parallel via a
thread pool) with a live progress bar, merging all per-host results
into a single nmap.xml and a single human-readable nmap.txt.

Dependencies: none beyond the Python 3 standard library. `nmap` itself
must be installed and on PATH.

Usage examples
--------------
# Discover hosts on a subnet, then run "nmap -sV -T4" against each one,
# 10 at a time, merging output into nmap.xml + nmap.txt
python3 parallel_nmap.py -t 192.168.1.0/24 -a "-sV -T4" -j 10

# Reuse an existing `nmap -sn` output file instead of re-running discovery
nmap -sn 192.168.1.0/24 -oN hosts.txt
python3 parallel_nmap.py -i hosts.txt -a "-p 1-1000 -sV"

Notes
-----
- Per-host scans that need raw sockets (SYN scan, OS detection, etc.) need
  root/administrator privileges, same as running nmap directly.
- "In sync" means launched concurrently via a thread pool (each nmap
  invocation is its own OS process), not synchronized to the same instant.
- nmap.xml is a single valid nmap-style XML document: one <nmaprun> root
  containing every host's <host> element and combined <runstats>,
  produced by merging each host's individual -oX output.
- nmap.txt is nmap's normal human-readable report (-oN) for every host,
  concatenated with a summary header and per-host separators.
"""

import argparse
import concurrent.futures
import re
import shlex
import subprocess
import sys
import tempfile
import xml.etree.ElementTree as ET
from datetime import datetime
from pathlib import Path


def discover_hosts(target: str) -> list[str]:
    """Run `nmap -sn <target>` and return the list of hosts that were up."""
    cmd = ["nmap", "-sn", target]
    print(f"[*] Running discovery: {' '.join(cmd)}", file=sys.stderr)
    result = subprocess.run(cmd, capture_output=True, text=True)
    if result.returncode != 0:
        print(result.stderr, file=sys.stderr)
        raise SystemExit(f"[!] nmap discovery failed with exit code {result.returncode}")
    return parse_hosts(result.stdout)


def parse_hosts(nmap_output: str) -> list[str]:
    """Extract IP addresses from `nmap -sn` style output text."""
    hosts = []
    for line in nmap_output.splitlines():
        m = re.match(r"^Nmap scan report for (?:\S+\s+\()?([\da-fA-F:.]+)\)?$", line.strip())
        if m:
            hosts.append(m.group(1))
    return hosts


def scan_host(host: str, extra_args: list[str], xml_path: Path, text_path: Path) -> tuple[str, int]:
    """Run a single nmap scan against one host, writing XML (-oX) and
    human-readable (-oN) output to xml_path / text_path."""
    cmd = ["nmap"] + extra_args + ["-oX", str(xml_path), "-oN", str(text_path), host]
    result = subprocess.run(cmd, capture_output=True, text=True)
    return host, result.returncode


def print_progress(done: int, total: int, width: int = 40) -> None:
    """Render a simple stdlib-only progress bar in place on one line."""
    frac = done / total if total else 1.0
    filled = int(width * frac)
    bar = "#" * filled + "-" * (width - filled)
    sys.stdout.write(f"\r[{bar}] {done}/{total} ({frac * 100:5.1f}%)")
    sys.stdout.flush()
    if done == total:
        sys.stdout.write("\n")


def merge_xml(xml_files: list[Path], output_path: Path) -> None:
    """Merge multiple per-host nmap -oX files into a single nmap.xml."""
    trees = [ET.parse(f) for f in xml_files if f.exists()]
    if not trees:
        raise SystemExit("[!] No per-host XML output to merge.")

    base_root = trees[0].getroot()

    # Collect every <host> element from every tree BEFORE mutating base_root
    # (trees[0]'s root IS base_root, so stripping it first would lose its host).
    all_host_els = []
    for tree in trees:
        all_host_els.extend(tree.getroot().findall("host"))

    # Strip existing <host> elements and pull <runstats> out so we can
    # reinsert hosts before it (matches real nmap XML element ordering).
    for host_el in list(base_root.findall("host")):
        base_root.remove(host_el)
    runstats = base_root.find("runstats")
    if runstats is not None:
        base_root.remove(runstats)

    up = down = 0
    for host_el in all_host_els:
        base_root.append(host_el)
        status = host_el.find("status")
        if status is not None and status.get("state") == "up":
            up += 1
        else:
            down += 1

    # Re-append <runstats> at the end, with counts/finish time updated for the merge.
    if runstats is not None:
        base_root.append(runstats)
        finished = runstats.find("finished")
        if finished is not None:
            now = datetime.now()
            finished.set("time", str(int(now.timestamp())))
            finished.set("timestr", now.strftime("%a %b %d %H:%M:%S %Y"))
        hosts_el = runstats.find("hosts")
        if hosts_el is not None:
            hosts_el.set("up", str(up))
            hosts_el.set("down", str(down))
            hosts_el.set("total", str(up + down))

    ET.indent(base_root, space="  ")
    ET.ElementTree(base_root).write(output_path, encoding="utf-8", xml_declaration=True)


def merge_text(hosts: list[str], text_files: dict[str, Path], elapsed: float, output_path: Path) -> None:
    """Concatenate each host's -oN human-readable output into one report."""
    found = sum(1 for h in hosts if text_files[h].exists())
    now = datetime.now().strftime("%a %b %d %H:%M:%S %Y")

    lines = [
        "=" * 70,
        "Parallel Nmap Scan Report",
        f"Generated: {now}",
        f"Hosts scanned: {len(hosts)}  (results found for {found})",
        f"Total scan time: {elapsed:.1f}s",
        "=" * 70,
        "",
    ]

    for host in hosts:
        lines.append("-" * 70)
        lines.append(f"Host: {host}")
        lines.append("-" * 70)
        path = text_files[host]
        if path.exists():
            content = path.read_text().strip()
            # Drop nmap's own "Starting Nmap ..." banner line for readability,
            # since it's repeated identically for every host.
            content_lines = [ln for ln in content.splitlines() if not ln.startswith("Starting Nmap")]
            lines.append("\n".join(content_lines))
        else:
            lines.append("(no output - scan may have failed)")
        lines.append("")

    output_path.write_text("\n".join(lines))


def main():
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    src = parser.add_mutually_exclusive_group(required=True)
    src.add_argument("-t", "--target", help="Target/subnet to run `nmap -sn` against, e.g. 192.168.1.0/24")
    src.add_argument("-i", "--input", help="Path to an existing `nmap -sn` output file to parse instead of scanning")

    parser.add_argument(
        "-a", "--args", default="-sV -T4",
        help='Extra nmap arguments to use for the per-host scan (default: "-sV -T4"). '
             'Pass as a single quoted string, e.g. -a "-p- -sS"'
    )
    parser.add_argument(
        "-j", "--jobs", type=int, default=255,
        help="Max number of nmap scans to run concurrently (default: 255)"
    )
    parser.add_argument(
        "-o", "--output", default="nmap.xml",
        help="Path to write the merged XML results to (default: nmap.xml)"
    )
    parser.add_argument(
        "-T", "--text-output", default="nmap.txt",
        help="Path to write the merged human-readable report to (default: nmap.txt)"
    )
    args = parser.parse_args()

    if args.input:
        text = Path(args.input).read_text()
        hosts = parse_hosts(text)
    else:
        hosts = discover_hosts(args.target)

    if not hosts:
        print("[!] No live hosts found.", file=sys.stderr)
        sys.exit(1)

    print(f"[*] Found {len(hosts)} live host(s): {', '.join(hosts)}", file=sys.stderr)

    extra_args = shlex.split(args.args)
    print(f"[*] Launching nmap ({' '.join(extra_args)}) against all hosts, {args.jobs} at a time...", file=sys.stderr)

    start = datetime.now()
    failed_hosts = []
    with tempfile.TemporaryDirectory(prefix="nmap_parallel_") as tmpdir:
        tmp_path = Path(tmpdir)
        xml_files = {host: tmp_path / f"{host.replace(':', '_')}.xml" for host in hosts}
        text_files = {host: tmp_path / f"{host.replace(':', '_')}.txt" for host in hosts}

        with concurrent.futures.ThreadPoolExecutor(max_workers=args.jobs) as pool:
            futures = {
                pool.submit(scan_host, host, extra_args, xml_files[host], text_files[host]): host
                for host in hosts
            }
            done = 0
            print_progress(done, len(hosts))
            for future in concurrent.futures.as_completed(futures):
                host = futures[future]
                try:
                    host, rc = future.result()
                    if rc != 0:
                        failed_hosts.append(host)
                except Exception:
                    failed_hosts.append(host)
                done += 1
                print_progress(done, len(hosts))

        elapsed = (datetime.now() - start).total_seconds()

        if failed_hosts:
            print(f"[!] {len(failed_hosts)} host(s) failed: {', '.join(failed_hosts)}", file=sys.stderr)

        print(f"[*] All scans finished in {elapsed:.1f}s. Merging results...", file=sys.stderr)

        merge_xml(list(xml_files.values()), Path(args.output))
        merge_text(hosts, text_files, elapsed, Path(args.text_output))

    print(f"[*] XML results written to {args.output}", file=sys.stderr)
    print(f"[*] Human-readable report written to {args.text_output}", file=sys.stderr)


if __name__ == "__main__":
    main()
