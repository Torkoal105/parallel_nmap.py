#!/usr/bin/env python3
"""
nmap_parallel_scan.py

Scans up to 255 hosts concurrently by launching one nmap subprocess per
host and waiting for all of them to finish (i.e. it blocks/joins until
every host has been scanned - "synchronous" from the caller's point of
view, but each host scan runs in parallel under the hood).

Usage examples:

# Scan a /24 subnet (up to 254 hosts), nmap args "-sV -sT -T5 -p- --host-timeout 30s --max-rtt-timeout 30s --initial-rtt-timeout 30s"

usage - parallel normal tcp (normal):
sudo python3 parallel_nmap_portscan_only.py -t 192.168.100.0/24 -a "-sV -sT -T5 -p- --host-timeout 30s --max-rtt-timeout 30s --initial-rtt-timeout 30s"

usage - parallel normal udp (slow):
sudo python3 parallel_nmap_portscan_only.py -t 192.168.100.0/24 -a "-sV -sU -T5 -p- --host-timeout 30s --max-rtt-timeout 30s --initial-rtt-timeout 30s"
"""

import argparse
import ipaddress
import os
import shutil
import subprocess
import sys
import tempfile
import xml.etree.ElementTree as ET
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime


def check_nmap_installed():
    if shutil.which("nmap") is None:
        sys.exit("Error: nmap is not installed or not on PATH.")


def load_hosts(args):
    hosts = []
    if args.target:
        net = ipaddress.ip_network(args.target, strict=False)
        if net.num_addresses == 1:
            # Single host, e.g. -t 192.168.1.5 (parsed as a /32)
            hosts = [str(net.network_address)]
        else:
            hosts = [str(ip) for ip in net.hosts()]
    elif args.hosts_file:
        with open(args.hosts_file) as f:
            hosts = [line.strip() for line in f if line.strip() and not line.startswith("#")]
    elif args.hosts:
        hosts = args.hosts

    if len(hosts) > 255:
        print(f"Warning: {len(hosts)} hosts given, only the first 255 will be scanned.")
        hosts = hosts[:255]

    return hosts


def scan_host(host, nmap_args, tmpdir):
    """Run a single nmap scan against one host, writing per-host XML + text
    into tmpdir (later merged into the combined nmap.xml / nmap.txt).
    Returns (host, returncode, xml_path, txt_path, stderr).
    """
    safe_name = host.replace("/", "_").replace(":", "_")
    xml_path = os.path.join(tmpdir, f"{safe_name}.xml")
    txt_path = os.path.join(tmpdir, f"{safe_name}.txt")

    cmd = ["nmap"] + nmap_args.split() + [host, "-oX", xml_path, "-oN", txt_path]

    try:
        result = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=300,  # per-host timeout, adjust as needed
        )
        return host, result.returncode, xml_path, txt_path, result.stderr
    except subprocess.TimeoutExpired:
        return host, -1, xml_path, txt_path, "Timed out"


def merge_txt(txt_paths, out_file):
    """Concatenate per-host human-readable output into one nmap.txt."""
    with open(out_file, "w") as out:
        out.write(f"# Combined nmap scan output - generated {datetime.now().isoformat()}\n\n")
        for path in txt_paths:
            if os.path.exists(path):
                with open(path) as f:
                    out.write(f.read())
                out.write("\n")


def merge_xml(xml_paths, out_file, nmap_args):
    """Merge per-host XML output into a single valid nmap.xml document."""
    root = ET.Element("nmaprun", {
        "scanner": "nmap",
        "args": f"nmap {nmap_args} <multiple hosts, merged>",
        "start": str(int(datetime.now().timestamp())),
        "startstr": datetime.now().strftime("%a %b %d %H:%M:%S %Y"),
    })

    scaninfo_added = False
    host_count = 0

    for path in xml_paths:
        if not os.path.exists(path):
            continue
        try:
            tree = ET.parse(path)
        except ET.ParseError:
            continue
        src_root = tree.getroot()

        if not scaninfo_added:
            scaninfo = src_root.find("scaninfo")
            if scaninfo is not None:
                root.append(scaninfo)
            scaninfo_added = True

        for host_el in src_root.findall("host"):
            root.append(host_el)
            host_count += 1

    runstats = ET.SubElement(root, "runstats")
    ET.SubElement(runstats, "finished", {
        "time": str(int(datetime.now().timestamp())),
        "timestr": datetime.now().strftime("%a %b %d %H:%M:%S %Y"),
    })
    ET.SubElement(runstats, "hosts", {
        "up": str(host_count), "down": "0", "total": str(host_count)
    })

    ET.ElementTree(root).write(out_file, encoding="utf-8", xml_declaration=True)


def main():
    parser = argparse.ArgumentParser(description="Scan up to 255 hosts in parallel with nmap.")
    src = parser.add_mutually_exclusive_group(required=True)
    src.add_argument("-t", "--target", help="Target: CIDR network (e.g. 192.168.178.0/24) or single host/IP")
    src.add_argument("--hosts-file", help="File containing one host/IP per line")
    src.add_argument("--hosts", nargs="+", help="Explicit list of hosts/IPs")

    parser.add_argument("-a", "--nmap-args", default="-sV -T4",
                         help='nmap flags to use per host, quoted (default: "-sV -T4"), '
                              'e.g. -a "-sV -sT -T5 -p-"')
    parser.add_argument("--outdir", default=".",
                         help="Directory to write combined nmap.xml / nmap.txt (default: current dir)")
    parser.add_argument("--workers", type=int, default=255,
                         help="Max concurrent nmap processes (default: 255)")
    parser.add_argument("--keep-per-host", action="store_true",
                         help="Keep the intermediate per-host XML/text files instead of deleting them")
    args = parser.parse_args()

    check_nmap_installed()
    hosts = load_hosts(args)
    if not hosts:
        sys.exit("No hosts to scan.")

    os.makedirs(args.outdir, exist_ok=True)
    xml_out = os.path.join(args.outdir, "nmap.xml")
    txt_out = os.path.join(args.outdir, "nmap.txt")

    # Per-host scans land here first, then get merged into the two
    # combined output files.
    workdir = os.path.join(args.outdir, "per_host") if args.keep_per_host else tempfile.mkdtemp(prefix="nmap_scan_")
    os.makedirs(workdir, exist_ok=True)

    print(f"Scanning {len(hosts)} hosts with up to {args.workers} concurrent workers "
          f"(nmap args: '{args.nmap_args}')")
    start = datetime.now()

    results = []
    xml_paths = []
    txt_paths = []
    with ThreadPoolExecutor(max_workers=args.workers) as executor:
        futures = {
            executor.submit(scan_host, host, args.nmap_args, workdir): host
            for host in hosts
        }
        # as_completed + result() blocks the main thread until every
        # future is done, so the script as a whole runs synchronously
        # relative to the caller even though scans overlap internally.
        for future in as_completed(futures):
            host = futures[future]
            try:
                host, rc, xml_path, txt_path, stderr = future.result()
                status = "OK" if rc == 0 else f"FAILED (rc={rc})"
                print(f"[{status}] {host}")
                if rc != 0 and stderr:
                    print(f"    stderr: {stderr.strip()[:200]}")
                results.append((host, rc))
                xml_paths.append(xml_path)
                txt_paths.append(txt_path)
            except Exception as e:
                print(f"[ERROR] {host}: {e}")
                results.append((host, None))

    elapsed = (datetime.now() - start).total_seconds()
    ok = sum(1 for _, rc in results if rc == 0)
    print(f"\nScans done: {ok}/{len(hosts)} succeeded in {elapsed:.1f}s")

    print("Merging output...")
    merge_txt(txt_paths, txt_out)
    merge_xml(xml_paths, xml_out, args.nmap_args)
    print(f"  -> {os.path.abspath(txt_out)}")
    print(f"  -> {os.path.abspath(xml_out)}")

    if not args.keep_per_host:
        shutil.rmtree(workdir, ignore_errors=True)


if __name__ == "__main__":
    main()
