#!/usr/bin/env python3
import argparse
import ipaddress
import subprocess
import socket
import sys
import json
import csv
import re
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import Path

# ANSI colors
GREEN = '\033[0;32m'
RED = '\033[0;31m'
YELLOW = '\033[1;33m'
BLUE = '\033[0;34m'
CYAN = '\033[0;36m'
BOLD = '\033[1m'
NC = '\033[0m'

BANNER = f"""

███╗   ███╗██╗   ██╗██╗  ████████╗██╗██████╗ ██╗     ███████╗    ██╗██████╗     
████╗ ████║██║   ██║██║  ╚══██╔══╝██║██╔══██╗██║     ██╔════╝    ██║██╔══██╗    
██╔████╔██║██║   ██║██║     ██║   ██║██████╔╝██║     █████╗      ██║██████╔╝    
██║╚██╔╝██║██║   ██║██║     ██║   ██║██╔═══╝ ██║     ██╔══╝      ██║██╔═══╝     
██║ ╚═╝ ██║╚██████╔╝███████╗██║   ██║██║     ███████╗███████╗    ██║██║         
╚═╝     ╚═╝ ╚═════╝ ╚══════╝╚═╝   ╚═╝╚═╝     ╚══════╝╚══════╝    ╚═╝╚═╝         
	                                                                                
███████╗ ██████╗ █████╗ ███╗   ██╗███╗   ██╗██╗███╗   ██╗ ██████╗               
██╔════╝██╔════╝██╔══██╗████╗  ██║████╗  ██║██║████╗  ██║██╔════╝               
███████╗██║     ███████║██╔██╗ ██║██╔██╗ ██║██║██╔██╗ ██║██║  ███╗              
╚════██║██║     ██╔══██║██║╚██╗██║██║╚██╗██║██║██║╚██╗██║██║   ██║              
███████║╚██████╗██║  ██║██║ ╚████║██║ ╚████║██║██║ ╚████║╚██████╔╝              
╚══════╝ ╚═════╝╚═╝  ╚═╝╚═╝  ╚═══╝╚═╝  ╚═══╝╚═╝╚═╝  ╚═══╝ ╚═════╝               
                                                                                
** The author is not responsible for any consequences resulting from this script, 
as it was created solely for testing purposes in a lab or on a local network.
beyond the scope of applicable international law. **

Author by anggrdwjy
Source : https://github.com/anggrdwjy/multiple-ipscan
"""

def detect_ping_cmd():
    """Detect available ping commands for v4 and v6"""
    has_ping6 = False
    has_ping4_flag = False
    has_ping6_flag = False

    # check ping6 binary
    try:
        subprocess.run(["which", "ping6"], capture_output=True, timeout=1)
        # more accurate: check command -v
        result = subprocess.run(["ping6", "-c", "1", "-W", "1", "::1"], capture_output=True, timeout=2)
        has_ping6 = True
    except:
        has_ping6 = False

    # check ping -4 and -6 support
    try:
        r = subprocess.run(["ping", "-4", "-c", "1", "-W", "1", "127.0.0.1"], capture_output=True, timeout=2)
        has_ping4_flag = True
    except:
        has_ping4_flag = False

    try:
        r = subprocess.run(["ping", "-6", "-c", "1", "-W", "1", "::1"], capture_output=True, timeout=2)
        has_ping6_flag = True
    except:
        has_ping6_flag = False

    return has_ping6, has_ping4_flag, has_ping6_flag

HAS_PING6_BIN, HAS_PING4_FLAG, HAS_PING6_FLAG = detect_ping_cmd()

def parse_single_target(t, max_per_target, all_v4, all_v6, warnings):
    """Parse a single target (v4 or v6) and add it to the dict"""
    t = t.strip()
    if not t:
        return

    # Keep original for ping if %iface exists (link-local)
    original_t = t
    t_clean = t.split('%')[0] if '%' in t else t

    is_v6 = ':' in t_clean

    if is_v6:
        # IPv6
        if '/' in t_clean:
            try:
                net = ipaddress.IPv6Network(t_clean, strict=False)
                num = net.num_addresses
                if num > max_per_target:
                    warnings.append(f"Prefix {original_t} has {num} addresses > limit {max_per_target}, taking first {max_per_target}.")
                    start = int(net.network_address)
                    for i in range(max_per_target):
                        ip_int = start + i
                        if ip_int not in all_v6:
                            all_v6[ip_int] = str(ipaddress.IPv6Address(ip_int))
                else:
                    if net.prefixlen == 128:
                        ip_int = int(net.network_address)
                        if ip_int not in all_v6:
                            all_v6[ip_int] = str(net.network_address)
                    elif net.prefixlen == 127:
                        for ip in net:
                            ip_int = int(ip)
                            if ip_int not in all_v6:
                                all_v6[ip_int] = str(ip)
                    else:
                        for ip in net:
                            ip_int = int(ip)
                            if ip_int not in all_v6:
                                all_v6[ip_int] = str(ip)
            except Exception as e:
                raise ValueError(f"Invalid IPv6 CIDR format '{original_t}': {e}")

        elif '-' in t_clean:
            try:
                # handle shorthand fd00::1-ff
                parts = t_clean.split('-', 1)
                start_str = parts[0].strip()
                end_str = parts[1].strip()

                if ':' not in end_str and '::' not in end_str:
                    # shorthand hextet
                    try:
                        start_ip = ipaddress.IPv6Address(start_str)
                        s_int = int(start_ip)
                        e_suffix = int(end_str, 16)
                        start_last = s_int & 0xFFFF
                        e_int = s_int - start_last + e_suffix
                        if e_int < s_int:
                            s_int, e_int = e_int, s_int
                        count = e_int - s_int + 1
                        if count > max_per_target:
                            warnings.append(f"Range {original_t} {count} > {max_per_target}, truncated.")
                            e_int = s_int + max_per_target - 1
                        for i in range(s_int, e_int+1):
                            if i not in all_v6:
                                all_v6[i] = str(ipaddress.IPv6Address(i))
                        return
                    except:
                        pass

                start_ip = ipaddress.IPv6Address(start_str)
                end_ip = ipaddress.IPv6Address(end_str)
                s = int(start_ip)
                e = int(end_ip)
                if s > e:
                    s, e = e, s
                count = e - s + 1
                if count > max_per_target:
                    warnings.append(f"Range {original_t} {count} > {max_per_target}, taking first {max_per_target}.")
                    e = s + max_per_target - 1
                for i in range(s, e+1):
                    if i not in all_v6:
                        all_v6[i] = str(ipaddress.IPv6Address(i))
            except Exception as ex:
                raise ValueError(f"Invalid IPv6 Range format '{original_t}': {ex}")
        else:
            try:
                ip = ipaddress.IPv6Address(t_clean)
                ip_int = int(ip)
                if ip_int not in all_v6:
                    # if %iface exists, keep original for ping
                    all_v6[ip_int] = original_t if '%' in original_t else str(ip)
            except Exception as ex:
                raise ValueError(f"Invalid IPv6 Single IP format '{original_t}': {ex}")
    else:
        # IPv4
        if '/' in t_clean:
            try:
                net = ipaddress.IPv4Network(t_clean, strict=False)
                if net.prefixlen == 32:
                    hosts = [net.network_address]
                elif net.prefixlen == 31:
                    hosts = [net.network_address, net.broadcast_address]
                else:
                    hosts = list(net.hosts())

                if len(hosts) > max_per_target:
                    warnings.append(f"Prefix {original_t} has {len(hosts)} hosts > limit {max_per_target}, taking first {max_per_target}.")
                    hosts = hosts[:max_per_target]

                for ip in hosts:
                    ip_int = int(ip)
                    if ip_int not in all_v4:
                        all_v4[ip_int] = str(ip)
            except Exception as e:
                raise ValueError(f"Invalid IPv4 CIDR format '{original_t}': {e}")

        elif '-' in t_clean:
            try:
                parts = t_clean.split('-', 1)
                start_ip = ipaddress.IPv4Address(parts[0].strip())
                end_ip = ipaddress.IPv4Address(parts[1].strip())
                s = int(start_ip)
                e = int(end_ip)
                if s > e:
                    s, e = e, s
                count = e - s + 1
                if count > max_per_target:
                    warnings.append(f"Range {original_t} {count} > {max_per_target}, truncated.")
                    e = s + max_per_target - 1
                for i in range(s, e+1):
                    if i not in all_v4:
                        all_v4[i] = str(ipaddress.IPv4Address(i))
            except Exception as e:
                raise ValueError(f"Invalid IPv4 Range format '{original_t}': {e}")
        else:
            try:
                ip = ipaddress.IPv4Address(t_clean)
                ip_int = int(ip)
                if ip_int not in all_v4:
                    all_v4[ip_int] = str(ip)
            except Exception as e:
                raise ValueError(f"Invalid IPv4 Single IP format '{original_t}': {e}")


def parse_targets(target_str, max_per_target):
    all_v4 = {}
    all_v6 = {}
    warnings = []

    for raw in target_str.split(','):
        raw = raw.strip()
        if not raw:
            continue
        parse_single_target(raw, max_per_target, all_v4, all_v6, warnings)

    # Merge and sort: v4 first, then v6
    v4_sorted = [all_v4[k] for k in sorted(all_v4.keys())]
    v6_sorted = [all_v6[k] for k in sorted(all_v6.keys())]

    all_ips = v4_sorted + v6_sorted
    return all_ips, len(v4_sorted), len(v6_sorted), warnings


def ping_host(ip_str, timeout):
    """Return True if host is UP"""
    is_v6 = ':' in ip_str
    ip_clean = ip_str.split('%')[0] if '%' in ip_str else ip_str

    try:
        if is_v6:
            if HAS_PING6_BIN:
                cmd = ["ping6", "-c", "1", "-W", str(timeout), ip_str]
            elif HAS_PING6_FLAG:
                cmd = ["ping", "-6", "-c", "1", "-W", str(timeout), ip_str]
            else:
                cmd = ["ping", "-c", "1", "-W", str(timeout), ip_str]
        else:
            if HAS_PING4_FLAG:
                cmd = ["ping", "-4", "-c", "1", "-W", str(timeout), ip_clean]
            else:
                cmd = ["ping", "-c", "1", "-W", str(timeout), ip_clean]

        result = subprocess.run(cmd, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, timeout=timeout+1)
        return result.returncode == 0
    except:
        return False


def get_hostname(ip_str):
    """Reverse DNS lookup"""
    ip_clean = ip_str.split('%')[0] if '%' in ip_str else ip_str
    try:
        hostname, _, _ = socket.gethostbyaddr(ip_clean)
        return hostname.rstrip('.')
    except:
        # fallback: try using host command
        try:
            result = subprocess.run(["host", ip_clean], capture_output=True, text=True, timeout=2)
            m = re.search(r'domain name pointer (.+)\.', result.stdout)
            if m:
                return m.group(1)
        except:
            pass
        return "-"


def get_mac(ip_str):
    """Get MAC from ip neighbor"""
    ip_clean = ip_str.split('%')[0] if '%' in ip_str else ip_str
    is_v6 = ':' in ip_str
    try:
        if is_v6:
            # try ip -6 neigh
            result = subprocess.run(["ip", "-6", "neighbor", "show", ip_clean], capture_output=True, text=True, timeout=1)
            if result.stdout:
                m = re.search(r'([0-9a-fA-F]{2}:){5}[0-9a-fA-F]{2}', result.stdout)
                if m:
                    return m.group(0).lower()
            # fallback ip neigh
            result = subprocess.run(["ip", "neighbor", "show", ip_clean], capture_output=True, text=True, timeout=1)
            m = re.search(r'([0-9a-fA-F]{2}:){5}[0-9a-fA-F]{2}', result.stdout)
            if m:
                return m.group(0).lower()
        else:
            result = subprocess.run(["ip", "neighbor", "show", ip_clean], capture_output=True, text=True, timeout=1)
            m = re.search(r'([0-9a-fA-F]{2}:){5}[0-9a-fA-F]{2}', result.stdout)
            if m:
                return m.group(0).lower()
            # fallback arp
            result = subprocess.run(["arp", "-n", ip_clean], capture_output=True, text=True, timeout=1)
            m = re.search(r'([0-9a-fA-F]{2}:){5}[0-9a-fA-F]{2}', result.stdout)
            if m:
                return m.group(0).lower()
    except:
        pass
    return "-"


def scan_host(ip_str, timeout):
    """Scan one host, return dict"""
    is_up = ping_host(ip_str, timeout)
    if is_up:
        hostname = get_hostname(ip_str)
        mac = get_mac(ip_str)
        status = "UP"
    else:
        hostname = "-"
        mac = "-"
        status = "DOWN"

    version = "v6" if ':' in ip_str else "v4"

    return {
        "ip": ip_str,
        "status": status,
        "hostname": hostname,
        "mac": mac,
        "version": version
    }


def main():
    parser = argparse.ArgumentParser(
        description="Advanced Hybrid IPv4/IPv6 Scanner - Python Version",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Usage examples:
  %(prog)s 192.168.1.0/24
  %(prog)s fd00::/120 --csv result.csv --json result.json
  %(prog)s 192.168.1.1,fd00::1,10.0.0.1-10.0.0.20 -t 1 --jobs 100 --up-only
  %(prog)s 8.8.8.8,1.1.1.1 --csv google_dns.csv --json google_dns.json --all
        """
    )
    parser.add_argument("target", help="Target IP/CIDR/Range, comma-separated for multiple. Can mix v4 & v6. Example: 192.168.1.0/24,fd00::/120")
    parser.add_argument("-t", "--timeout", type=int, default=1, help="Ping timeout in seconds (default: 1)")
    parser.add_argument("-m", "--mode", choices=["all", "up_only"], default="all", help="Display mode: all (UP & DOWN) or up_only (default: all)")
    parser.add_argument("--max-ips", type=int, default=65536, help="Max IPs per target (anti /64 bomb, default: 65536)")
    parser.add_argument("--jobs", type=int, default=100, help="Number of concurrent threads (default: 100, bash version is 80)")
    parser.add_argument("--csv", dest="csv_file", help="Export results to CSV")
    parser.add_argument("--json", dest="json_file", help="Export results to JSON")
    parser.add_argument("--up-only", action="store_true", help="Shortcut for --mode up_only")
    parser.add_argument("--no-color", action="store_true", help="Disable colors")
    parser.add_argument("--no-banner", action="store_true", help="Hide ASCII banner")

    args = parser.parse_args()

    if args.up_only:
        args.mode = "up_only"

    use_color = not args.no_color
    
	# Banner
    if not args.no_banner:
        print(BANNER)
		
    # Parse targets
    try:
        all_ips, total_v4, total_v6, warnings = parse_targets(args.target, args.max_ips)
    except ValueError as e:
        print(f"{RED if use_color else ''}Error: {e}{NC if use_color else ''}")
        sys.exit(1)

    total_hosts = len(all_ips)

    if total_hosts == 0:
        print(f"{RED if use_color else ''}No valid IPs found.{NC if use_color else ''}")
        sys.exit(1)

    for w in warnings:
        print(f"{YELLOW if use_color else ''}[WARN] {w}{NC if use_color else ''}")

    print(f"{BOLD if use_color else ''}{'='*104}{NC if use_color else ''}")
    print(f"{BOLD if use_color else ''}Scan Target    : {YELLOW if use_color else ''}{args.target}{NC if use_color else ''}")
    print(f"{BOLD if use_color else ''}Total IP       : {total_hosts} IP (v4: {total_v4}, v6: {total_v6}) limit {args.max_ips}/target{NC if use_color else ''}")
    print(f"{BOLD if use_color else ''}Timeout / Jobs : {args.timeout}s / {args.jobs} threads{NC if use_color else ''}")
    print(f"{BOLD if use_color else ''}{'='*104}{NC if use_color else ''}")

    # Scanning
    results = []
    total_up = 0
    start_time = time.time()

    # Header tabel
    header_ip = "IP Address"
    header_status = "Status"
    header_hostname = "Hostname"
    header_mac = "MAC Address"
    header_ver = "Ver"

    if use_color:
        print(f"{BOLD}{header_ip:<40} {header_status:<8} {header_hostname:<30} {header_mac:<18} {header_ver}{NC}")
    else:
        print(f"{header_ip:<40} {header_status:<8} {header_hostname:<30} {header_mac:<18} {header_ver}")
    print("="*104)

    with ThreadPoolExecutor(max_workers=args.jobs) as executor:
        future_to_ip = {executor.submit(scan_host, ip, args.timeout): ip for ip in all_ips}

        for future in as_completed(future_to_ip):
            try:
                res = future.result()
                results.append(res)

                if res["status"] == "UP":
                    total_up += 1

                # Display live (real-time)
                if res["status"] == "UP" or args.mode == "all":
                    ip_display = res["ip"]
                    # Sort later, but display in completion order
                    # Store first, display sorted at the end
                    pass

            except Exception as e:
                ip = future_to_ip[future]
                results.append({"ip": ip, "status": "DOWN", "hostname": "-", "mac": "-", "version": "v6" if ':' in ip else "v4"})

    # Sort results for final display: v4 first then v6, numeric
    def sort_key(r):
        try:
            ip_clean = r["ip"].split('%')[0]
            if ':' in ip_clean:
                return (1, int(ipaddress.IPv6Address(ip_clean)))
            else:
                return (0, int(ipaddress.IPv4Address(ip_clean)))
        except:
            return (2, 0)

    results.sort(key=sort_key)

    # Display sorted
    for res in results:
        if res["status"] == "UP" or args.mode == "all":
            if use_color:
                if res["status"] == "UP":
                    if res["version"] == "v6":
                        color_ip = CYAN
                    else:
                        color_ip = GREEN
                    color_status = GREEN
                else:
                    if res["version"] == "v6":
                        color_ip = BLUE
                    else:
                        color_ip = RED
                    color_status = RED
                print(f"{color_ip}{res['ip']:<40}{NC} {color_status}{res['status']:<8}{NC} {res['hostname']:<30} {res['mac']:<18} {res['version']}")
            else:
                print(f"{res['ip']:<40} {res['status']:<8} {res['hostname']:<30} {res['mac']:<18} {res['version']}")

    elapsed = time.time() - start_time
    total_down = total_hosts - total_up
    total_up_v4 = sum(1 for r in results if r["status"] == "UP" and r["version"] == "v4")
    total_up_v6 = total_up - total_up_v4
    print("="*104)
    if use_color:
        print(f"{BOLD}Summary:{NC} Total: {total_hosts} (v4:{total_v4} v6:{total_v6}) | {GREEN}UP: {total_up} (v4:{total_up_v4} v6:{total_up_v6}){NC} | {RED}DOWN: {total_down}{NC} | Elapsed: {elapsed:.1f}s")
    else:
        print(f"Summary: Total: {total_hosts} (v4:{total_v4} v6:{total_v6}) | UP: {total_up} (v4:{total_up_v4} v6:{total_up_v6}) | DOWN: {total_down} | Elapsed: {elapsed:.1f}s")
    print()

    # Export CSV
    if args.csv_file:
        try:
            with open(args.csv_file, 'w', newline='', encoding='utf-8') as f:
                writer = csv.DictWriter(f, fieldnames=["ip", "status", "hostname", "mac", "version"])
                writer.writeheader()
                for r in results:
                    if r["status"] == "UP" or args.mode == "all":
                        writer.writerow(r)
            print(f"{GREEN if use_color else ''}[OK] CSV results saved to: {args.csv_file}{NC if use_color else ''}")
        except Exception as e:
            print(f"{RED if use_color else ''}[ERR] Failed to save CSV: {e}{NC if use_color else ''}")

    # Export JSON
    if args.json_file:
        try:
            export_data = []
            for r in results:
                if r["status"] == "UP" or args.mode == "all":
                    export_data.append(r)

            # Add metadata
            output = {
                "target": args.target,
                "total": total_hosts,
                "total_v4": total_v4,
                "total_v6": total_v6,
                "up": total_up,
                "up_v4": total_up_v4,
                "up_v6": total_up_v6,
                "down": total_down,
                "elapsed_seconds": round(elapsed, 2),
                "results": export_data
            }

            with open(args.json_file, 'w', encoding='utf-8') as f:
                json.dump(output, f, indent=2)

            print(f"{GREEN if use_color else ''}[OK] JSON results saved to: {args.json_file}{NC if use_color else ''}")
        except Exception as e:
            print(f"{RED if use_color else ''}[ERR] Failed to save JSON: {e}{NC if use_color else ''}")


if __name__ == "__main__":
    main()
