import ipaddress
import os
import re
import socket
import subprocess
import sys
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime

netwatch_code = """
███╗   ██╗███████╗████████╗██╗    ██╗ █████╗ ████████╗ ██████╗██╗  ██╗
████╗  ██║██╔════╝╚══██╔══╝██║    ██║██╔══██╗╚══██╔══╝██╔════╝██║  ██║
██╔██╗ ██║█████╗     ██║   ██║ █╗ ██║███████║   ██║   ██║     ███████║
██║╚██╗██║██╔══╝     ██║   ██║███╗██║██╔══██║   ██║   ██║     ██╔══██║
██║ ╚████║███████╗   ██║   ╚███╔███╔╝██║  ██║   ██║   ╚██████╗██║  ██║
╚═╝  ╚═══╝╚══════╝   ╚═╝    ╚══╝╚══╝ ╚═╝  ╚═╝   ╚═╝    ╚═════╝╚═╝  ╚═╝
                    LOCAL NETWORK MONITORING TOOL
"""

def list_network_interfaces():
    """Return list of available interfaces with their IPv4 and network mask."""
    try:
        output = subprocess.check_output(["ip", "-4", "addr", "show"], text=True, stderr=subprocess.DEVNULL)
    except (subprocess.CalledProcessError, FileNotFoundError):
        return []

    interfaces = []
    current = None
    for line in output.splitlines():
        line = line.rstrip()
        match = re.match(r"^\d+: ([^:]+):", line)
        if match:
            current = {"name": match.group(1), "ip": None, "prefix": None}
            interfaces.append(current)
            continue
        if current is None:
            continue
        inet_match = re.search(r"inet (\d+\.\d+\.\d+\.\d+)/(\d+)", line)
        if inet_match:
            current["ip"] = inet_match.group(1)
            current["prefix"] = int(inet_match.group(2))

    return [iface for iface in interfaces if iface["ip"] and iface["name"] != "lo"]


def select_interface(interface_name=None):
    """Chooses the network interface to monitor."""
    interfaces = list_network_interfaces()
    if not interfaces:
        raise RuntimeError("There is no IPv4 interface available.")

    if interface_name:
        for iface in interfaces:
            if iface["name"] == interface_name:
                return iface
        raise ValueError(f"Interface {interface_name} is not available.")

    if len(interfaces) == 1:
        return interfaces[0]

    print("Available network interfaces:")
    for index, iface in enumerate(interfaces, start=1):
        print(f"  {index}. {iface['name']} -> {iface['ip']}/{iface['prefix']}")

    while True:
        selection = input("Choose interface number: ").strip()
        if not selection.isdigit():
            print("Please enter a valid interface number.")
            continue
        selection = int(selection)
        if 1 <= selection <= len(interfaces):
            return interfaces[selection - 1]
        print("Invalid number. Please try again.")


def get_subnet_cidr(interface):
    """Return the IPv4Network object for the selected interface."""
    if not interface or not interface.get("ip") or interface.get("prefix") is None:
        raise ValueError("Incomplete network interface.")
    return ipaddress.IPv4Network(f"{interface['ip']}/{interface['prefix']}", strict=False)


def ping_host(ip, timeout=1):
    """Sends a single ping to the IP address."""
    try:
        subprocess.run(["ping", "-c", "1", "-W", str(timeout), ip], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, check=True)
        return True
    except subprocess.CalledProcessError:
        return False
    except FileNotFoundError:
        return False


def read_arp_table():
    """Reads ARP entries from /proc/net/arp."""
    result = {}
    try:
        with open("/proc/net/arp", "r", encoding="utf-8") as arp_file:
            next(arp_file)
            for line in arp_file:
                parts = line.split()
                if len(parts) >= 4:
                    ip_address = parts[0]
                    mac = parts[3]
                    result[ip_address] = mac
    except FileNotFoundError:
        pass
    return result


def scan_network(interface, timeout=1, max_workers=50):
    """Scan the local network and return a list of active hosts."""
    network = get_subnet_cidr(interface)
    hosts = list(network.hosts())
    if not hosts:
        return []

    arp_entries = read_arp_table()
    discovered = []

    def check_host(ip):
        ip_str = str(ip)
        reachable = ping_host(ip_str, timeout=timeout)
        mac = arp_entries.get(ip_str, "--:--:--:--:--:--")
        hostname = ip_str
        try:
            hostname = socket.gethostbyaddr(ip_str)[0]
        except (socket.herror, socket.gaierror, OSError):
            pass
        return {
            "ip": ip_str,
            "reachable": reachable,
            "mac": mac,
            "hostname": hostname,
        }

    with ThreadPoolExecutor(max_workers=max_workers) as executor:
        futures = {executor.submit(check_host, host): host for host in hosts}
        for future in as_completed(futures):
            host_info = future.result()
            if host_info["reachable"]:
                discovered.append(host_info)

    # Sort so that reachable (ONLINE) hosts appear first, then by IP address
    discovered.sort(key=lambda entry: (0 if entry["reachable"] else 1, tuple(map(int, entry["ip"].split(".")))))
    return discovered


def monitor_network(interface_name=None, interval=10, duration=None):
    """Monitors networking in realtime, refreshing the display every `interval` seconds."""
    interface = select_interface(interface_name)
    network = get_subnet_cidr(interface)
    start = datetime.now()
    seen_hosts = {}

    try:
        while True:
            discovered = scan_network(interface)
            timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
            os.system("clear")
            print(netwatch_code)
            print(f"Monitoring interface: {interface['name']} ({interface['ip']}/{interface['prefix']})")
            print(f"Network: {network} | Hosts: {network.num_addresses - 2}")
            print(f"Last updated: {timestamp}")
            print(f"Elapsed time: {(datetime.now() - start).total_seconds():.0f} seconds")
            print("\nIP\t\tMAC\t\t\tHOSTNAME")
            print("-" * 80)

            for host in discovered:
                print(f"{host['ip']:16}{host['mac']:20}{host['hostname']}")
                seen_hosts[host["ip"]] = {
                    "mac": host["mac"],
                    "hostname": host["hostname"],
                    "last_seen": timestamp,
                }

            if duration is not None and (datetime.now() - start).total_seconds() >= duration:
                print("\nEnd of monitoring duration reached.")
                break

            
            print("\nPress CTRL+C to stop monitoring. Refreshing in", interval, "seconds...")
            try:
                for _ in range(interval):
                    time.sleep(1)
            except KeyboardInterrupt:
                print("\nClosing monitor...")
                break
    except KeyboardInterrupt:
        print("\nMonitoring stopped.")


def main():
    print(netwatch_code)
    interface_name = None
    if len(sys.argv) > 1:
        interface_name = sys.argv[1]
    monitor_network(interface_name=interface_name, interval=10)


if __name__ == "__main__":
    main()
