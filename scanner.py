import nmap


class NetworkScanner:
    DEFAULT_PORTS = [
        21, 22, 23, 25, 53, 80, 110, 135, 139, 143, 443,
        445, 1433, 1521, 3306, 3389, 5432, 5900, 6379,
        8080, 8443, 27017,
    ]

    def __init__(self):
        self.nm = nmap.PortScanner()

    def scan_network(self, target, ports=None):
        try:
            selected_ports = ports or self.DEFAULT_PORTS
            ports_arg = ",".join(str(port) for port in selected_ports)
            self.nm.scan(hosts=target, ports=ports_arg, arguments="-sT -Pn -n")

            scan_results = []

            for host in self.nm.all_hosts():
                vendor_data = self.nm[host].get("vendor", {})
                tcp_data = self.nm[host].get("tcp", {})
                summary = {"requested": len(selected_ports), "open": 0, "closed": 0, "filtered": 0, "other": 0}

                device_info = {
                    "ip": host,
                    "status": self.nm[host].state(),
                    "vendor": vendor_data,
                    "ports": [],
                    "scanned_ports": list(selected_ports),
                    "port_scan_summary": summary,
                }

                for port in selected_ports:
                    port_data = tcp_data.get(port, {})
                    state = port_data.get("state", "other")

                    if state == "open":
                        summary["open"] += 1
                        device_info["ports"].append(
                            {
                                "port": port,
                                "name": port_data.get("name", ""),
                                "product": port_data.get("product", ""),
                                "version": port_data.get("version", ""),
                            }
                        )
                    elif state == "closed":
                        summary["closed"] += 1
                    elif state == "filtered":
                        summary["filtered"] += 1
                    else:
                        summary["other"] += 1

                scan_results.append(device_info)

            return scan_results
        except Exception as exc:
            print(f"Scanner error: {exc}")
            return []


if __name__ == "__main__":
    scanner = NetworkScanner()
    print("Starting scan...")
    results = scanner.scan_network("127.0.0.1")
    for res in results:
        print(f"IP: {res['ip']}, Vendor: {res['vendor']}")
