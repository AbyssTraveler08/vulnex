# Vulnex discovery fix

This build improves local network discovery for Wi-Fi/Ethernet LANs.

## Why Nmap sometimes finds only the router and the Vulnex machine

A simple `nmap -sn` can miss LAN clients when:

- Nmap is running without raw-packet privileges on macOS/Linux.
- The client firewall ignores ICMP/TCP discovery probes.
- The Wi-Fi access point has client/AP isolation enabled.
- Devices are on another VLAN/subnet.
- The OS has not populated its ARP/neighbor cache.

## What changed

Vulnex now:

1. Tries Nmap ARP discovery (`-PR`).
2. Falls back to ICMP/TCP discovery probes.
3. Merges the operating system ARP cache with Nmap results.
4. Deduplicates devices by IP.
5. Preserves MAC/hostname/vendor information whenever available.

This remains limited to private/loopback/link-local networks selected by the application.

## Mac verification

Run these commands on the same machine as Vulnex:

```bash
which nmap
nmap --version
sudo nmap -sn -PR 192.168.0.0/24
arp -a
```

If the `sudo nmap` command discovers many more devices than the Vulnex button, the issue is macOS raw-packet privileges. If even `sudo nmap` sees only the router and this Mac, check the router's **AP/client isolation**, VLAN configuration, and whether the other devices are actually on `192.168.0.0/24`.

Vulnex does not automatically run itself with `sudo` because that would be a poor security/permissions model and can cause the Streamlit/Python environment to become owned by root.
