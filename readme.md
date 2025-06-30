# NetReaper v0.1

NetReaper is a command-line tool for performing Man-in-the-Middle (MITM) attacks on a local network using ARP spoofing. This project is intended for educational purposes in the field of cybersecurity and network analysis.

**DISCLAIMER:** This tool is for educational use only. Only use it on networks and devices that you own and have explicit permission to test. Unauthorized access to computer networks is illegal.

## How It Works

The tool performs ARP spoofing by sending crafted ARP response packets to a target machine and the network's gateway. This poisons their ARP caches, causing them to redirect their traffic through the attacker's machine, effectively placing the attacker in the middle of their communication.

## Features (v0.1)

-   **ARP Spoofing:** Successfully redirects traffic between a target and the gateway.
-   **Dynamic MAC Discovery:** Automatically finds the MAC addresses of the target and gateway.
-   **Graceful Exit:** Upon termination (Ctrl+C), the script automatically sends corrective ARP packets to restore the network to its normal state, preventing connectivity loss for the target.

## Requirements

-   Python 3.7+
-   Python packages: `scapy`, `rich`
-   **Windows:** [Npcap](https://npcap.com/) must be installed with "WinPcap API-compatible Mode" enabled.
-   **Linux/macOS:** The script must be run with `sudo`.
-   IP Forwarding must be enabled on the attacker's machine.

## Setup & Usage

1.  **Clone the repository:**
    ```bash
    git clone https://github.com/Mystery-World3/netreaper.git
    cd netreaper
    ```

2.  **Enable IP Forwarding:**
    -   **Windows (as Administrator):**
        ```powershell
        Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters" -Name "IPEnableRouter" -Value 1
        ```
    -   **Linux:**
        ```bash
        sudo sysctl -w net.ipv4.ip_forward=1
        ```
    -   **macOS:**
        ```bash
        sudo sysctl -w net.inet.ip.forwarding=1
        ```

3.  **Set up a virtual environment and install packages:**
    ```bash
    # Create and activate venv
    python -m venv venv
    .\venv\Scripts\Activate  # Windows
    # source venv/bin/activate # macOS/Linux

    # Install requirements
    pip install scapy rich
    ```

4.  **Configure the Script:**
    Open `netreaper.py` and set the `target_ip` and `gateway_ip` variables to match your network configuration.

5.  **Run the Spoofer:**
    The script must be run with elevated privileges.
    ```bash
    # On Windows, use a terminal that was "Run as administrator"
    python netreaper.py

    # On Linux/macOS
    sudo python netreaper.py
    ```
    Press `Ctrl+C` to stop the attack and restore the network.
