# NetReaper

NetReaper is a command-line tool for performing Man-in-the-Middle (MITM) attacks on a local network. It uses ARP spoofing to redirect traffic and includes a packet sniffer to capture unencrypted HTTP POST data, such as login credentials.

**DISCLAIMER:** This tool is intended for educational purposes in the fields of cybersecurity and network analysis ONLY. Using this tool on networks or devices you do not own or have explicit permission to test is illegal and unethical. The author is not responsible for any misuse of this software.

## How It Works

The tool places the attacker's machine in the middle of the communication between a target device and the network gateway. It achieves this by poisoning their ARP caches with crafted ARP response packets. Once the traffic is redirected, NetReaper sniffs the packets, filters for HTTP POST requests, and extracts potentially sensitive data from the payload.

## Features

-   **MITM Attack via ARP Spoofing:** Successfully redirects traffic between a target and the gateway.
-   **Packet Sniffing:** Captures traffic flowing through the attacker's machine.
-   **Credential Harvesting:** Specifically looks for keywords like `username`, `password`, etc., in HTTP POST requests and displays the data.
-   **Multi-threaded:** Runs the ARP spoofing loop and the packet sniffer simultaneously for a stable attack.
-   **Graceful Shutdown:** Upon termination (Ctrl+C), the script automatically sends corrective ARP packets to restore the network to its normal state, preventing connectivity loss for the target.

## Requirements

-   Python 3.7+
-   Python packages: `scapy`, `scapy-http`, `rich`
-   **Windows:** [Npcap](https://npcap.com/) must be installed with "WinPcap API-compatible Mode" enabled.
-   **Linux/macOS:** The script must be run with `sudo`.
-   **IP Forwarding** must be enabled on the attacker's machine.

## Setup & Usage

1.  **Clone the Repository**
    ```bash
    git clone https://github.com/Mystery-World3/netreaper.git
    cd netreaper
    ```

2.  **Enable IP Forwarding**
    This is a critical step to ensure the target device maintains internet connectivity during the attack.
    -   **Windows (in an Administrator PowerShell):**
        ```powershell
        Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters" -Name "IPEnableRouter" -Value 1
        ```
        *(A restart may be required for this to take effect.)*
    -   **Linux:**
        ```bash
        sudo sysctl -w net.ipv4.ip_forward=1
        ```
    -   **macOS:**
        ```bash
        sudo sysctl -w net.inet.ip.forwarding=1
        ```

3.  **Set Up Virtual Environment & Install Dependencies**
    ```bash
    # Create and activate venv
    python -m venv venv
    .\venv\Scripts\Activate  # On Windows
    # source venv/bin/activate # On macOS/Linux

    # Install requirements
    pip install scapy scapy-http rich
    ```
    *(You can also create a `requirements.txt` file for this.)*

4.  **Configure the Script**
    Open `netreaper.py` (or `main.py`) in a text editor and set the `target_ip` and `gateway_ip` variables to match your network configuration. You can use **LANspector** to find the correct IPs.

5.  **Run the Tool**
    The script must be run with elevated privileges to access raw sockets.
    -   **On Windows:** Open a new terminal **as Administrator**, navigate to the project directory, activate the venv, and run:
        ```powershell
        python netreaper.py
        ```
    -   **On Linux/macOS:**
        ```bash
        sudo python netreaper.py
        ```

6.  **Testing**
    While NetReaper is running, go to the **target device**, open a web browser, and navigate to a non-secure (HTTP) login page, such as [http://testphp.vulnweb.com/login.php](http://testphp.vulnweb.com/login.php). Enter any credentials and submit the form. The captured data will appear in the NetReaper terminal.

Press `Ctrl+C` in the terminal to stop the attack and automatically restore the network.

    ---

*Created by Mystery-World3*

