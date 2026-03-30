"""
Author: Ramtin Loghmani
Assignment: #2
Description: Port Scanner — A tool that scans a target machine for open network ports
"""

# Import the required modules
import socket
import threading
import sqlite3
import os
import platform
import datetime

# Print Python version and OS name
print(f"Python Version: {platform.python_version()}")
print(f"Operating System: {os.name}")

# Dictionary that maps common port numbers to their corresponding network service names
common_ports = {
    21: "FTP",
    22: "SSH",
    23: "Telnet",
    25: "SMTP",
    53: "DNS",
    80: "HTTP",
    110: "POP3",
    143: "IMAP",
    443: "HTTPS",
    3306: "MySQL",
    3389: "RDP",
    8080: "HTTP-Alt"
}


class NetworkTool:
    """Parent class for network-related tools."""

    def __init__(self, target):
        self.__target = target

    # Q3: What is the benefit of using @property and @target.setter?
    # Using @property and @target.setter allows us to control how the private attribute
    # self.__target is accessed and modified. This provides encapsulation, meaning we can
    # add validation logic (like rejecting empty strings) without changing how the attribute
    # is used externally. Direct access to self.__target would bypass any validation checks.
    @property
    def target(self):
        return self.__target

    @target.setter
    def target(self, value):
        if value == "":
            print("Error: Target cannot be empty")
        else:
            self.__target = value

    def __del__(self):
        print("NetworkTool instance destroyed")


# Q1: How does PortScanner reuse code from NetworkTool?
# PortScanner inherits from NetworkTool, which means it reuses the constructor that stores
# the target IP as a private attribute, the @property getter and @target.setter for
# validated access, and the destructor. For example, when PortScanner calls
# super().__init__(target), it reuses the parent's constructor to store the target IP
# without rewriting that logic.
class PortScanner(NetworkTool):
    """Child class that performs port scanning, inheriting from NetworkTool."""

    def __init__(self, target):
        super().__init__(target)
        self.scan_results = []
        self.lock = threading.Lock()

    def __del__(self):
        print("PortScanner instance destroyed")
        super().__del__()

    def scan_port(self, port):
        """Scan a single port on the target machine."""
        # Q4: What would happen without try-except here?
        # Without try-except, if the target machine is unreachable or a network error
        # occurs, Python would raise a socket.error exception that is not caught. This
        # would crash the program immediately and stop all remaining port scans. The
        # try-except block allows us to handle the error gracefully and continue scanning
        # other ports.
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(1)
            result = sock.connect_ex((self.target, port))
            if result == 0:
                status = "Open"
            else:
                status = "Closed"
            service_name = common_ports.get(port, "Unknown")
            self.lock.acquire()
            self.scan_results.append((port, status, service_name))
            self.lock.release()
        except socket.error as e:
            print(f"Error scanning port {port}: {e}")
        finally:
            sock.close()

    def get_open_ports(self):
        """Return only the open ports using a list comprehension."""
        return [result for result in self.scan_results if result[1] == "Open"]

    # Q2: Why do we use threading instead of scanning one port at a time?
    # Threading allows us to scan multiple ports concurrently instead of waiting for each
    # port to finish before starting the next one. Each port scan can take up to 1 second
    # (the timeout value), so scanning 1024 ports sequentially would take up to 1024
    # seconds (~17 minutes). With threading, all ports are scanned in parallel, reducing
    # the total scan time dramatically to just a few seconds.
    def scan_range(self, start_port, end_port):
        """Scan a range of ports using threads."""
        threads = []
        for port in range(start_port, end_port + 1):
            t = threading.Thread(target=self.scan_port, args=(port,))
            threads.append(t)
        for t in threads:
            t.start()
        for t in threads:
            t.join()


def save_results(target, results):
    """Save scan results to a SQLite database."""
    try:
        conn = sqlite3.connect("scan_history.db")
        cursor = conn.cursor()
        cursor.execute("""CREATE TABLE IF NOT EXISTS scans (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            target TEXT,
            port INTEGER,
            status TEXT,
            service TEXT,
            scan_date TEXT
        )""")
        for result in results:
            cursor.execute(
                "INSERT INTO scans (target, port, status, service, scan_date) VALUES (?, ?, ?, ?, ?)",
                (target, result[0], result[1], result[2], str(datetime.datetime.now()))
            )
        conn.commit()
        conn.close()
    except sqlite3.Error as e:
        print(f"Database error: {e}")


def load_past_scans():
    """Load and display past scan results from the database."""
    try:
        conn = sqlite3.connect("scan_history.db")
        cursor = conn.cursor()
        cursor.execute("SELECT * FROM scans")
        rows = cursor.fetchall()
        for row in rows:
            print(f"[{row[5]}] {row[1]} : Port {row[2]} ({row[4]}) - {row[3]}")
        conn.close()
    except (sqlite3.Error, sqlite3.OperationalError):
        print("No past scans found.")


# ============================================================
# MAIN PROGRAM
# ============================================================
if __name__ == "__main__":
    target = input("Enter target IP address (default 127.0.0.1): ")
    if target == "":
        target = "127.0.0.1"

    try:
        start_port = int(input("Enter start port (1-1024): "))
        end_port = int(input("Enter end port (1-1024): "))
    except ValueError:
        print("Invalid input. Please enter a valid integer.")
        exit()

    if start_port < 1 or start_port > 1024 or end_port < 1 or end_port > 1024:
        print("Port must be between 1 and 1024.")
        exit()

    if end_port < start_port:
        print("End port must be greater than or equal to start port.")
        exit()

    scanner = PortScanner(target)
    print(f"Scanning {target} from port {start_port} to {end_port}...")
    scanner.scan_range(start_port, end_port)

    open_ports = scanner.get_open_ports()
    print(f"\n--- Scan Results for {target} ---")
    for port_info in open_ports:
        print(f"Port {port_info[0]}: Open ({port_info[2]})")
    print("------")
    print(f"Total open ports found: {len(open_ports)}")

    save_results(target, scanner.scan_results)

    history_choice = input("Would you like to see past scan history? (yes/no): ")
    if history_choice.lower() == "yes":
        load_past_scans()

# Q5: New Feature Proposal
# I would add a Port Risk Classifier feature that categorizes each open port by security
# risk level (High, Medium, or Low). Ports like 21 (FTP), 22 (SSH), 23 (Telnet), and
# 3389 (RDP) would be classified as High risk, while ports like 25, 110, 143, and 3306
# would be Medium risk, and all others would be Low risk. This could be implemented using
# a list comprehension with a nested if-statement:
# risk_report = [(p, s, "HIGH" if p in [21,22,23,3389] else "MEDIUM" if p in [25,110,143,3306] else "LOW") for p, s, svc in open_ports]
# Diagram: See diagram_101595929.png in the repository root
