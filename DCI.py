from scapy.all import sniff, IP
from collections import defaultdict
import time
import os

# Configuration
REQUEST_LIMIT = 5  # Number of requests within the time window
TIME_WINDOW = 10  # Time window for request limit (in seconds)
TEMP_BLOCK_DURATION = 600  # Duration to temporarily block an IP (in seconds)
WARNINGS_LIMIT = 5  # Number of warnings before permanent block

# Track request timestamps, warnings, and blocks
request_timestamps = defaultdict(list)
ip_warnings = defaultdict(int)
temp_block_list = {}
perm_block_list = set()

def print_header():
    header = """
  ____     ____       _____ 
 |  _ \   / ___|     | ____|
 | | | | | |           | |
 | | | | | |           | | 
 | |_| | | |__     _  _| |__
 |____/   \____|   |______|
                 
    """
    print(header)
    # Adding names and roles below the header
    print("Team Members:")
    print("Niraj Zambre (Team Leader)")
    print("Omkar Dolhare (Cyber Security Specialist)")
    print("Ritesh Rajput (Support Engineer)\n")

def print_warning(ip, warning_count):
    print(f"\n[WARNING] IP {ip} has exceeded request limit. Warning {warning_count}.")
    print_ascii_warning()

def print_temporary_block(ip):
    print(f"\n[BLOCK] IP {ip} temporarily blocked for {TEMP_BLOCK_DURATION / 60} minutes.")
    print_ascii_block()

def print_permanent_block(ip):
    print(f"\n[BLOCK] IP {ip} permanently blocked after {WARNINGS_LIMIT} warnings.")
    print_ascii_block()

def print_ascii_warning():
    warning_art = """
     __      _______ _____  ____  _ 
     \\ \\    / / ____|  __ \\|  _ \\| |
      \\ \\  / / (___ | |__) | |_) | |
       \\ \\/ / \\___ \\|  _  /|  _ <| |
        \\  / ____) | | \\ \\| |_) | |
         \\/|_____/|_|  \\_\\____/|_|
    """
    print(warning_art)

def print_ascii_block():
    block_art = """
      ____  _            _    
     |  _ \\| |          | |   
     | |_) | | ___  _ __| | __
     |  _ <| |/ _ \\| '__| |/ /
     | |_) | | (_) | |  |   < 
     |____/|_|\\___/|_|  |_|\\_\\
    """
    print(block_art)

def should_block_ip(src_ip):
    # Check if IP is permanently blocked
    if src_ip in perm_block_list:
        return True

    # Check if IP is temporarily blocked
    if src_ip in temp_block_list:
        if time.time() < temp_block_list[src_ip]:
            return True
        else:
            del temp_block_list[src_ip]  # Remove expired temp block

    return False

def packet_callback(packet):
    if IP in packet:
        src_ip = packet[IP].src

        # Check if the IP is currently blocked
        if should_block_ip(src_ip):
            print(f"Blocked IP {src_ip} attempted to send a packet")
            return

        # Record the timestamp of the request
        current_time = time.time()
        request_timestamps[src_ip] = [ts for ts in request_timestamps[src_ip] if ts > current_time - TIME_WINDOW]
        request_timestamps[src_ip].append(current_time)

        # Check if the IP exceeds the request limit
        if len(request_timestamps[src_ip]) > REQUEST_LIMIT:
            ip_warnings[src_ip] += 1
            print_warning(src_ip, ip_warnings[src_ip])
            
            if ip_warnings[src_ip] >= WARNINGS_LIMIT:
                # Permanent block after exceeding warning limit
                perm_block_list.add(src_ip)
                print_permanent_block(src_ip)
            else:
                # Temporary block
                temp_block_list[src_ip] = current_time + TEMP_BLOCK_DURATION
                print_temporary_block(src_ip)

            # Clear request timestamps after action
            request_timestamps[src_ip] = []

def main():
    os.system('cls' if os.name == 'nt' else 'clear')  # Clear the terminal screen
    print_header()
    print("Starting packet capture...")
    sniff(prn=packet_callback, store=0)

if __name__ == "__main__":
    main()
