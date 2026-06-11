import re
from collections import Counter

# Configuration
LOG_FILE_PATH = "auth.log"
FAILED_THRESHOLD = 5

# Regex pattern matching failed password attempts
# Example log line: "Jun  6 08:12:00 server sshd[1234]:
# Failed password for invalid user admin from 192.168.1.105 port 54321 ssh2"
FAILED_LOG_PATTERN = r"Failed password for .* from (\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})"

def analyze_brute_force(log_path):
    failed_ips = []
    
    try:
        with open(log_path, "r") as file:
            for line in file:
                match = re.search(FAILED_LOG_PATTERN, line)
                if match:
                    failed_ips.append(match.group(1))
                    
        # Aggregate the counts per IP
        ip_counts = Counter(failed_ips)
        
        print("--- SOC Alert: IP Brute Force Analysis ---")
        flagged_any = False
        for ip, count in ip_counts.items():
            if count >= FAILED_THRESHOLD:
                print(f"[!] CRITICAL: IP {ip} exceeded threshold with {count} failed attempts.")
                flagged_any = True
                
        if not flagged_any:
            print("[+] Scan complete: No suspicious brute-force activity detected.")
            
    except FileNotFoundError:
        print(f"[-] Error: Log file not found at {log_path}")

if __name__ == "__main__":
    analyze_brute_force(LOG_FILE_PATH)
