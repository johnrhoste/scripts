# Version 1.1 -- see changelog in README for details.

import re
import glob
from collections import Counter

# Configuration
LOG_FILES_MASK = "/var/log/auth.log*"  # Catches auth.log and auth.log.1
FAILED_THRESHOLD = 5

# Optimized non-greedy regex pattern
FAILED_LOG_PATTERN = r"Failed password for .*? from (\S+)"

def analyze_brute_force(log_mask):
    ip_counts = Counter()  # Memory-efficient tracking
    files_processed = 0
    
    # glob allows processing current and recently rotated logs
    for log_path in glob.glob(log_mask):
        try:
            # Note: If handling .gz files, you'd use the 'gzip' module here
            # A .gz file is a compressed archive created using the GNU Zip (gzip)
            # algorithm. Commonly found on Unix and Linux systems,
            # it is used to reduce file sizes for easier storage and transfer.
            with open(log_path, "r", errors="ignore") as file:
                files_processed += 1
                for line in file:
                    match = re.search(FAILED_LOG_PATTERN, line)
                    if match:
                        ip_counts[match.group(1)] += 1
        except FileNotFoundError:
            continue
        except PermissionError:
            print(f"[-] Error: Permission denied reading {log_path}. Try running with sudo.")
            return

    if files_processed == 0:
        print(f"[-] Error: No log files found matching {log_mask}")
        return
        
    print(f"--- SOC Alert: IP Brute Force Analysis ---")
    flagged_any = False
    
    # Print results sorted by highest offender first
    for ip, count in ip_counts.most_common():
        if count >= FAILED_THRESHOLD:
            print(f"[!] CRITICAL: IP {ip} exceeded threshold with {count} failed attempts.")
            flagged_any = True
            
    if not flagged_any:
        print("[+] Scan complete: No suspicious brute-force activity detected.")

if __name__ == "__main__":
    analyze_brute_force(LOG_FILES_MASK)
