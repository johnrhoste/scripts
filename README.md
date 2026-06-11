## r e a d ~ m e

This is collection of scripts that I've found to be useful for various practice labs & THM challenges. It's a combination of scripts that I've put together, as well as scripts found on the web.

## `LinEnum.sh`

Created by GitHub user @rebootuser (Owen Shearing). 

Open-source Bash script used to automate enumeration and for privilege escalation analysis. It searches for security misconfigurations, insecure permissions, outdated software, or other vulnerabilities that could provide leverage to obtain root access to a system.

Some things that it does (not comprehensive):

* Runs a thorough scan ( -t).
* Search for keywords in config / log files (-k).
* System & environment profiling.
* Checks if any directories are world-writable (which would allow path interception attacks).
* Checks for sudo misconfigurations (can users run commands like `sudo` without a password?).
* Searches for exposed private SSH keys (`id_rsa`, `id_dsa`).
* Lists active cron jobs, systemd timers, and if any scheduled task scripts are world-writable.
* Lists all running processes (`ps aux`) and evaluates file permissions to determine if low-priv users can modify a services executable.

## `js-analyze-auth-log.py`

A script that analyzes system log files (currently configured for `auth.log`) to detect potential SSH brute-forcing.

Here's how it works:

1. Parses Log Files with Regular Expressions
	* Uses RegEx to search for specific signatures left behind by failed SSH login attempts.

2. It Counts & Aggregates All Failures
	* Python's built-in `counter` automatically totals the number of times each unique IP address appears in a file. 

3. Determines if the set Threshold is Violated
	* The current script is configured with a threshold of 5 failed login attempts. 
	* The script compares the failure count of each IP against the set threshold.

4. Creates Alerts & Reports
	* If an IP exceeds the threshold, it prints an alert to the console, identifying the IP address and the number of failed attempts. This is intended to mimic a simple SOC alert.
	* If no IPs exceed the threshold, a report is printed showing that no suspicious activity was detected. 
