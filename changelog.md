## c h a n g e l o g

## `js-analyze-auth-log.py`

#### v1.1

Quick summary:
* `Counter` section was modified.
* Adjusted the regex logic.
* Added the `glob` module to catch all logs.
* Utilized the `ipaddress` module.

~

1. The initial version of the script read every failed IP into a massive list ( `failed_ips = []`) before counting it. If the `auth.log` is a few gigabytes of data, this could consume substantial amounts of RAM, potentially resulting in a crash.

	* **The fix:** `Counter` is continuously updated as the file is read, which keeps memory usage at a minimum no matter the size of the log file.

2. The original script forced the regex to scan all the way to the end of each line and backtrack, which slows down overall execution.

	* **The fix:** Make the match "non-greedy" by adding a `?`, or specifically match non-whitespace characters to help the regex engine skip straight to the IP address.

		> Note: In regular expressions (regex), non-greedy (also known as lazy or reluctant) means that a quantifier will match the shortest possible string that satisfies the pattern.

3. Account for Log Rotation — because Linux systems automatically rotate logs, a portion of a brute-force attack might be missed during a log rotation. The original script only looked at the active `auth.log`.

	* **The fix:** Python's built-in `glob` module can be used to find and parse both the current log and any rotated logs (like `auth.log.1`.

4. IPv6 addresses were ignored.

    * **The fix:** Implemented Python's `ipaddress` module.
