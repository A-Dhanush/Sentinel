import subprocess
import requests
import argparse
import re
from concurrent.futures import ThreadPoolExecutor
from threading import Lock
from colorama import Fore

DBMS_ERRORS = {
    "MySQL": (r"SQL syntax.*MySQL", r"Warning.*mysql_.*", r"valid MySQL result", r"MySqlClient\."),
    "PostgreSQL": (r"PostgreSQL.*ERROR", r"Warning.*\Wpg_.*", r"valid PostgreSQL result", r"Npgsql\."),
    "Microsoft SQL Server": (r"Driver.* SQL[\-\_\ ]*Server", r"OLE DB.* SQL Server", r"(\W|\A)SQL Server.*Driver", r"Warning.*mssql_.*", r"(\W|\A)SQL Server.*[0-9a-fA-F]{8}", r"(?s)Exception.*\WSystem\.Data\.SqlClient\.", r"(?s)Exception.*\WRoadhouse\.Cms\."),
    "Microsoft Access": (r"Microsoft Access Driver", r"JET Database Engine", r"Access Database Engine"),
    "Oracle": (r"\bORA-[0-9][0-9][0-9][0-9]", r"Oracle error", r"Oracle.*Driver", r"Warning.*\Woci_.*", r"Warning.*\Wora_.*"),
    "IBM DB2": (r"CLI Driver.*DB2", r"DB2 SQL error", r"\bdb2_\w+\("),
    "SQLite": (r"SQLite/JDBCDriver", r"SQLite.Exception", r"System.Data.SQLite.SQLiteException", r"Warning.*sqlite_.*", r"Warning.*SQLite3::", r"\[SQLITE_ERROR\]"),
    "Sybase": (r"(?i)Warning.*sybase.*", r"Sybase message", r"Sybase.*Server message.*"),
}

# Global set to store processed URLs
processed_urls = set()

# Lock to ensure thread-safe access to the set
url_lock = Lock()

# Function to run ParamSpider and get the parameters
def run_paramspider(url):
    try:
        subprocess.run(['paramspider', '-d', url], check=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    except subprocess.CalledProcessError as e:
        print(f"Error running ParamSpider: {e}")

# Function to read payloads from sql_payloads.txt
def read_payloads():
    with open('sql_payloads.txt', 'r') as file:
        payloads = [line.strip() for line in file if line.strip()]
    return payloads

# Function to detect DBMS for a given URL with payload
def detect_dbms(url_with_payload):
    try:
        # Send a request and check for payload in the response
        response = requests.get(url_with_payload, timeout=5)

        # Check for each DBMS error pattern
        for dbms, patterns in DBMS_ERRORS.items():
            if any(re.search(pattern, response.text) for pattern in patterns):
                return dbms, None

    except requests.RequestException as e:
        return None, f"Error testing {url_with_payload}: {e}"

    return None, None

# Function to perform SQL scanning on a single URL with a payload
def sql_scan_single(url, payloads):
    try:
        with url_lock:
            # Check if the URL has already been processed, if yes, skip
            if url in processed_urls:
                return None

            # Mark the URL as processed to avoid duplicate scans
            processed_urls.add(url)

        # Flag to keep track of whether a vulnerability has been found for this URL
        vulnerability_found = False

        # Iterate over payloads only if vulnerability hasn't been found
        for payload in payloads:
            if not vulnerability_found:
                # Replace "FUZZ" with the payload in the URL
                url_with_payload = url.replace('FUZZ', payload)

                # Send a request and check for payload in the response
                print(Fore.LIGHTWHITE_EX + f"[+] Testing {url_with_payload}")
                response = requests.get(url_with_payload, timeout=5)

                # Check for each DBMS error pattern
                for dbms, patterns in DBMS_ERRORS.items():
                    if any(re.search(pattern, response.text) for pattern in patterns):
                        print(Fore.RED + f"[+] Vulnerable: {url_with_payload}")

                        # Set the flag to True once a vulnerability is found
                        vulnerability_found = True

        # Return the result for saving in report.txt
        if vulnerability_found:
            return f"SQL Vulnerable: {url_with_payload}"
        else:
            return None

    except requests.RequestException as e:
        print(f"Error testing {url}: {e}")
        return None

# Function to clear processed URLs set
def clear_processed_urls():
    with url_lock:
        processed_urls.clear() 

# Function to perform SQL scanning on multiple URLs with payloads using threading
def sql_scan(url, payloads):
    results = []

    # Read parameters from params.txt
    params_file = f"results/{url}.txt"
    with open(params_file, 'r') as f:
        params_urls = f.read().splitlines()

    # Detect DBMS for the URL
    dbms_result, dbms_error = detect_dbms(params_urls[0])  # Detect DBMS for the first URL

    # Print DBMS result or error
    if dbms_result:
        print(Fore.LIGHTGREEN_EX + f"[+] DBMS Detected: {dbms_result}")

        # Write the detected DBMS to report.txt
        with open('report.txt', 'a') as report_file:
            report_file.write(f"DBMS Detected: {dbms_result}\n")
    elif dbms_error:
        print(Fore.LIGHTRED_EX + f"Error: {dbms_error}")

    # Use ThreadPoolExecutor to parallelize the scanning process
    with ThreadPoolExecutor(max_workers=10) as executor:
        # List comprehension to generate a list of futures
        futures = [executor.submit(sql_scan_single, param_url, payloads) for param_url in params_urls for payload in payloads]

        # Wait for all futures to complete
        for future in futures:
            result = future.result()
            if result:
                results.append(result)

    # Write results to report.txt
    with open('report.txt', 'a') as report_file:
        for result in results:
            report_file.write(result + '\n')
        print(Fore.LIGHTGREEN_EX + "[+] Results saved to report.txt")

# This function takes a URL as an argument and initiates the SQL scan
def start_sqli_scan(url):
    # Clear processed URLs set before starting a new scan
    clear_processed_urls()

    # Run ParamSpider
    run_paramspider(url)

    # Read payloads from sql_payloads.txt
    payloads = read_payloads()

    # Perform SQL scan
    sql_scan(url, payloads)
