import subprocess
import requests
import argparse
from concurrent.futures import ThreadPoolExecutor
from colorama import Fore
from threading import Lock

# Set to store processed URLs
processed_urls = set()

# Lock to ensure thread-safe access to the set
url_lock = Lock()

# Function to run ParamSpider and get the parameters
def run_paramspider(url):
    try:
        subprocess.run(['paramspider', '-d', url], check=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    except subprocess.CalledProcessError as e:
        print(f"Error running ParamSpider: {e}")

# Function to read payloads from xss_payloads.txt
def read_payloads():
    with open('xss_payloads.txt', 'r') as file:
        payloads = [line.strip() for line in file if line.strip()]
    return payloads

# Function to perform XSS scanning on a single URL with a payload
def xss_scan_single(url, payload):
    try:
        # Replace "FUZZ" with the payload in the URL
        url_with_payload = url.replace('FUZZ', payload)

        # Ensure the URL has a scheme (http or https)
        if not url_with_payload.startswith("http://") and not url_with_payload.startswith("https://"):
            url_with_payload = "http://" + url_with_payload
        
        # Extract the base URL without parameters
        base_url = url.split('?')[0]

        # Check if base URL has already been scanned
        with url_lock:
            if base_url in processed_urls:
                return None

            # Mark base URL as processed
            processed_urls.add(base_url)
        
        # Send a request and check for payload in the response
        print(Fore.LIGHTWHITE_EX + f"[+] Testing {url_with_payload}")
        response = requests.get(url_with_payload)
        
        # Print the vulnerable URLs in red
        if payload in response.text:
            print(Fore.RED + f"[+] Vulnerable: {url_with_payload}")
            return f"XSS Vulnerable: {url_with_payload}"
    except Exception as e:
        print(f"Error scanning {url}: {e}")
    return None

# Function to clear processed URLs set
def clear_processed_urls():
    with url_lock:
        processed_urls.clear()

# Function to perform XSS scanning on multiple URLs with payloads using threading
def xss_scan(url, payloads):
    results = []
    
    # Read parameters from params.txt
    params_file = f"results/{url}.txt"
    with open(params_file, 'r') as f:
        params_urls = f.read().splitlines()

    # Use ThreadPoolExecutor to parallelize the scanning process
    with ThreadPoolExecutor(max_workers=10) as executor:
        # List comprehension to generate a list of futures
        futures = [executor.submit(xss_scan_single, url, payload) for url in params_urls for payload in payloads]

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

# This function takes a URL as an argument and initiates the XSS scan
def start_xss_scan(url):
    # Clear processed URLs set before starting a new scan
    clear_processed_urls()

    # Run ParamSpider
    run_paramspider(url)

    # Read payloads from xss_payloads.txt
    payloads = read_payloads()

    # Perform XSS scan
    xss_scan(url, payloads)
