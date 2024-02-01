import subprocess
import requests
import argparse
import re
from xss import start_xss_scan
from sqli import start_sqli_scan
from concurrent.futures import ThreadPoolExecutor
from threading import Lock
from colorama import Fore

print(Fore.LIGHTBLUE_EX + """
   _____            __               __
  / ___/___  ____  / /_(_)___  ___  / /
  \__ \/ _ \/ __ \/ __/ / __ \/ _ \/ / 
 ___/ /  __/ / / / /_/ / / / /  __/ /  
/____/\___/_/ /_/\__/_/_/ /_/\___/_/   
                                   
   #XSS/SQL Vulnerability Scanner                       
               """ + Fore.WHITE)

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="XSS/SQL Vulnerability Scanner")
    parser.add_argument("-u", "--url", required=True, help="Target URL")
    parser.add_argument("--xss", action="store_true", help="Scan only for XSS vulnerabilities")
    parser.add_argument("--sql", action="store_true", help="Scan only for SQL vulnerabilities")
    args = parser.parse_args()

    if args.xss:
        start_xss_scan(args.url)
    elif args.sql:
        start_sqli_scan(args.url)
    else:
        # Run both scanners if no specific scan flags are mentioned
        start_xss_scan(args.url)
        start_sqli_scan(args.url)
