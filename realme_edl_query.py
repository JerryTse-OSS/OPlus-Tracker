#!/usr/bin/env python3
"""
Query official EDL packages for Realme
Designed by Jerry Tse
"""

import sys
import re
import argparse
import requests
import os
from concurrent.futures import ThreadPoolExecutor

def check_url(url):
    try:
        resp = requests.head(url, timeout=2, allow_redirects=True)
        if resp.status_code == 200:
            print("Fetch Info:")
            print(f"• Link: {url}")
            os._exit(0) 
    except:
        pass

def main():
    parser = argparse.ArgumentParser(
        description='Realme EDL Query Tool',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Example:
  python3 %(prog)s "RMX3888_16.0.3.500(CN01)" CN 202601241320
"""
    )
    parser.add_argument('version_name', metavar='VERSION_NAME',
                        help='Version name (e.g., RMX3888_16.0.3.500(CN01))')
    parser.add_argument('region', metavar='REGION',
                        help='Region code (e.g., CN, EU, IN)')
    parser.add_argument('date', metavar='DATE',
                        help='12-character date prefix (e.g., 202601241320)')
    args = parser.parse_args()

    VERSION_NAME = args.version_name
    REGION = args.region.upper()
    DATE_PREFIX = args.date

    if len(DATE_PREFIX) != 12:
        parser.error(f"Date length is {len(DATE_PREFIX)}, expected 12 characters.")

    from config import REALME_CONFIG

    if REGION in ("EU", "EUEX", "EEA", "TR"):
        conf = REALME_CONFIG["gdpr"]
    elif REGION in ("CN", "CH"):
        conf = REALME_CONFIG["domestic"]
    else:
        conf = REALME_CONFIG["export"]
    
    BUCKET, SERVER = conf["bucket"], conf["server"]

    VERSION_CLEAN = re.sub(r"^RMX\d+_", "", VERSION_NAME).replace("(", "").replace(")", "")
    MODEL = VERSION_NAME.split("_")[0]
    BASE_URL = f"https://{SERVER}/sw/{MODEL}{BUCKET}_11_{VERSION_CLEAN}_{DATE_PREFIX}"

    print(f"Querying for {VERSION_NAME}\n")

    executor = ThreadPoolExecutor(max_workers=100)

    try:
        for i in range(10000):
            url = f"{BASE_URL}{i:04d}.zip"
            executor.submit(check_url, url)
            
        executor.shutdown(wait=True)
    except KeyboardInterrupt:
        os._exit(1)

    print("Fetch Info:")
    print("• Link: Not Found")

if __name__ == "__main__":
    main()
