#!/usr/bin/env python3
# Designed by Jerry Tse
import sys
import re
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
    if len(sys.argv) != 4:
        print("Usage: python3 script.py <VERSION_NAME> <REGION> <DATE>")
        print("Example: ~/venv/bin/python realme_edl_query.py \"RMX3888_16.0.3.500(CN01)\" CN 202601241320")
        return

    VERSION_NAME = sys.argv[1]
    REGION = sys.argv[2].upper()
    DATE_PREFIX = sys.argv[3]
    
    if len(DATE_PREFIX) != 12:
        print(f"\n❌ Error: Argument 4 (Date) length is {len(DATE_PREFIX)}, expected 12 characters.")
        sys.exit(1)

    if REGION in ("EU", "EUEX", "EEA", "TR"):
        BUCKET, SERVER = "GDPR", "rms01.realme.net"
    elif REGION in ("CN", "CH"):
        BUCKET, SERVER = "domestic", "rms11.realme.net"
    else:
        BUCKET, SERVER = "export", "rms01.realme.net"

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
