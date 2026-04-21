#!/usr/bin/env python3
"""
Resolves dynamic download links (ColorOS 16+)
Designed by Jerry Tse
"""

import argparse
import base64
from datetime import datetime
from urllib.parse import parse_qs, urlparse

import requests


def android_request(
    url,
    method="GET",
    data=None,
    headers=None,
    allow_redirects=False,
    timeout=30,
    max_retries=3,
):

    base_headers = {
        "userId": "oplus-ota|00000001",
        "Range": "bytes=0-",
    }

    if headers:
        base_headers.update(headers)

    for attempt in range(max_retries):
        try:
            response = requests.get(
                url,
                headers=base_headers,
                timeout=timeout,
                allow_redirects=allow_redirects,
            )

            print_request_info(url, method, base_headers, data, response)

            return response

        except requests.exceptions.Timeout as e:
            if attempt < max_retries - 1:
                continue
            else:
                print(f"❌ Timeout")
                return None

        except requests.exceptions.ConnectionError as e:
            if attempt < max_retries - 1:
                continue
            else:
                print(f"❌ Error")
                return None

        except requests.exceptions.RequestException as e:
            if attempt < max_retries - 1:
                continue
            else:
                print(f"❌ Failed")
                return None

    return None


def print_request_info(url, method, headers, data, response):

    print("=" * 50)
    print("Copyright (C) 2025-2026 Jerry Tse")
    print("=" * 50)
    print(f"URL: {url}")

    if response.status_code in [301, 302, 303, 307, 308]:
        redirect_url = response.headers.get("Location")


def parse_expires_time(url):

    try:
        parsed_url = urlparse(url)
        query_params = parse_qs(parsed_url.query)

        if "Expires" in url:
            expires_str = query_params.get("Expires", [None])[0]
            if not expires_str:
                return None

        elif "x-oss-expires" in url:
            expires_str = query_params.get("x-oss-expires", [None])[0]
            if not expires_str:
                return None

        expires_timestamp = int(expires_str)
        expires_time = datetime.fromtimestamp(expires_timestamp)
        current_time = datetime.now()

        return {"timestamp": expires_timestamp, "expires_time": expires_time}
    except Exception as e:
        print(f"❌ Cannot get expires: {e}")
        return None


def get_redirect_url(url, market_name):
    extra_headers = {}
    if market_name:
        encoded = base64.b64encode(market_name.encode("utf-8")).decode("ascii")
        extra_headers["marketName"] = encoded

    response = android_request(
        url,
        "GET",
        headers=extra_headers,
        allow_redirects=False,
        timeout=10,
        max_retries=3,
    )

    if response and response.status_code == 302:
        redirect_url = response.headers.get("Location")

        time_info = parse_expires_time(redirect_url)

        print(f"\n✅ Success to resolve the URL:")
        print("=" * 50)
        print(redirect_url)
        print("=" * 50)

        if time_info:
            print(
                f"\n📅 Expire time(UTC+8): {time_info['expires_time'].strftime('%Y-%m-%d %H:%M:%S')}"
            )
        return redirect_url
    else:
        print("❌ Failed to resolve")
        return None


if __name__ == "__main__":
    parser = argparse.ArgumentParser(
        description="C16 URL Transfer Tool",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Example:
  python3 %(prog)s <URL> [market_name]
""",
    )
    parser.add_argument("url", help="URL to resolve")
    parser.add_argument(
        "market_name", nargs="?", default="", help="Optional market name"
    )
    args = parser.parse_args()

    url = args.url
    market_name = args.market_name

    redirect_url = get_redirect_url(url, market_name)

    if redirect_url:
        print("✅ DONE")
    else:
        print("❌ FAILED")
        exit(1)
