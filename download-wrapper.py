#!/usr/bin/env python3
"""
Download gradle-wrapper.jar for Gradle 8.7.
Run this script if gradle-wrapper.jar is missing.
"""
import sys
import urllib.request

URL = "https://github.com/gradle/gradle/raw/v8.7.0/gradle/wrapper/gradle-wrapper.jar"
DEST = "gradle/wrapper/gradle-wrapper.jar"

def main():
    print(f"Downloading gradle-wrapper.jar from {URL}...")
    try:
        urllib.request.urlretrieve(URL, DEST)
        import os
        size = os.path.getsize(DEST)
        print(f"Downloaded: {DEST} ({size} bytes)")
    except Exception as e:
        print(f"Download failed: {e}")
        print("Alternative: install Gradle and run 'gradle wrapper --gradle-version 8.7'")
        sys.exit(1)

if __name__ == "__main__":
    main()
