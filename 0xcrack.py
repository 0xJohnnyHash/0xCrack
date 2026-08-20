#!/usr/bin/env python3
"""
0xCrack — console launcher.

    python 0xcrack.py -T hashes.txt -S wordlist.txt -oG report.html

(Once installed with `pip install -e .` you can just run `0xcrack ...`.)
"""
from oxcrack.cli import main

if __name__ == "__main__":
    main()
