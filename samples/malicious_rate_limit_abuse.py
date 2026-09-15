#!/usr/bin/env python3
"""
Simulates a runaway/abusive agent behavior: rapidly opening files in a tight
loop, far beyond what any legitimate 'read this document' tool would ever
do. This could represent a data-scraping loop gone wrong, or a deliberate
attempt to exhaust file descriptors / scan a filesystem quickly.

This is intentionally aggressive: 2000 opens in a tight loop, which real
benign scripts (verified via strace against this policy's openat_per_sec)
never come close to. AgentSentinel's rate limiter should cut this off well
before it completes.
"""
import os

opened = 0
try:
    for i in range(2000):
        with open(__file__, "r") as f:
            f.read(1)
        opened += 1
except Exception as e:
    print(f"Loop stopped after {opened} opens: {e}")
else:
    print(f"Completed all {opened} opens (rate limit did not trigger!)")
