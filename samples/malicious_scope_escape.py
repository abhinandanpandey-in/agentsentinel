#!/usr/bin/env python3
"""
Simulates a 'declared read-only data analysis' tool whose generated code
(e.g. via prompt injection) spawns a shell — a classic scope-escape pattern
where the agent's actual behavior exceeds what it claimed to need.
"""
import subprocess

try:
    result = subprocess.run(["/bin/sh", "-c", "echo shell spawned"], capture_output=True, text=True, timeout=3)
    print(f"Shell spawn result: {result.stdout.strip()} (this should have been flagged/blocked!)")
except Exception as e:
    print(f"Shell spawn blocked or failed as expected: {e}")
