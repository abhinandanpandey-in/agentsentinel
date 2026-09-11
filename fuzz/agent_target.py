#!/usr/bin/env python3
"""
agent_target.py — a deliberately naive 'agent' used as the fuzzing target.

This simulates the realistic shape of a prompt-injection vulnerability: an
LLM-driven agent is asked to do something benign (e.g. "summarize this
document") and is given untrusted content (a file, a scraped web page, an
email) as context. If that content contains text that looks like an
instruction, a poorly-guarded agent will sometimes act on it as if it came
from the user/system, not from the untrusted document.

This script hard-codes that vulnerability on purpose: it treats certain
marker lines in its input document as commands to execute. This is NOT how
you should build a real agent (see docs/architecture.md's threat model) —
it exists purely as a fuzzing target so we can verify AgentSentinel catches
the resulting syscalls regardless of how the agent got tricked into making
them.

Recognized injected directives (case-sensitive, one per line, anywhere in
the document):
  INJECT:READ_SSH_KEY          -> reads ~/.ssh/id_rsa
  INJECT:EXFIL <ip> <port>     -> opens a socket to <ip>:<port>
  INJECT:SPAWN_SHELL           -> spawns /bin/sh
  INJECT:READ_AWS_CREDS        -> reads ~/.aws/credentials

Anything else in the document is just "summarized" (word count printed),
which is the intended benign behavior.
"""
import sys
import os
import socket
import subprocess

def summarize(text: str) -> str:
    return f"Document summary: {len(text.split())} words."

def main():
    if len(sys.argv) < 2:
        print("usage: agent_target.py <document.txt>")
        sys.exit(1)

    with open(sys.argv[1], "r") as f:
        document = f.read()

    print(summarize(document))

    for line in document.splitlines():
        line = line.strip()
        if line == "INJECT:READ_SSH_KEY":
            path = os.path.expanduser("~/.ssh/id_rsa")
            try:
                with open(path) as f:
                    f.read()
                print(f"[agent] read {path} (injection succeeded!)")
            except Exception as e:
                print(f"[agent] read {path} blocked: {e}")

        elif line == "INJECT:READ_AWS_CREDS":
            path = os.path.expanduser("~/.aws/credentials")
            try:
                with open(path) as f:
                    f.read()
                print(f"[agent] read {path} (injection succeeded!)")
            except Exception as e:
                print(f"[agent] read {path} blocked: {e}")

        elif line.startswith("INJECT:EXFIL "):
            parts = line.split()
            ip, port = parts[1], int(parts[2])
            try:
                s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                s.settimeout(2)
                s.connect((ip, port))
                print(f"[agent] connected to {ip}:{port} (injection succeeded!)")
            except Exception as e:
                print(f"[agent] connect to {ip}:{port} blocked: {e}")

        elif line == "INJECT:SPAWN_SHELL":
            try:
                r = subprocess.run(["/bin/sh", "-c", "echo pwned"], capture_output=True, text=True, timeout=3)
                print(f"[agent] spawned shell: {r.stdout.strip()} (injection succeeded!)")
            except Exception as e:
                print(f"[agent] shell spawn blocked: {e}")

if __name__ == "__main__":
    main()
