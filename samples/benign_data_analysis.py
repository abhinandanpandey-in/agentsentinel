#!/usr/bin/env python3
"""A benign 'agent tool' that only touches files in its own working dir."""
import os

with open("./workdir_output.txt", "w") as f:
    f.write("analysis complete\n")

print("Benign tool ran successfully, wrote ./workdir_output.txt")
