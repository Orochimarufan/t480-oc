#!/usr/bin/env python3

import sys, os
import plistlib

from argparse import ArgumentParser
from pathlib import Path

# Fall back to TSV
try:
    from tabulate import tabulate
except ImportError:
    def print_table(content):
        print("\033[31m[Note]: python tabulate library not found. Output is locked to TSV\033[0m", file=sys.stderr)
        print_tsv(content)
else:
    def print_table(content):
        print(tabulate(content, headers="firstrow", tablefmt="fancy_outline"))

def print_tsv(content):
    for row in content:
        print("\t".join(map(str, row)))

def read_plist(path: str):
    with open(path, 'rb') as f:
        return plistlib.load(f)

def format_kernel(kext):
    arch = kext["Arch"]
    mink = kext["MinKernel"]
    maxk = kext["MaxKernel"]
    sx = []
    if arch != "Any":
        sx.append(arch) 
    if mink or maxk:
        sx.append(f"{mink}-{maxk}")
    return " ".join(sx)

if __name__ == "__main__":
    # Arguments
    p = ArgumentParser()
    p.add_argument("config_plist", type=Path, default=Path("OC/config.plist"), help="OpenCore config.plist path [%(default)s]", nargs="?")
    p.add_argument("kind", choices=("kexts", "ssdts"), default="kexts", nargs="?", help="Kind of data to print (%(choices)s)")
    args = p.parse_args()

    config = read_plist(args.config_plist)

    if args.kind == "kexts":
        # Load Kext info
        kext_dir = args.config_plist.parent / "Kexts"
        kexts = [(ix, kext, read_plist(kext_dir / kext["BundlePath"] / kext["PlistPath"]))
            for ix, kext in enumerate(config["Kernel"]["Add"])]

        # Format table
        print_table([("#", "✓", "Name", "Version", "Kernel", "Path"), *(
            (ix, '✓' if kext["Enabled"] else '', info["CFBundleName"], info["CFBundleVersion"], format_kernel(kext), kext["BundlePath"])
            for ix, kext, info in kexts)])

    elif args.kind == "ssdts":
        # List SSDTs
        print_table([("#", "✓", "Comment", "Path"), *(
            (ix, '✓' if ssdt["Enabled"] else '', ssdt["Comment"], ssdt["Path"])
            for ix, ssdt in enumerate(config["ACPI"]["Add"]))])

