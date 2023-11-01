#!/usr/bin/env python3

import json
import os
import sys
from argparse import ArgumentParser
from pathlib import Path
from urllib.request import urlopen

from oclib import *
import packaging.version

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

# Kext updates
kext_github_map: dict[str, str]|None = None

try:
    from cachier import cachier
except ImportError:
    from functools import cache
    print("\033[31mNote: Python cachier library not found. May run into GitHub API limit checking for Kext updates\033[0m", file=sys.stderr)
else:
    from datetime import timedelta
    from tempfile import gettempdir
    cache = cachier(stale_after=timedelta(hours=2), cache_dir=Path(gettempdir()) / "proper-list")

@cache
def get_latest_github_release(github_repo: str) -> dict:
    with urlopen(f"https://api.github.com/repos/{github_repo}/releases/latest") as f:
        return json.load(f)

def get_latest_release(github_repo: str) -> str:
    return (
        get_latest_github_release(github_repo)
        ["tag_name"]
        .lstrip('v'))

def format_latest_release(kext_info: BundleInfo) -> str:
    global kext_github_map
    if kext_github_map is None:
        with (Path(__file__).parent / "kext-github.json").open() as f:
            kext_github_map = json.load(f)
    github_repo = kext_github_map.get(kext_info["CFBundleName"])
    if github_repo is not None:
        latest = get_latest_release(github_repo)
        color = 0
        try:
            cur_ver = packaging.version.parse(kext_info["CFBundleVersion"])
            latest_ver = packaging.version.parse(latest)
            color = None
            if cur_ver < latest_ver:
                color = 31
            elif cur_ver > latest_ver:
                color = 34
            else:
                color = 32
        except:
            pass
        # color must be outside OSC8 for tabulate 0.9 to work
        return f"\033[{color}m\033]8;;https://github.com/{github_repo}\033\\{latest}\033]8;;\033\\\033[0m"
    return ""


if __name__ == "__main__":
    # Arguments
    p = ArgumentParser()
    p.add_argument("config_plist", type=Path, default=Path("OC/config.plist"), help="OpenCore config.plist path [%(default)s]", nargs="?")
    p.add_argument("kind", choices=("kexts", "ssdts"), default="kexts", nargs="?", help="Kind of data to print (%(choices)s)")
    args = p.parse_args()

    config: OcConfig = read_plist(args.config_plist)

    if args.kind == "kexts":
        config_kexts: list[KextEntry] = config["Kernel"]["Add"]

        # Load Kext info
        kext_dir = args.config_plist.parent / "Kexts"
        kexts: list[tuple[int, KextEntry, BundleInfo]] = [
            (ix, kext, read_plist(kext_dir / kext["BundlePath"] / kext["PlistPath"]))
                for ix, kext in enumerate(config_kexts)]

        # Format table
        print_table([("#", "✓", "Name", "Version", "Latest", "Kernel", "Path"), *(
            (ix, '✓' if kext["Enabled"] else '', info["CFBundleName"], info["CFBundleVersion"], format_latest_release(info), format_kernel(kext), kext["BundlePath"])
            for ix, kext, info in kexts)])

    elif args.kind == "ssdts":
        # List SSDTs
        print_table([("#", "✓", "Comment", "Path"), *(
            (ix, '✓' if ssdt["Enabled"] else '', ssdt["Comment"], ssdt["Path"])
            for ix, ssdt in enumerate(config["ACPI"]["Add"]))])

