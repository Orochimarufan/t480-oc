#!/usr/bin/env python3
# Interactive OpenCore config.plist Kext updater

from argparse import ArgumentParser
from pathlib import Path

from oclib import *

# Arguments
p = ArgumentParser()
p.add_argument("config_plist", type=Path, default=Path("OC/config.plist"), help="OpenCore config.plist path [%(default)s]", nargs="?")
args = p.parse_args()

# Init
kext_dir = args.config_plist.parent / "Kexts"

print("Interactive OpenCore config.plist Kext updater")
print(f"Updating {args.config_plist}")
print(f"Looking for new or deleted Kexts in {kext_dir}")
print()

config: OcConfig = read_plist(args.config_plist)
config_kexts: list[KextEntry] = config["Kernel"]["Add"]

bundles_kept: set[str] = set()
bundles_removed: set[str] = set()
bundles_new: set[str] = set()

new_kexts: list[KextEntry] = []

# Check for deleted Kexts
for kext in config_kexts:
    bundle_path = kext["BundlePath"]
    info_path = kext_dir / bundle_path / kext["PlistPath"]
    if not info_path.exists():
        if yesno(f"Couldn't find Kext '{bundle_path}'. Remove it from config.plist?"):
            bundles_removed.add(bundle_path)
            continue
    new_kexts.append(kext)
    bundles_kept.add(bundle_path)

# Check for new Kexts
for path in kext_dir.rglob("*.kext/Contents/Info.plist"):
    bundle_path = str(path.parent.parent.relative_to(kext_dir))
    if bundle_path not in bundles_kept:
        bundle_info: BundleInfo = read_plist(path)
        if yesno(f"Found new Kext '{bundle_info['CFBundleName']}' v{bundle_info['CFBundleVersion']} at '{bundle_path}'. Add it to config.plist?"):
            new_kexts.append({
                "Comment": f"{bundle_path}: {bundle_info['CFBundleName']}",
                "Enabled": True,
                "BundlePath": bundle_path,
                "PlistPath": "Contents/Info.plist",
                "ExecutablePath": f"Contents/MacOS/{bundle_info['CFBundleExecutable']}",
                "Arch": "Any",
                "MinKernel": "",
                "MaxKernel": "",
            })
            bundles_new.add(bundle_path)

# Save config.plist
if not bundles_removed and not bundles_new:
    print("No changes were made.")

else:
    print()
    print("Change Summary:")
    if bundles_removed:
        print("  Removed Kexts:")
        for bundle in bundles_removed:
            print(f"    - {bundle}")
    if bundles_new:
        print("  New Kexts:")
        for bundle in bundles_new:
            print(f"    - {bundle}")

    print()
    if yesno("Save changes?"):
        config["Kernel"]["Add"] = new_kexts
        save_plist(args.config_plist, config)
