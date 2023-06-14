# OpenCore helpers

import io
import os
import plistlib
from base64 import b64encode
from typing import Sequence, TypedDict


# OC Config Schema
class OcConfigKernelCommon(TypedDict):
    Enabled: bool
    Comment: str
    Arch: str
    MinKernel: str
    MaxKernel: str

class KextEntry(OcConfigKernelCommon):
    BundlePath: str
    PlistPath: str
    ExecutablePath: str

class KextBlock(OcConfigKernelCommon):
    Identifier: str
    Strategy: str

class KextForce(KextEntry):
    Identifier: str

class KextPatch(OcConfigKernelCommon):
    Base: str
    Count: int
    Find: bytes
    Identifier: str
    Limit: int
    Mask: bytes
    Replace: bytes
    ReplaceMask: bytes

class OcConfigKernel(TypedDict):
    Add: list[KextEntry]
    Block: list[KextBlock]
    Emulate: dict
    Force: list[KextForce]
    Patch: list[KextPatch]
    Quirks: dict
    Scheme: dict

class OcConfig(TypedDict):
    ACPI: dict
    Booter: dict
    DeviceProperties: dict
    Kernel: OcConfigKernel
    Misc: dict
    NVRAM: dict
    PlatformInfo: dict
    UEFI: dict

# Bundle info plist (incomplete)
class BundleInfo(TypedDict):
    CFBundleName: str
    CFBundleIdentifier: str
    CFBundleVersion: str
    CFBundleExecutable: str


# Plists
class PlistWriter(plistlib._PlistWriter):
    # Don't split data into lines
    def write_bytes(self, data: bytes):
        self.file.write(self._indent_level * self.indent + b"<data>")
        self.file.write(b64encode(data))
        self.file.write(b"</data>\n")


def read_plist(path: str|os.PathLike) -> dict:
    with open(path, 'rb') as f:
        return plistlib.load(f)

def save_plist(path: str|os.PathLike, data: dict):
    tmp = os.fspath(path) + ".tmp"
    try:
        with open(tmp, 'wb') as f:
            PlistWriter(f, sort_keys=False).write(data)
    except:
        if os.path.exists(tmp):
            os.unlink(tmp)
        raise
    os.rename(tmp, path)

def dump_plist(data: dict) -> bytes:
    f = io.BytesIO()
    PlistWriter(f, sort_keys=False).write(data)
    return f.getvalue()

def get_nested_key(dict: dict, path: Sequence[str]):
    for segment in path:
        dict = dict[segment]
    return dict

def set_nested_key(dict: dict, path: Sequence[str], value):
    (*path, key) = path
    get_nested_key(dict, path)[key] = value


# Misc
def format_kernel(kext: OcConfigKernelCommon) -> str:
    arch = kext["Arch"]
    mink = kext["MinKernel"]
    maxk = kext["MaxKernel"]
    sx = []
    if arch != "Any":
        sx.append(arch)
    if mink or maxk:
        sx.append(f"{mink}-{maxk}")
    return " ".join(sx)

def yesno(prompt: str) -> bool:
    answer = None
    while answer not in {"y", "n", "yes", "no"}:
        print(prompt, " (y/n) ", end="")
        answer = input().strip().lower()
    return answer[0] == "y"
