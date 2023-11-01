#!/usr/bin/env python3
# OpenCore installer script with Vault and SecureBoot support
# (c) 2022-2023 Taeyeon Mori

# ===================================================================
# Dependencies (See requirements.txt)

# Stdlib
from abc import ABC, abstractmethod
from argparse import ArgumentParser
from base64 import b32hexencode, b64decode
from functools import cached_property
from functools import partial as bind
from getpass import getpass
from hashlib import file_digest, sha256
from os import fspath, isatty
from pathlib import Path
from shutil import copy, rmtree, which
from subprocess import check_call
from sys import argv, stderr
from typing import (IO, Any, Callable, Literal, Optional, Sequence, TypeVar,
                    Union)

# Vault Crypto
from cryptography.hazmat.primitives.asymmetric.padding import PKCS1v15
from cryptography.hazmat.primitives.asymmetric.rsa import (
    RSAPrivateKey, RSAPublicKey, generate_private_key)
from cryptography.hazmat.primitives.hashes import SHA256
from cryptography.hazmat.primitives.serialization import (BestAvailableEncryption,
                                                          Encoding,
                                                          PrivateFormat,
                                                          load_pem_private_key)

# SecureBoot Crypto
from signify.authenticode import SignedPEFile

# Utilities
from dotenv import dotenv_values
from oclib import (OcConfig, dump_plist, get_nested_key, read_plist,
                   set_nested_key)

# ===================================================================
# Helpers
T = TypeVar('T')
U = TypeVar('U')

if isatty(stderr.fileno()):
    def msg(msg: str, *, prefix="", color=0, file=stderr):
        print(f"\033[{color}m{prefix}", msg, "\033[0m", file=file)
else:
    def msg(msg: str, *, prefix="", color=None, file=stderr):
        print(prefix, msg, file=file)

msg_head = bind(msg, prefix="==", color=33)
msg_err = bind(msg, prefix="!!", color=31)

def ask_choice(question: str, choices={"yes": True, "no": False}, default="no", *, sentinel=object()):
    if default is not None and default not in choices:
        raise ValueError(f"Default {default} is not a valid choice: {choices}")
    prompt = f"\033[35m{question} [{'/'.join((choice.upper() if choice == default else choice.lower()) for choice in choices.keys())}]\033[0m"
    answer = None
    while answer is None or default is None:
        print(prompt, end=' ')
        answer = input().lower()
        result = sentinel
        if answer:
            for choice, value in choices.items():
                if choice.startswith(answer):
                    if result is sentinel:
                        result = value
                    else:
                        print(f"Answer '{answer}' does not uniquely identify a choice, please try again.")
                        answer = None
                        break
            if answer is not None and result is not sentinel:
                return result
        elif default is not None:
            return choices[default]

def ensure_existing(path: Union[Path, str]) -> Path:
    if isinstance(path, str):
        path = Path(str)
    if not path.exists():
        raise FileNotFoundError(path)
    return path

def lookup_tool(name: str, path: Optional[Path]) -> Path:
    if path is not None:
        return ensure_existing(path)
    xpath = which(name)
    if xpath is None:
        raise FileNotFoundError(f"Could not find tool '{name}' in $PATH")
    return Path(xpath)

def optmap(fn: Callable[[T], U], opt: Optional[T]) -> Optional[U]:
    return fn(opt) if opt is not None else None

def b2a_b32h_nopad(data: bytes) -> str:
    return b32hexencode(data).decode('ascii').rstrip('=')

class SignTool(ABC):
    @abstractmethod
    def sign_file(self, path: Path, out_path: Optional[Path]): ...


# ===================================================================
# Configuration
class Config:
    root: Path
    env: dict

    # EFI
    esp_path: Path = Path("/efi")
    esp_name: str = "OC"
    esp_backup: Optional[str] = "OC.bak"
    esp_restore_on_error: bool = True
    esp_device: Optional[str] = None

    # SecureBoot
    sb_tool: Optional[SignTool]
    sb_cache_path: Optional[Path]
    sb_cache_fmt: str = "{stem}.{hash}{suffix}"
    sb_cache_opencore: Literal['auto', 'always', 'never'] = 'auto'
    sb_cache_mismatch: bool = False

    # OC Vault
    vault_key_size: int = 2048
    vault_key_file: Optional[Path]
    vault_hash_fn = sha256

    def __init__(self, root: Path, env: dict):
        missing_keys = ENV_REQUIRED_KEYS - env.keys()
        if missing_keys:
            raise ValueError(f"Missing required environment keys: {', '.join(missing_keys)}")

        self.root = root
        self.env = env

        # SecureBoot signing tool
        toolname: Optional[str] = optmap(str.lower, env.get("SB_TOOL", None))
        if toolname:
            try:
                tool = SB_TOOLS[toolname]
            except KeyError:
                raise ValueError(f"Unknown value for SecureBoot signing tool: '{toolname}'")
            prefix = f"sb_{toolname}_"
            kwds = {k.lower().removeprefix(prefix): v for k,v in env.items() if k.lower().startswith(prefix)}
            self.sb_tool = tool(**kwds)
        else:
            self.sb_tool = None

        # SecureBoot cache
        self.sb_cache_path = optmap(Path, env.get("SB_CACHE_PATH", None))

        fmt: Optional[str] = env.get("SB_CACHE_FORMAT", None)
        if fmt:
            if "%n" not in cache and "%h" not in fmt:
                raise ValueError(f"SB_CACHE_FORMAT must include atleast one of %n or %h: {fmt}")
            self.sb_cache_fmt = (cache
                .replace("{", "{{")
                .replace("}", "}}")
                .replace("%n", "{stem}")
                .replace("%h", "{hash}")
                .replace("%e", "{suffix}"))

        self.sb_cache_opencore = env.get("SB_CACHE_OPENCORE", self.sb_cache_opencore)
        if self.sb_cache_opencore not in ('auto', 'always', 'never'):
            raise ValueError(f"Invalid value for SB_CACHE_OPENCORE: {self.sb_cache_opencore}")
        self.sb_cache_mismatch = env.get("SB_CACHE_IGNORE_MISMATCH", 'false') in ('true', 'yes')

        # ESP stuff
        self.esp_path = Path(env.get("ESP_PATH", self.esp_path)) # TODO: detection?
        self.esp_name = env.get("ESP_NAME", self.esp_name)
        self.esp_backup = env.get("ESP_BACKUP", self.esp_backup) or None
        self.esp_restore_on_error = optmap(str.lower, env.get("ESP_RESTORE_ON_ERROR", None)) not in ('false', 'no')
        self.esp_device = env.get("ESP_DEVICE", None)

        # Vault signing
        self.vault_key_size = int(env.get("VAULT_KEY_SIZE", self.vault_key_size))
        self.vault_key_file = optmap(Path, env.get("VAULT_KEY_FILE", None))

    @property
    def oc_dir(self):
        return self.root / "OC"

    @cached_property
    def vault_key(self) -> RSAPrivateKey:
        """ Load or generate vault private key """
        # TODO: log key source
        if self.vault_key_file and self.vault_key_file.exists():
            msg(f"Loading vault key from file: {self.vault_key_file}")
            try:
                return load_pem_private_key(
                    data=self.vault_key_file.read_bytes(),
                    password=None
                )
            except TypeError:
                pass
            return load_pem_private_key(
                data=self.vault_key_file.read_bytes(),
                password=getpass("  Vault Key Passphrase: ").encode('utf-8')
            )
        else:
            msg(f"Generating new vault key (RSA {self.vault_key_size})")
            vault_key = generate_private_key(
                public_exponent=0x10001, # 65537
                key_size=self.vault_key_size,
            )
            if self.vault_key_file:
                encrypt = None
                if passwd := getpass("  New Vault Key Passphrase: "):
                    encrypt = BestAvailableEncryption(password=passwd.encode('utf-8'))
                self.vault_key_file.write_bytes(vault_key.private_bytes(
                    encoding=Encoding.PEM,
                    format=PrivateFormat.PKCS8,
                    encryption_algorithm=encrypt
                ))
                msg(f"Saved vault key to file: {self.vault_key_file}")
            return vault_key

    @property
    def is_vault_persistent(self):
        return self.vault_key_file is not None


# ===================================================================
# Crypto
# -------------------------------------------------------------------
# Vault Hashing
def hash_file(conf: Config, path: Path) -> bytes:
    with path.open('rb') as f:
        return file_digest(f, conf.vault_hash_fn).digest()

def copy_and_hash(conf: Config, src: Path, dst: Path, *, bufsize=2**18) -> bytes:
    with open(src, "rb") as fs:
        digest = conf.vault_hash_fn()
        with open(dst, "wb") as fd:
            buffer = bytearray(bufsize)
            view = memoryview(buffer)
            while True:
                read = fs.readinto(buffer)
                if read == 0:
                    break
                data = view[:read]
                digest.update(data)
                fd.write(data)
        return digest.digest()

def maybe_copy_and_hash(conf: Config, src: Path, dst: Optional[Path], return_digest: bool) -> Optional[bytes]:
    if dst is not None:
        if return_digest:
            return copy_and_hash(conf, src, dst)
        else:
            copy(src, dst)
    elif return_digest:
        return hash_file(conf, src)


# -------------------------------------------------------------------
# SecureBoot signing tools
class Sbctl(SignTool):
    """
    Sign EFI binaries using machine sbctl.8 setup.
    https://github.com/Foxboron/sbctl
    """
    def __init__(self, path: Optional[str]=None):
        self.exepath = lookup_tool("sbctl", path)

    def sign_file(self, path, out_path):
        check_call([
            self.exepath,
            "sign",
            fspath(path),
            *(["-o", fspath(out_path)] if out_path else [])
        ])


class Sbsign(SignTool):
    """
    Sign EFI binaries with key and cert files using the sbsign.1 tool.
    https://github.com/phrack/sbsigntools
    """
    def __init__(self, key: str, cert: str, path: Optional[str]=None):
        self.exepath = lookup_tool("sbsign", path)
        self.keyfile = ensure_existing(key)
        self.crtfile = ensure_existing(cert)

    def sign_file(self, path, out_path):
        check_call([
            self.exepath,
            "--key", self.keyfile,
            "--cert", self.crtfile,
            path,
            *(["--output", out_path] if out_path else [])
        ])


class Cacheonly(SignTool):
    """
    Don't sign anything, but use previously signed binaries from cache.
    Allows for rebuilding persistent-key vault without SecureBoot keys.
    """
    def __init__(self, allow_unsigned: Optional[str]=None):
        self.allow_unsigned = allow_unsigned.lower() in ('yes', 'true')

    def sign_file(self, path, out_path):
        if not self.allow_unsigned:
            raise LookupError("Suitable signed UEFI image not found in cache (SB_TOOL=cacheonly)")
        msg_err("No matching signed UEFI image in cache. Copying unsigned image.")
        maybe_copy_and_hash(conf, path, out_path, False)


SB_TOOLS = {
    "sbctl": Sbctl,
    "sbsign": Sbsign,
    "cacheonly": Cacheonly,
}

def get_pe_hash(pe: SignedPEFile, hash_fn=sha256) -> bytes:
    """ Get the AuthentiCode hash of a signed PE binary """
    fp = pe.get_fingerprinter()
    fp.add_authenticode_hashers(hash_fn)
    return next(iter(fp.hashes()['authentihash'].values()))

def sign_pe_image(conf: Config, path: Path, out_path: Optional[Path]=None, *, return_file_digest: bool=False, dont_cache: bool=False) -> Optional[bytes]:
    """ Sign an UEFI executable """
    if not conf.sb_tool:
        return maybe_copy_and_hash(conf, src, dst, return_file_digest)

    # Check cache
    cache_file: Optional[Path] = None
    if conf.sb_cache_path:
        # Compute hash
        with path.open('rb') as f:
            pe = SignedPEFile(f)
            digest = get_pe_hash(pe)

        cache_file = conf.sb_cache_path / conf.sb_cache_fmt.format(
            stem=path.stem,
            hash=b2a_b32h_nopad(digest),
            suffix=path.suffix)

        if cache_file.exists():
            # Check match
            with cache_file.open('rb') as f:
                pe = SignedPEFile(f)
                cache_ok = True
                # Check that it's actually signed
                # TODO: allow specifying pubkey to verify against. For now, ignore cert error
                status, err = pe.explain_verify()
                if status not in (status.OK, status.CERTIFICATE_ERROR):
                    msg_err(f"Cached SecureBoot image isn't properly signed: {cache_file}")
                    import traceback
                    msg_err(traceback.format_exception_only(None, err))
                    cache_ok = False
                # Check that it matches our file
                cache_digest = get_pe_hash(pe)
                if cache_digest != digest:
                    if conf.sb_cache_mismatch:
                        msg(f"Cached SecureBoot image doesn't match, using anyway.", prefix="!!")
                    else:
                        msg_err(f"Cached SecureBoot image doesn't match, ignoring: {cache_file}")
                        cache_ok = False
                    msg(f"Checksums: {b2a_b32h_nopad(cache_digest)} != {b2a_b32h_nopad(digest)}")
            # Use cache
            if cache_ok:
                msg(f"Using signed image from {cache_file}")
                return maybe_copy_and_hash(conf, cache_file, out_path if out_path is not None else path, return_file_digest)

    # Try to sign the file using configured tool
    conf.sb_tool.sign_file(path, out_path)

    if out_path is None:
        out_path = path

    # Maybe cache image for later use
    if cache_file is not None and not dont_cache:
        msg(f"Caching signed image to {cache_file}")
        cache_file.parent.mkdir(parents=True, exist_ok=True)
        return maybe_copy_and_hash(conf, out_path, cache_file, return_file_digest)
    elif return_file_digest:
        return hash_file(conf, out_path)

def install_sign_efi(conf: Config, src: Path, dst: Path) -> bytes:
    """ Sign UEFI executable and return digest """
    return sign_pe_image(conf, src, dst, return_file_digest=True)


# -------------------------------------------------------------------
# OpenCore Vault
def write_oc_pubkey(pubkey: RSAPublicKey, out: IO[bytes]) -> int:
    """
    Serialize OpenCore Vault RSA public key.
    Return number of bytes that were written to out.
    See OpenCore source at Utilities/RsaTool/RsaTool.c
    """
    written = 0
    # /* Output size of RSA key in 64-bit words */
    nwords = pubkey.key_size // 64
    if nwords >= 2**16:
        raise RuntimeError("pubkey too large?")
    written += out.write(nwords.to_bytes(8, 'little'))
    N = pubkey.public_numbers().n
    B = 2**64 # /* B = 2^64 */
    # /* Calculate and output N0inv = -1 / N[0] mod 2^64 */
    N0inv = pow(N, -1, B)
    N0inv = B - N0inv
    written += out.write(N0inv.to_bytes(8, 'little'))
    # /* Calculate R = 2^(# of key bits) */
    R = 2 ** N.bit_length()
    # /* Calculate RR = R^2 mod N */
    RR = R ** 2 % N
    # /* Write out modulus as little endian array of integers. */
    written += out.write(N.to_bytes(nwords * 8, 'little'))
    # /* Write R^2 as little endian array of integers. */
    written += out.write(RR.to_bytes(nwords * 8, 'little'))
    return written

OC_VAULT_BEGIN_MARKER = b"=BEGIN OC VAULT="
OC_VAULT_END_MARKER = b"==END OC VAULT=="

def install_opencore_efi(conf: Config, src: Path, dest: Path):
    """ Install the OpenCore UEFI executable while baking in the vault public key """
    # FIXME: do this better
    # See OpenCorePkg/Utilities/CreateVault/sign.command
    data = src.read_bytes()

    # Find embedded vault key region
    offset = data.find(OC_VAULT_BEGIN_MARKER)
    if offset < 0:
        raise RuntimeError(f"Could not find Vault key marker in {src}")
    offset += len(OC_VAULT_BEGIN_MARKER)
    end = data.find(OC_VAULT_END_MARKER, offset)
    if end < 0:
        raise RuntimeError(f"Could not find Vault end marker in {src}")
    max_len = end - offset

    # Copy to destination while embedding public key data
    view = memoryview(data)
    with dest.open("wb") as f:
        f.write(view[:offset])
        pubkey_len = write_oc_pubkey(conf.vault_key.public_key(), f)
        if pubkey_len > max_len:
            raise OverflowError(f"vault public key data too big ({pubkey_len}B/{max_len}B)")
        f.write(view[offset+pubkey_len:])
    msg(f"Baked RSA public key into {dest} ({pubkey_len}B/{max_len}B)")

    # SecureBoot-sign result
    sign_pe_image(conf, dest, None,
        dont_cache=conf.sb_cache_opencore == 'never'
            or conf.sb_cache_opencore == 'auto' and not conf.is_vault_persistent)

def sign_vault(conf: Config, files: dict, esp_oc_dir: Path):
    """ Create and sign vault file """
    plist_data = dump_plist({
        "Version": 1,
        "Files": files
    })
    sig_data = conf.vault_key.sign(
        data=plist_data,
        padding=PKCS1v15(),
        algorithm=SHA256(),
    )
    (esp_oc_dir / "vault.plist").write_bytes(plist_data)
    (esp_oc_dir / "vault.sig").write_bytes(sig_data)


# ===================================================================
# OC config plist interpolation
PlistValue = Union[str, int, bytes, list, dict]
ENV_REQUIRED_KEYS = {"SYSTEM_SERIAL", "SYSTEM_MLB", "SYSTEM_ROM", "SYSTEM_UUID"}
ENV_CONFIG_KEYS: dict[str, tuple[tuple[str,...], Callable[[str], PlistValue]]] = {
    # Identity
    "SYSTEM_SERIAL": (("PlatformInfo", "Generic", "SystemSerialNumber"), str),
    "SYSTEM_MLB": (("PlatformInfo", "Generic", "MLB"), str),
    "SYSTEM_ROM": (("PlatformInfo", "Generic", "ROM"), b64decode),
    "SYSTEM_UUID": (("PlatformInfo", "Generic", "SystemUUID"), str),

    # Security
    "SEC_APECID": (("Misc", "Security", "ApECID"), int),
    "SEC_VAULT": (("Misc", "Security", "Vault"), str),
    "SEC_SCAN_POLICY": (("Misc", "Security", "ScanPolicy"), int),
}

def install_config_plist(conf: Config, template: Path, dest: Path) -> bytes:
    """ Substitute values from .env file into config.plist and copy to ESP """
    data: OcConfig = read_plist(template)

    for key in ENV_CONFIG_KEYS & conf.env.keys():
        path, convert = ENV_CONFIG_KEYS[key]
        set_nested_key(data, path, convert(conf.env[key]))

    plist_data = dump_plist(data)
    dest.write_bytes(plist_data)
    return conf.vault_hash_fn(plist_data).digest()


# ===================================================================
# Transfer files
def walk(root: Path):
    """ Like os.walk but for pathlib Paths """
    for path in root.iterdir():
        yield path
        if path.is_dir() and not hasattr(path, "skip"):
            yield from walk(path)

def install_oc(conf: Config):
    """ Main OpenCore install process """
    oc_dir = conf.oc_dir
    efi_dir = conf.esp_path / "EFI"
    dest = efi_dir / conf.esp_name
    backup_dir = efi_dir / conf.esp_backup

    if not efi_dir.exists() and conf.esp_device:
        msg_head("Trying to mount EFI volume")
        if os.getuid() != 0:
            msg_err("Cannot mount volume as non-root")
        else:
            import subprocess, shlex
            def run(*argv):
                msg(f"Running {shlex.join(argv)}", color=36)
                return subprocess.run(argv)
            if sys.platform == 'darwin':
                run("diskutil", "mount", "nobrowse", "-mountPoint", conf.esp_path, conf.esp_device)
            else:
                run("mount", conf.esp_device, conf.esp_path)

    if dest.exists():
        # Create backup of ESP dir
        if conf.esp_backup:
            msg_head(f"Renaming {dest} to {conf.esp_backup}")
            if backup_dir.exists():
                msg(f"Removing {backup_dir}")
                rmtree(backup_dir)
            dest.rename(backup_dir)
        else:
            msg_head(f"Removing existing {dest}")
            rmtree(dest)

    try:
        msg_head(f"Installing OpenCore from {oc_dir} to {dest}")
        dest.mkdir(parents=True)

        # Record installed files for vault
        files: dict[str, bytes] = {}
        def add(name: Path, digest: bytes):
            files[str(name).replace('/', '\\')] = digest

        opencore_efi: Optional[Path] = None

        # Install all files from oc_dir
        for path in walk(conf.oc_dir):
            name = path.relative_to(oc_dir)
            target = dest / name

            # Create folders
            if path.is_dir():
                if path.name[0] == '.':
                    print(f"[skip] {name}/", file=stderr)
                    path.skip = True
                else:
                    target.mkdir()
                continue

            lower = str(name).lower()

            # Skip hidden files, except .contentVisibility and .contentFlavour
            # Skip documentation and log files
            # Skip vault files, they are generated from scratch later
            if ((name.name[0] == '.' and lower not in (".contentvisibility", ".contentflavour"))
                    or lower.rsplit('.', 1)[-1] in ("html", "log")
                    or lower.startswith("vault.")):
                print(f"[skip] {name}", file=stderr)
                continue

            # Fill and install OpenCore config
            if lower == "config.plist":
                if name.name != "config.plist":
                    msg(f"Warning: There may be issues with vault verification if config.plist's filename isn't all lower-case.", color=31)
                print(f"[conf] {name}", file=stderr)
                add(name, install_config_plist(conf, path, target))

            # OpenCore binary must be installed last, so remember it for later
            elif lower == "opencore.efi":
                opencore_efi = path

            # SecureBoot-sign and install EFI drivers
            elif lower.endswith('.efi') and lower.startswith("drivers/"):
                print(f"[sign] {name}", file=stderr)
                add(name, install_sign_efi(conf, path, target))

            # Just copy all other files
            else:
                print(f"[copy] {name}", file=stderr)
                add(name, copy_and_hash(conf, path, target))

        if not opencore_efi:
            raise RuntimeError("Didn't find OpenCore.efi")

        # Build and sign vault
        msg_head("Signing Vault")
        sign_vault(conf, files, dest)

        # Build, sign and install main OpenCore binary
        msg_head("Installing and signing main OpenCore binary")
        install_opencore_efi(conf, opencore_efi, dest / opencore_efi.relative_to(oc_dir))

    except:
        # Restore ESP dir from backup
        if conf.esp_restore_on_error and conf.esp_backup and backup_dir.exists():
            msg_head(f"Restoring backup from {backup_dir}")
            rmtree(dest)
            backup_dir.rename(dest)
        raise


def main(argv):
    parser = ArgumentParser(prog=argv[0])
    parser.add_argument("-f", "--noconfirm", action="store_true", help="Don't ask for confirmation interactively")
    parser.add_argument("--env-file", type=ensure_existing, action="append", default=[])
    parser.add_argument("env", metavar="NAME=VALUE", nargs="*")
    args = parser.parse_args(argv[1:])

    # Build config from files and commandline
    env = {}
    if not args.env_file:
        args.env_file = [".env"]
    for de in args.env_file:
        env.update(dotenv_values(de))
    for ev in args.env:
        k, v = ev.split('=',1)
        env[k] = v

    conf = Config(Path(argv[0]).parent.resolve().parent, env)

    # Confirmation prompt
    if not args.noconfirm and not ask_choice(f"""Install to {conf.esp_path / "EFI" / conf.esp_name}"""):
            return

    # Proceed
    install_oc(conf)

if __name__ == "__main__":
    main(argv)
