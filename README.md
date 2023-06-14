OpenCore SecureBoot installer for T480
======================================

This is my T480 OpenCore setup, derived from [Valnoxy/t480-oc](https://github.com/valnoxy/t480-oc)

The OC folder contains all files to be copied to the ESP and isn't anything special.
The tools folder contains some tools i wrote to make managing the OC install easier:
- `tools/install.py` ESP install script with SecureBoot and Vault signing
- `tools/proper-list.py` Tool for listing all Kexts configured in `config.plist` in a more human-readable manner
- `tools/update-kexts.py` Tool for insteractively adding/removing Kexts from `config.plist`
- `tools/pj` Tool for converting plists to json, mostly useful for inspecting plists using [`jq`](https://stedolan.github.io/jq/)

A makefile is included for convenience:
- `make setup` Set up required python environment for tools
- `make config` Edit `OC/config.plist` using [ProperTree](https://github.com/corpnewt/ProperTree)
- `make list` List Kexts using `tools/proper-list.py`
- `make ssdts` List SSDTs using `tools/proper-list.py`
- `make newkext` Check for added/deleted Kexts using `tools/update-kexts.py`
- `make env` Edit `.env` using `$EDITOR`
- `make install` Install to ESP according to `.env` (needs root)

Note that machine-specific configuration (including PlatformInfo like serial) goes into the `.env` file instead of `config.plist`, to keep that file clean for versioning and/or sharing. The concerned values are automatically added to `config.plist` when it's copied to the ESP by the install script.
