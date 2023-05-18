#!/usr/bin/env python3

from urllib.request import urlopen
from zipfile import ZipFile
from sys import argv
from tempfile import TemporaryFile
from shutil import copyfileobj

url = "https://github.com/corpnewt/ProperTree/archive/refs/heads/master.zip"

print(f"Downloading ProperTree from {url}")

with TemporaryFile("wb+") as t:
    with urlopen(url) as r:
        copyfileobj(r, t)
    t.seek(0)
    with ZipFile(t) as f:
        for info in f.infolist():
            info.filename = info.filename.split('/',1)[1]
            if info.filename:
                f.extract(info, argv[1])
