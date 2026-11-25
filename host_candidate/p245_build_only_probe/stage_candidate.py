"""Assemble a disposable unsigned archive by replacing only its primary DEX."""

import argparse
from copy import copy
from pathlib import Path
import zipfile

from strict_dex import SIGNATURE_ENTRY


def stage(base_path, rebuilt_path, output_path):
    with zipfile.ZipFile(rebuilt_path) as rebuilt:
        if rebuilt.namelist().count("classes.dex") != 1:
            raise ValueError("P245_REBUILT_PRIMARY_DEX_REQUIRED")
        primary = rebuilt.read("classes.dex")
    with zipfile.ZipFile(base_path) as base:
        names = base.namelist()
        if names.count("classes.dex") != 1 or len(set(names)) != len(names):
            raise ValueError("P245_UNAMBIGUOUS_BASE_ARCHIVE_REQUIRED")
        with zipfile.ZipFile(output_path, "x") as output:
            for entry in base.infolist():
                if not SIGNATURE_ENTRY.fullmatch(entry.filename):
                    data = primary if entry.filename == "classes.dex" else base.read(entry)
                    # ZipFile.writestr changes header_offset in the passed entry.
                    output.writestr(copy(entry), data)


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ("base", "rebuilt", "output"):
        parser.add_argument(name, type=Path)
    args = parser.parse_args()
    stage(args.base, args.rebuilt, args.output)
