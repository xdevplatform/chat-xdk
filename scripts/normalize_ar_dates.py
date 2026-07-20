#!/usr/bin/env python3
"""Zero the date field of every member header in `!<arch>` static archives.

macOS ar/ranlib/strip stamp each archive member (and the __.SYMDEF symbol
table) with the build time, so byte-identical inputs produce byte-different
archives. ZERO_AR_DATE=1 handles the cctools passes, but this pass guarantees
every 12-byte date field is zeroed regardless of which tool wrote the header,
making the committed prebuilts reproducible across CI and local builds.

Usage: normalize_ar_dates.py ARCHIVE [ARCHIVE ...]
"""

import sys

MAGIC = b"!<arch>\n"
HEADER_LEN = 60
# Member header layout: name[16] date[12] uid[6] gid[6] mode[8] size[10] end[2]
DATE_OFFSET = 16
DATE_LEN = 12
SIZE_OFFSET = 48
SIZE_LEN = 10
END_MARKER = b"`\n"
ZERO_DATE = b"0".ljust(DATE_LEN)


def normalize(path):
    with open(path, "r+b") as f:
        data = bytearray(f.read())
        if data[: len(MAGIC)] != MAGIC:
            raise SystemExit(f"{path}: not an ar archive")
        changed = False
        off = len(MAGIC)
        while off + HEADER_LEN <= len(data):
            header = data[off : off + HEADER_LEN]
            if header[HEADER_LEN - 2 :] != END_MARKER:
                raise SystemExit(f"{path}: malformed member header at offset {off}")
            date_field = slice(off + DATE_OFFSET, off + DATE_OFFSET + DATE_LEN)
            if data[date_field] != ZERO_DATE:
                data[date_field] = ZERO_DATE
                changed = True
            size = int(header[SIZE_OFFSET : SIZE_OFFSET + SIZE_LEN].split()[0])
            # Member data is 2-byte aligned.
            off += HEADER_LEN + size + (size & 1)
        if changed:
            f.seek(0)
            f.write(data)


def main():
    if len(sys.argv) < 2:
        raise SystemExit(__doc__.strip().splitlines()[-1])
    for path in sys.argv[1:]:
        normalize(path)


if __name__ == "__main__":
    main()
