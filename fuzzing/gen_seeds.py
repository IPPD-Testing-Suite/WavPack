#!/usr/bin/env python3
"""
Generate binary seed corpus files for WavPack fuzzing harnesses.
Each seed is crafted to exercise a specific injected vulnerability.
"""

import os
import struct

BASE = os.path.dirname(os.path.abspath(__file__))

def mkdir(path):
    os.makedirs(path, exist_ok=True)

# ---------------------------------------------------------------------------
# Seed 1 — channel_identities_seed_corpus/seed_01
# Bug 1: off-by-one malloc in read_channel_identities (src/open_utils.c:564)
# A 44-byte WavPack block with ID_CHANNEL_IDENTITIES metadata.
# ---------------------------------------------------------------------------
def make_seed1():
    d = os.path.join(BASE, "channel_identities_seed_corpus")
    mkdir(d)

    # WavPack block header (32 bytes) + 8 bytes metadata = 40 bytes total
    # ckSize = total_block_size - 8 = 40 - 8 = 32
    data = bytes([
        # WavPack block header (32 bytes)
        0x77, 0x76, 0x70, 0x6B,  # "wvpk"
        0x20, 0x00, 0x00, 0x00,  # ckSize = 32 (40 - 8)
        0x07, 0x04,              # version = 0x0407
        0x00, 0x00,              # block_index_u8, total_samples_u8
        0x00, 0x00, 0x00, 0x00,  # total_samples = 0
        0x00, 0x00, 0x00, 0x00,  # block_index = 0
        0x00, 0x00, 0x00, 0x00,  # block_samples = 0
        0x04, 0x10, 0x00, 0x00,  # flags = 0x1004 (FINAL_BLOCK | MONO_FLAG)
        0x00, 0x00, 0x00, 0x00,  # crc = 0
        # ID_CHANNEL_INFO metadata: 3 channels, no mask
        0x0D, 0x01, 0x03, 0x00,
        # ID_CHANNEL_IDENTITIES | ID_ODD_SIZE (0x6B): 1 word, 1 real byte identity=2, padding=0
        0x6B, 0x01, 0x02, 0x00,
    ])
    assert len(data) == 40, f"Seed 1 length {len(data)} != 40"
    with open(os.path.join(d, "seed_01"), "wb") as f:
        f.write(data)
    print(f"Wrote seed 1: {len(data)} bytes -> {d}/seed_01")

# ---------------------------------------------------------------------------
# Seed 2 — binary_tag_seed_corpus/seed_01
# Bug 2: memcpy size+1 in get_ape_tag_item binary branch (src/tag_utils.c:259)
# An 88-byte file: 40-byte WavPack block + 16-byte APEv2 item + 32-byte footer.
# ---------------------------------------------------------------------------
def make_seed2():
    d = os.path.join(BASE, "binary_tag_seed_corpus")
    mkdir(d)

    # 40-byte WavPack block (block_samples=1)
    wv_block = bytes([
        0x77, 0x76, 0x70, 0x6B,  # "wvpk"
        0x20, 0x00, 0x00, 0x00,  # ckSize = 32
        0x07, 0x04,              # version
        0x00, 0x00,              # block_index_u8, total_samples_u8
        0x01, 0x00, 0x00, 0x00,  # total_samples = 1
        0x00, 0x00, 0x00, 0x00,  # block_index = 0
        0x01, 0x00, 0x00, 0x00,  # block_samples = 1
        0x04, 0x10, 0x00, 0x00,  # flags = 0x1004
        0x00, 0x00, 0x00, 0x00,  # crc
        0x0D, 0x01, 0x01, 0x00,  # ID_CHANNEL_INFO: 1 channel
        0x0A, 0x01, 0xFF, 0xFF,  # ID_WV_BITSTREAM: 2 bytes
    ])
    assert len(wv_block) == 40

    # 16-byte APEv2 item data
    # vsize=2, flags=2 (binary: bit1=1), key="Cover\0", value=0xDEAD
    ape_item = bytes([
        0x02, 0x00, 0x00, 0x00,  # vsize = 2
        0x02, 0x00, 0x00, 0x00,  # flags = 2 (binary type)
        0x43, 0x6F, 0x76, 0x65,  # "Cove"
        0x72, 0x00,              # "r\0"
        0xDE, 0xAD,              # 2 bytes binary value
    ])
    assert len(ape_item) == 16

    # 32-byte APEv2 footer
    # length = 16 (item) + 32 (footer) = 48
    ape_footer = bytes([
        0x41, 0x50, 0x45, 0x54, 0x41, 0x47, 0x45, 0x58,  # "APETAGEX"
        0xD0, 0x07, 0x00, 0x00,  # version = 2000
        0x30, 0x00, 0x00, 0x00,  # length = 48
        0x01, 0x00, 0x00, 0x00,  # item_count = 1
        0x00, 0x00, 0x00, 0x00,  # flags = 0 (footer, no header)
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,  # reserved
    ])
    assert len(ape_footer) == 32

    data = wv_block + ape_item + ape_footer
    assert len(data) == 88, f"Seed 2 length {len(data)} != 88"
    with open(os.path.join(d, "seed_01"), "wb") as f:
        f.write(data)
    print(f"Wrote seed 2: {len(data)} bytes -> {d}/seed_01")

# ---------------------------------------------------------------------------
# Seed 3 — entropy_seed_corpus/seed_01
# Bug 3: signed integer overflow in wp_exp2s (src/entropy_utils.c:340)
# A 44-byte WavPack block with entropy vars having log value = 0x2000.
# ---------------------------------------------------------------------------
def make_seed3():
    d = os.path.join(BASE, "entropy_seed_corpus")
    mkdir(d)

    data = bytes([
        # WavPack block header (32 bytes)
        0x77, 0x76, 0x70, 0x6B,  # "wvpk"
        0x24, 0x00, 0x00, 0x00,  # ckSize = 36
        0x07, 0x04,              # version
        0x00, 0x00,              # block_index_u8, total_samples_u8
        0x00, 0x00, 0x00, 0x00,  # total_samples = 0
        0x00, 0x00, 0x00, 0x00,  # block_index = 0
        0x00, 0x00, 0x00, 0x00,  # block_samples = 0
        0x04, 0x10, 0x00, 0x00,  # flags = 0x1004 (FINAL_BLOCK | MONO_FLAG)
        0x00, 0x00, 0x00, 0x00,  # crc = 0
        # ID_CHANNEL_INFO: 1 channel
        0x0D, 0x01, 0x01, 0x00,
        # ID_ENTROPY_VARS (0x05), 3 words = 6 bytes
        # median[0] = 0x2000 (triggers UBSan overflow), others = 0
        0x05, 0x03,
        0x00, 0x20, 0x00, 0x00, 0x00, 0x00,
    ])
    assert len(data) == 44, f"Seed 3 length {len(data)} != 44"
    with open(os.path.join(d, "seed_01"), "wb") as f:
        f.write(data)
    print(f"Wrote seed 3: {len(data)} bytes -> {d}/seed_01")

# ---------------------------------------------------------------------------
# Seed 4 — id3_tag_seed_corpus/seed_01
# Bug 4: stack buffer overflow in get_id3_tag_item (src/tag_utils.c:288)
# A 168-byte file: 40-byte WavPack block + 128-byte ID3v1 tag.
# ---------------------------------------------------------------------------
def make_seed4():
    d = os.path.join(BASE, "id3_tag_seed_corpus")
    mkdir(d)

    # 40-byte WavPack block (block_samples=1)
    wv_block = bytes([
        0x77, 0x76, 0x70, 0x6B,  # "wvpk"
        0x20, 0x00, 0x00, 0x00,  # ckSize = 32
        0x07, 0x04,              # version
        0x00, 0x00,              # block_index_u8, total_samples_u8
        0x01, 0x00, 0x00, 0x00,  # total_samples = 1
        0x00, 0x00, 0x00, 0x00,  # block_index = 0
        0x01, 0x00, 0x00, 0x00,  # block_samples = 1
        0x04, 0x10, 0x00, 0x00,  # flags = 0x1004
        0x00, 0x00, 0x00, 0x00,  # crc
        0x0D, 0x01, 0x01, 0x00,  # ID_CHANNEL_INFO: 1 channel
        0x0A, 0x01, 0xFF, 0xFF,  # ID_WV_BITSTREAM: 2 bytes
    ])
    assert len(wv_block) == 40

    # 128-byte ID3v1 tag
    # Structure: "TAG" (3) + title (30) + artist (30) + album (30) + year (4) + comment (30) + genre (1)
    tag_marker = b"TAG"
    title = b"Hello World!" + b"\x00" * 18   # 30 bytes
    artist = b"\x00" * 30
    album = b"\x00" * 30
    year = b"\x00" * 4
    comment = b"\x00" * 30
    genre = b"\x00"

    id3_tag = tag_marker + title + artist + album + year + comment + genre
    assert len(id3_tag) == 128, f"ID3v1 tag length {len(id3_tag)} != 128"

    data = wv_block + id3_tag
    assert len(data) == 168, f"Seed 4 length {len(data)} != 168"
    with open(os.path.join(d, "seed_01"), "wb") as f:
        f.write(data)
    print(f"Wrote seed 4: {len(data)} bytes -> {d}/seed_01")

# ---------------------------------------------------------------------------
# Seed 5 — append_tag_seed_corpus/seed_01
# Bug 5: wrong pointer offset in append_ape_tag_item (src/tag_utils.c:435)
# Same as Seed 2 (has an APEv2 tag so MODE_VALID_TAG is set), causing the
# fuzzer harness to call WavpackAppendTagItem, which triggers the bug.
# ---------------------------------------------------------------------------
def make_seed5():
    d = os.path.join(BASE, "append_tag_seed_corpus")
    mkdir(d)

    # Reuse the same content as Seed 2
    wv_block = bytes([
        0x77, 0x76, 0x70, 0x6B,
        0x20, 0x00, 0x00, 0x00,
        0x07, 0x04,
        0x00, 0x00,
        0x01, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00,
        0x01, 0x00, 0x00, 0x00,
        0x04, 0x10, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00,
        0x0D, 0x01, 0x01, 0x00,
        0x0A, 0x01, 0xFF, 0xFF,
    ])
    ape_item = bytes([
        0x02, 0x00, 0x00, 0x00,
        0x02, 0x00, 0x00, 0x00,
        0x43, 0x6F, 0x76, 0x65,
        0x72, 0x00,
        0xDE, 0xAD,
    ])
    ape_footer = bytes([
        0x41, 0x50, 0x45, 0x54, 0x41, 0x47, 0x45, 0x58,
        0xD0, 0x07, 0x00, 0x00,
        0x30, 0x00, 0x00, 0x00,
        0x01, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    ])

    data = wv_block + ape_item + ape_footer
    assert len(data) == 88, f"Seed 5 length {len(data)} != 88"
    with open(os.path.join(d, "seed_01"), "wb") as f:
        f.write(data)
    print(f"Wrote seed 5: {len(data)} bytes -> {d}/seed_01")

if __name__ == "__main__":
    make_seed1()
    make_seed2()
    make_seed3()
    make_seed4()
    make_seed5()
    print("All seed files generated successfully.")
