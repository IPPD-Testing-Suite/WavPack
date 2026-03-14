# WavPack Seeded Vulnerability Report

**Library:** WavPack 5.7.0
**Branch:** master (with injected bugs)
**Purpose:** Fuzzer evaluation — intentionally introduced vulnerabilities for sanitizer-guided fuzzing research.
**Date:** 2026-03-14

> **Note:** These bugs are NOT present in the upstream WavPack codebase.
> They were introduced deliberately to evaluate custom fuzzer effectiveness.

---

## Summary Table

| # | CWE | Type | File (modified line) | Sanitizer | Trigger Input |
|---|-----|------|----------------------|-----------|---------------|
| 1 | CWE-122 | Heap buffer overflow (off-by-one malloc) | `src/open_utils.c:564` | ASan heap-buffer-overflow | WavPack file with ID_CHANNEL_IDENTITIES metadata |
| 2 | CWE-122 | Heap buffer overflow (memcpy size+1) | `src/tag_utils.c:259` | ASan heap-buffer-overflow | WavPack file with APEv2 binary tag item |
| 3 | CWE-190 | Signed integer overflow (uint32→int32) | `src/entropy_utils.c:340` | UBSan signed-integer-overflow | WavPack file with entropy variable log value ≥ 0x2000 |
| 4 | CWE-121 | Stack buffer overflow (undersized buffer) | `src/tag_utils.c:288` | ASan stack-buffer-overflow | WavPack file with ID3v1 tag containing title ≥ 4 bytes |
| 5 | CWE-122 | Heap buffer overflow (wrong pointer offset) | `src/tag_utils.c:435` | ASan heap-buffer-overflow | Any valid WavPack file with an APEv2 tag (triggers on append) |

---

## Bug 1 — Off-by-One Malloc in `read_channel_identities`

**File:** `src/open_utils.c`, line 564
**Harness:** `fuzzing/channel_identities_fuzzer.c`
**Sanitizer:** ASan heap-buffer-overflow (write)

### Change

```diff
- wpc->channel_identities = (unsigned char *)malloc (wpmd->byte_length + 1);
+ wpc->channel_identities = (unsigned char *)malloc (wpmd->byte_length);
```

### Description

`read_channel_identities()` reads per-channel identity bytes from a metadata block and stores them in a heap-allocated buffer. The original code correctly allocated `wpmd->byte_length + 1` bytes to hold the data plus a null terminator. After the injection, `malloc(wpmd->byte_length)` is called instead, allocating exactly `byte_length` bytes with no room for the null terminator. The immediately following line `wpc->channel_identities[wpmd->byte_length] = 0` then writes a null byte one position past the end of the allocation, causing a one-byte heap buffer overflow.

### Trigger Input

```
WavPack block containing ID_CHANNEL_IDENTITIES metadata (ID 0x2b|0x40=0x6b)
with at least one non-zero identity byte. Seed: fuzzing/channel_identities_seed_corpus/seed_01
```

A WavPack file whose block includes `ID_CHANNEL_IDENTITIES` metadata with `byte_length >= 1` and all identity bytes non-zero (required by the validation loop) triggers this bug. The allocation is one byte short, and the subsequent null-terminator write overflows it.

### Reproduction

```bash
./channel_identities_fuzzer fuzzing/channel_identities_seed_corpus/seed_01
```

---

## Bug 2 — memcpy Size Off-by-One in Binary APEv2 Tag Reading

**File:** `src/tag_utils.c`, line 259
**Harness:** `fuzzing/binary_tag_fuzzer.c`
**Sanitizer:** ASan heap-buffer-overflow (write)

### Change

```diff
- memcpy (value, p + isize + 1, vsize);
+ memcpy (value, p + isize + 1, vsize + 1);
```

### Description

`get_ape_tag_item()` retrieves a tag item's value from the in-memory APEv2 tag data. For binary-type items, when the caller supplies a buffer large enough (`vsize <= size`), the function copies the item's value bytes into the caller's buffer. The fuzzer first queries the size by passing `NULL`/`0`, then allocates exactly `malloc(vsize)` bytes, and calls again with `size = vsize`. The injected bug copies `vsize + 1` bytes instead of `vsize`, writing one byte past the end of the `malloc(vsize)` allocation. Since `p + isize + vsize + 1 <= q` is already validated, the source read is in-bounds; only the destination write overflows.

### Trigger Input

```
WavPack file with APEv2 binary tag item (flags bit 1 set, type = BINARY).
Seed: fuzzing/binary_tag_seed_corpus/seed_01
```

Any file containing a binary APEv2 tag item with `vsize >= 1` triggers the bug when `WavpackGetBinaryTagItem()` is called to read the item value.

### Reproduction

```bash
./binary_tag_fuzzer fuzzing/binary_tag_seed_corpus/seed_01
```

---

## Bug 3 — Signed Integer Overflow in `wp_exp2s`

**File:** `src/entropy_utils.c`, line 340
**Harness:** `fuzzing/entropy_fuzzer.c`
**Sanitizer:** UBSan signed-integer-overflow

### Change

```diff
- uint32_t value;
+ int32_t value;
```

### Description

`wp_exp2s()` converts a log-encoded 16-bit integer back to a linear 32-bit value. The local variable `value` originally had type `uint32_t`, making the left-shift `value << ((log - 9) & 0x1f)` well-defined for all inputs. By changing it to `int32_t`, the shift becomes a signed left shift. When the `log` argument is `0x2000` (8192) or greater, `log >> 8` becomes 32 or more, causing `(log - 9) & 0x1f = 23` (for `log = 0x2000`), and `value << 23` with `value >= 0x100` exceeds `INT32_MAX`, constituting undefined behavior caught by UBSan as a signed-integer-overflow. This function is called from `read_entropy_vars()` during WavPack block metadata parsing.

### Trigger Input

```
WavPack block with ID_ENTROPY_VARS metadata (ID 0x05) where the first 16-bit
log value (bytes 0-1 of data) is >= 0x2000 (i.e., high byte >= 0x20).
Seed: fuzzing/entropy_seed_corpus/seed_01
```

A WavPack file with a mono block (`MONO_FLAG` set) containing 6-byte entropy vars metadata where `median[0]`'s log value has high byte ≥ `0x20` triggers the overflow. Specifically, bytes `00 20` (value `0x2000`) for the first median log entry reliably trigger the bug.

### Reproduction

```bash
./entropy_fuzzer fuzzing/entropy_seed_corpus/seed_01
```

---

## Bug 4 — Stack Buffer Overflow in `get_id3_tag_item`

**File:** `src/tag_utils.c`, line 288
**Harness:** `fuzzing/id3_tag_fuzzer.c`
**Sanitizer:** ASan stack-buffer-overflow (write)

### Change

```diff
- char lvalue [64];
+ char lvalue [4];
```

### Description

`get_id3_tag_item()` reads a field from an ID3v1 tag (title, artist, album, etc.) into a stack-allocated string buffer, then returns its length. The buffer `lvalue` was 64 bytes, providing ample room for any ID3v1 field (each at most 30 bytes). The injected change reduces this to 4 bytes. `tagcpy()` is then called with `sizeof(m_tag->id3_tag.title) = 30` as the source size, and will copy up to 30 bytes of non-space/non-null characters into the 4-byte `lvalue`, overflowing the stack buffer by up to 26 bytes. The overflow occurs even on the initial size-query call (with `NULL` destination), because `tagcpy` fills `lvalue` before the null-check.

### Trigger Input

```
WavPack file with an ID3v1 tag (last 128 bytes begin with "TAG") where the
title field contains 4 or more non-space, non-null characters.
Seed: fuzzing/id3_tag_seed_corpus/seed_01
```

A WavPack file with an ID3v1 tag containing title "Hello World!" (12 characters) triggers the overflow. When `WavpackGetTagItem(wpc, "title", ...)` is called, `tagcpy` copies 12 bytes into `lvalue[4]`, overflowing by 8 bytes.

### Reproduction

```bash
./id3_tag_fuzzer fuzzing/id3_tag_seed_corpus/seed_01
```

---

## Bug 5 — Wrong Pointer Offset in `append_ape_tag_item`

**File:** `src/tag_utils.c`, line 435
**Harness:** `fuzzing/append_tag_fuzzer.c`
**Sanitizer:** ASan heap-buffer-overflow (write)

### Change

```diff
- p += m_tag->ape_tag_hdr.length - sizeof (APE_Tag_Hdr) - new_item_len;
+ p += m_tag->ape_tag_hdr.length - sizeof (APE_Tag_Hdr);
```

### Description

`append_ape_tag_item()` appends a new item to an in-memory APEv2 tag by reallocating the data buffer and writing the new item at the correct offset. The original code correctly sets `p` to `base + length - sizeof(APE_Tag_Hdr) - new_item_len`, pointing to the start of the new item's storage area within the allocation. The injected change omits the `- new_item_len` term, advancing `p` by `new_item_len` bytes too far. When subsequent writes of `new_item_len = vsize + isize + 9` bytes begin from this incorrect position, the write extends `new_item_len - 32` bytes past the end of the allocation for any item where `new_item_len > 32` (i.e., `vsize + isize > 23`). The fuzzer triggers this via `WavpackAppendTagItem(wpc, "Title", "Fuzz Me All Night Long", 22)`, where `new_item_len = 5 + 22 + 9 = 36`, causing a 4-byte overflow.

### Trigger Input

```
Any valid WavPack file with an existing APEv2 tag (so MODE_VALID_TAG is set),
causing the fuzzer to append a "Title" item with value "Fuzz Me All Night Long"
(22 bytes), which has new_item_len = 36 > 32.
Seed: fuzzing/append_tag_seed_corpus/seed_01
```

When a WavPack file with an APEv2 tag is opened and the fuzzer calls `WavpackAppendTagItem(wpc, "Artist", ...)` followed by `WavpackAppendTagItem(wpc, "Title", "Fuzz Me All Night Long", 22)`, the second append overflows the heap allocation by 4 bytes.

### Reproduction

```bash
./append_tag_fuzzer fuzzing/append_tag_seed_corpus/seed_01
```

---

## Build Instructions

All harnesses use the libFuzzer interface and must be compiled with Clang:

```bash
cd /path/to/wavpack

# Build the library first (configure with sanitizers):
./configure CC=clang CFLAGS="-fsanitize=address,undefined -fno-sanitize-recover=all -g -O1"
make -j$(nproc)

# Compile a specific harness (replace NAME with the target):
clang -std=c11 \
  -I include \
  -fsanitize=address,undefined \
  -fno-sanitize-recover=all \
  -fsanitize=fuzzer \
  -g -O1 \
  fuzzing/NAME_fuzzer.c \
  src/.libs/libwavpack.a \
  -o NAME_fuzzer

# Run with the seed corpus:
./NAME_fuzzer fuzzing/NAME_seed_corpus/ -max_total_time=60

# Reproduce with a known seed:
./NAME_fuzzer fuzzing/NAME_seed_corpus/seed_01
```

Available harnesses:

| Harness | Targets |
|---------|---------|
| `channel_identities_fuzzer` | Bug 1 |
| `binary_tag_fuzzer` | Bug 2 |
| `entropy_fuzzer` | Bug 3 |
| `id3_tag_fuzzer` | Bug 4 |
| `append_tag_fuzzer` | Bug 5 |

---

## Expected Sanitizer Output

### Bug 1 — Heap buffer overflow (off-by-one malloc)
```
=================================================================
==ASAN: heap-buffer-overflow on address ... at pc ...
WRITE of size 1 at ... thread T0
    #0 read_channel_identities src/open_utils.c:566
    #1 process_metadata src/open_utils.c:...
    #2 unpack_init src/open_utils.c:...
    #3 WavpackOpenFileInputEx64 src/open_utils.c:...
    #4 LLVMFuzzerTestOneInput fuzzing/channel_identities_fuzzer.c:...
```

### Bug 2 — Heap buffer overflow (memcpy size+1)
```
=================================================================
==ASAN: heap-buffer-overflow on address ... at pc ...
WRITE of size N at ... thread T0
    #0 get_ape_tag_item src/tag_utils.c:259
    #1 WavpackGetBinaryTagItem src/tag_utils.c:...
    #2 LLVMFuzzerTestOneInput fuzzing/binary_tag_fuzzer.c:...
```

### Bug 3 — UBSan signed-integer-overflow
```
src/entropy_utils.c:350: runtime error: left shift of 256 by 23 places cannot be represented in type 'int'
SUMMARY: UndefinedBehaviorSanitizer: undefined-behavior src/entropy_utils.c:350
```

### Bug 4 — Stack buffer overflow
```
=================================================================
==ASAN: stack-buffer-overflow on address ... at pc ...
WRITE of size 12 at ... thread T0
    #0 tagcpy src/tag_utils.c:...
    #1 get_id3_tag_item src/tag_utils.c:299
    #2 WavpackGetTagItem src/tag_utils.c:...
    #3 LLVMFuzzerTestOneInput fuzzing/id3_tag_fuzzer.c:...
```

### Bug 5 — Heap buffer overflow (wrong pointer)
```
=================================================================
==ASAN: heap-buffer-overflow on address ... at pc ...
WRITE of size 36 at ... thread T0
    #0 append_ape_tag_item src/tag_utils.c:447
    #1 WavpackAppendTagItem src/tag_utils.c:...
    #2 LLVMFuzzerTestOneInput fuzzing/append_tag_fuzzer.c:...
```

---

## Build System Integration

### CMakeLists.txt

```cmake
add_fuzzer(channel_identities_fuzzer)
add_fuzzer(binary_tag_fuzzer)
add_fuzzer(entropy_fuzzer)
add_fuzzer(id3_tag_fuzzer)
add_fuzzer(append_tag_fuzzer)
```

### Makefile (OSS-Fuzz)

```makefile
all: \
  $(OUT)/channel_identities_fuzzer \
  $(OUT)/channel_identities_fuzzer_seed_corpus.zip \
  $(OUT)/channel_identities_fuzzer.options \
  $(OUT)/binary_tag_fuzzer \
  $(OUT)/binary_tag_fuzzer_seed_corpus.zip \
  $(OUT)/binary_tag_fuzzer.options \
  $(OUT)/entropy_fuzzer \
  $(OUT)/entropy_fuzzer_seed_corpus.zip \
  $(OUT)/entropy_fuzzer.options \
  $(OUT)/id3_tag_fuzzer \
  $(OUT)/id3_tag_fuzzer_seed_corpus.zip \
  $(OUT)/id3_tag_fuzzer.options \
  $(OUT)/append_tag_fuzzer \
  $(OUT)/append_tag_fuzzer_seed_corpus.zip \
  $(OUT)/append_tag_fuzzer.options
```

---

## Changelog

### 2026-03-14 — Initial bug injection

Added 5 intentional vulnerabilities across `src/open_utils.c`, `src/tag_utils.c`, and `src/entropy_utils.c`. Created 5 libFuzzer harnesses and 5 seed corpus directories.

### 2026-03-14 — Connected harnesses

Added seed corpus directories with targeted binary seed files for each bug. Seeds are biased inputs that directly exercise the vulnerable code paths.

| Harness | Seed file | Seed bytes (hex) |
|---------|-----------|------------------|
| `channel_identities_fuzzer` | `channel_identities_seed_corpus/seed_01` | `77 76 70 6B 20 00 00 00 07 04 00 00 00 00 00 00 00 00 00 00 00 00 00 00 04 10 00 00 00 00 00 00 0D 01 03 00 6B 01 02 00` (40 bytes) |
| `binary_tag_fuzzer` | `binary_tag_seed_corpus/seed_01` | 88-byte WavPack block + APEv2 binary tag |
| `entropy_fuzzer` | `entropy_seed_corpus/seed_01` | `77 76 70 6B 24 00 00 00 07 04 00 00 00 00 00 00 00 00 00 00 00 00 00 00 04 10 00 00 00 00 00 00 0D 01 01 00 05 03 00 20 00 00 00 00` (44 bytes) |
| `id3_tag_fuzzer` | `id3_tag_seed_corpus/seed_01` | 40-byte WavPack block + 128-byte ID3v1 tag |
| `append_tag_fuzzer` | `append_tag_seed_corpus/seed_01` | Same as binary_tag_seed (has APEv2 tag for MODE_VALID_TAG) |

---

*This report documents intentional research vulnerabilities.
The upstream WavPack library does not contain these bugs.*
