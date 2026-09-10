#!/usr/bin/env python3
"""Extract the native TU102 FWSEC falcon app from a CMP 50HX PROM dump.

Walks the VBIOS like the open-gpu-kernel-modules 610.43.03 parser
(kernel_gsp_fwsec.c + kernel_gsp_vbios_tu102.c):

  ROM -> PCI image chain (NPDE sub-image chaining) -> BIT header
      -> FALCON_DATA token (id 0x70, v2) -> falcon ucode table
      -> entry appId FWSEC_PROD (0x85) -> FALCON_UCODE_DESC_V2
      -> code+data blob

The one ROM-specific input is the base added to the table/desc pointers
(the driver's expansionRomOffset). For the CMP 50HX 90.02.60.00.1A layout
(x86@0 size 0xf800, EFI@0xf800 size 0x11000) the working base is 0x11000;
the script derives it by trying candidates and validating the table header
and every entry's desc magic, so it stays correct if the layout shifts.

Entry layout found on this ROM (differs from the driver struct's field
order in name only): [appId u8][ver u8][descPtr u32].

Usage:
  python3 extract_fwsec.py CMP50HX.90.02.60.00.1A.live.rom blobs/

Writes blobs/fwsec_50hx_prod.bin (code||data as stored), optional _dbg,
and blobs/fwsec_50hx_desc.json with the V2 descriptor fields.
"""

import hashlib
import json
import struct
import sys
from pathlib import Path

BIT_HEADER_ID = 0xB8FF
BIT_HEADER_SIG = 0x00544942  # "BIT\0"
BIT_TOKEN_FALCON_DATA = 0x70
FWSEC_APPID_DBG = 0x45
FWSEC_APPID_PROD = 0x85
PCIR_BLOCK = 512  # image lengths are in 512-byte units

DESC_V2_MAGIC = b"\x01\x02"  # flags.version_available=1, descVersion=2


def pci_image_sizes(rom):
    """Chain PCI images with NPDE sub-image lengths; return [(offset, size)]."""
    images = []
    curr = 0
    while len(images) < 16:
        if rom[curr : curr + 2] != b"\x55\xaa":
            break
        pd = curr + struct.unpack_from("<H", rom, curr + 0x18)[0]
        if rom[pd : pd + 4] != b"PCIR":
            break
        img_len = struct.unpack_from("<H", rom, pd + 0x10)[0]
        dlen = struct.unpack_from("<H", rom, pd + 0x0A)[0]
        last = rom[pd + 0x15] & 0x80
        sub = img_len
        extat = (pd + dlen + 0xF) & ~0xF
        if rom[extat : extat + 4] == b"NPDE":
            rev = struct.unpack_from("<H", rom, extat + 4)[0]
            if rev in (0x100, 0x101):
                elen = struct.unpack_from("<H", rom, extat + 6)[0]
                sub = struct.unpack_from("<H", rom, extat + 8)[0]
                if elen >= 0x0C:
                    last = rom[extat + 0x0A] & 0x80
                elif sub < img_len:
                    last = 0
        images.append((curr, sub * PCIR_BLOCK))
        if last:
            break
        curr += sub * PCIR_BLOCK
    return images


def find_bit_header(rom, size):
    for addr in range(0, size - 3):
        if (
            struct.unpack_from("<H", rom, addr)[0] == BIT_HEADER_ID
            and struct.unpack_from("<I", rom, addr + 2)[0] == BIT_HEADER_SIG
        ):
            header_size = rom[addr + 8]
            if header_size and sum(rom[addr : addr + header_size]) & 0xFF == 0:
                return addr
    raise ValueError("BIT header not found")


def falcon_data_ptr(rom, bit_addr):
    header_size = rom[bit_addr + 8]
    token_size = rom[bit_addr + 9]
    entries = struct.unpack_from("<H", rom, bit_addr + 10)[0]
    for i in range(entries):
        tok = bit_addr + header_size + i * token_size
        if (
            rom[tok] == BIT_TOKEN_FALCON_DATA
            and rom[tok + 1] == 2
            and struct.unpack_from("<H", rom, tok + 2)[0] >= 4
        ):
            return struct.unpack_from("<I", rom, struct.unpack_from("<H", rom, tok + 4)[0])[0]
    raise ValueError("FALCON_DATA v2 token not found")


def valid_table(rom, base, table_ptr):
    """True if table at base+table_ptr is sane and FWSEC entries hit V2 descs."""
    t = base + table_ptr
    if t + 6 > len(rom):
        return False
    ver, hdr, ent, cnt = rom[t], rom[t + 1], rom[t + 2], rom[t + 3]
    if ver != 1 or hdr < 6 or ent < 6 or not (1 <= cnt <= 32):
        return False
    fwsec = 0
    for e in range(cnt):
        o = t + hdr + e * ent
        if o + 6 > len(rom):
            return False
        app_id = rom[o]
        ptr = struct.unpack_from("<I", rom, o + 2)[0]
        if ptr == 0:
            continue
        if app_id not in (FWSEC_APPID_PROD, FWSEC_APPID_DBG):
            continue
        d = base + ptr
        if d + 4 > len(rom):
            return False
        v_desc = struct.unpack_from("<I", rom, d)[0]
        if not (v_desc & 1) or ((v_desc >> 8) & 0xFF) != 2:
            return False
        fwsec += 1
    return fwsec > 0


def parse_desc_v2(rom, desc_off):
    names = [
        "vDesc", "StoredSize", "UncompressedSize", "VirtualEntry",
        "InterfaceOffset", "IMEMPhysBase", "IMEMLoadSize", "IMEMVirtBase",
        "IMEMSecBase", "IMEMSecSize", "DMEMOffset", "DMEMPhysBase",
        "DMEMLoadSize", "altIMEMLoadSize", "altDMEMLoadSize",
    ]
    return dict(zip(names, struct.unpack_from("<15I", rom, desc_off)))


def main():
    if len(sys.argv) != 3:
        print(__doc__)
        return 2
    rom = Path(sys.argv[1]).read_bytes()
    outdir = Path(sys.argv[2])
    outdir.mkdir(parents=True, exist_ok=True)

    images = pci_image_sizes(rom)
    print(f"PCI images: {[(hex(o), hex(s)) for o, s in images]}")

    bit_addr = find_bit_header(rom, len(rom))
    table_ptr = falcon_data_ptr(rom, bit_addr)
    print(f"BIT@0x{bit_addr:x} FALCON_DATA -> table ptr 0x{table_ptr:x}")

    # The pointer base (driver: expansionRomOffset). Try 0 plus every image
    # offset/size/size-delta; accept the first base whose table validates.
    candidates = [0] + [v for o, s in images for v in (o, s, o + s)]
    base = next((c for c in sorted(set(candidates)) if valid_table(rom, c, table_ptr)), None)
    if base is None:
        raise SystemExit("no valid pointer base found for the falcon ucode table")
    print(f"validated pointer base = 0x{base:x} (table @0x{base + table_ptr:x})")

    t = base + table_ptr
    hdr, ent, cnt = rom[t + 1], rom[t + 2], rom[t + 3]
    entries = []
    for e in range(cnt):
        o = t + hdr + e * ent
        app_id, ver = rom[o], rom[o + 1]
        ptr = struct.unpack_from("<I", rom, o + 2)[0]
        if ptr:
            entries.append((app_id, base + ptr))
        print(f"  [{e:2d}] appId=0x{app_id:02x} ver=0x{ver:02x} desc=0x{ptr:06x}")

    results = {}
    for app_id, tag in ((FWSEC_APPID_PROD, "prod"), (FWSEC_APPID_DBG, "dbg")):
        hit = next((d for a, d in entries if a == app_id), None)
        if hit is None:
            print(f"FWSEC_{tag.upper()} (0x{app_id:02x}) not present")
            continue
        d = parse_desc_v2(rom, hit)
        for k, v in d.items():
            print(f"  {tag}.{k:16s} = 0x{v:x}")
        code_off = hit + 0x3C
        code = rom[code_off : code_off + d["IMEMLoadSize"]]
        data_off = code_off + d["DMEMOffset"]
        data = rom[data_off : data_off + d["DMEMLoadSize"]]
        if len(code) != d["IMEMLoadSize"] or len(data) != d["DMEMLoadSize"]:
            raise SystemExit("FWSEC blob runs past ROM end")
        blob = code + data
        out = outdir / f"fwsec_50hx_{tag}.bin"
        out.write_bytes(blob)
        results[tag] = {
            "rom_desc_offset": f"0x{hit:x}",
            "rom_code_offset": f"0x{code_off:x}",
            "rom_data_offset": f"0x{data_off:x}",
            "code_data_contiguous": d["DMEMOffset"] == d["IMEMLoadSize"],
            **{k: f"0x{v:x}" for k, v in d.items()},
            "blob_size": len(blob),
            "blob_sha256": hashlib.sha256(blob).hexdigest(),
        }
        print(f"wrote {out} ({len(blob)} B, sha256 {results[tag]['blob_sha256']})")

    (outdir / "fwsec_50hx_desc.json").write_text(
        json.dumps(
            {
                "source": str(sys.argv[1]),
                "pointer_base": f"0x{base:x}",
                "bit_header": f"0x{bit_addr:x}",
                "table": f"0x{base + table_ptr:x}",
                **results,
            },
            indent=2,
        )
        + "\n"
    )
    return 0


if __name__ == "__main__":
    sys.exit(main())
