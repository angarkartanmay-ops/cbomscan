"""Parse ESP32 firmware: app images (.bin), full flash dumps, and stripped ELF files."""

import hashlib
import struct
import zlib
from dataclasses import dataclass, field
from pathlib import Path
from typing import List, Optional

ESP_IMAGE_MAGIC = 0xE9
APP_DESC_MAGIC = 0xABCD5432
SIG_BLOCK_MAGIC = 0xE7
SIG_BLOCK_SIZE = 1216
PARTITION_TABLE_OFFSET = 0x8000
PARTITION_MAGIC = 0x50AA

CHIP_IDS = {0: "ESP32", 2: "ESP32-S2", 5: "ESP32-C3", 9: "ESP32-S3", 12: "ESP32-C2", 13: "ESP32-C6",
            16: "ESP32-H2", 18: "ESP32-P4", 23: "ESP32-C5", 20: "ESP32-C61"}

ESP32_REGIONS = [
    (0x3F400000, 0x3F800000, "DROM", "data"),
    (0x3FF80000, 0x3FF82000, "RTC_DRAM", "data"),
    (0x3FFAE000, 0x40000000, "DRAM", "data"),
    (0x40070000, 0x400A0000, "IRAM", "code"),
    (0x400C0000, 0x400C2000, "RTC_IRAM", "code"),
    (0x400C2000, 0x40C00000, "IROM", "code"),
    (0x50000000, 0x50002000, "RTC_DATA", "data"),
]


@dataclass
class Segment:
    index: int
    addr: int
    data: bytes
    file_offset: int
    region: str
    kind: str

    @property
    def end(self):
        return self.addr + len(self.data)

    def contains(self, addr):
        return self.addr <= addr < self.end


@dataclass
class SignatureBlock:
    index: int
    file_offset: int
    scheme: str
    key_bits: int
    curve: Optional[str]
    public_key: bytes
    crc_ok: bool
    digest: bytes


@dataclass
class Firmware:
    path: str
    raw: bytes
    container: str
    chip: str = "unknown"
    entry: int = 0
    segments: List[Segment] = field(default_factory=list)
    app_desc: dict = field(default_factory=dict)
    signature_blocks: List[SignatureBlock] = field(default_factory=list)
    partitions: List[dict] = field(default_factory=list)
    app_offset: int = 0
    image_size: int = 0
    notes: List[str] = field(default_factory=list)

    @property
    def sha256(self):
        return hashlib.sha256(self.raw).hexdigest()

    def segment_at(self, addr):
        for s in self.segments:
            if s.contains(addr):
                return s
        return None

    def read(self, addr, n):
        s = self.segment_at(addr)
        if s is None:
            return None
        off = addr - s.addr
        return s.data[off:off + n]


def classify_addr(addr):
    for lo, hi, name, kind in ESP32_REGIONS:
        if lo <= addr < hi:
            return name, kind
    return "UNKNOWN", "data"


def _cstr(b):
    return b.split(b"\0", 1)[0].decode("ascii", "replace")


def parse_app_desc(data):
    if len(data) < 256 or struct.unpack_from("<I", data, 0)[0] != APP_DESC_MAGIC:
        return {}
    return {"secure_version": struct.unpack_from("<I", data, 4)[0], "version": _cstr(data[16:48]),
            "project_name": _cstr(data[48:80]), "time": _cstr(data[80:96]), "date": _cstr(data[96:112]),
            "idf_ver": _cstr(data[112:144]), "app_elf_sha256": data[144:176].hex()}


def parse_app_image(raw, base=0):
    if len(raw) < base + 24 or raw[base] != ESP_IMAGE_MAGIC:
        raise ValueError("not an ESP app image (missing 0xE9 magic)")
    nseg = raw[base + 1]
    entry = struct.unpack_from("<I", raw, base + 4)[0]
    chip_id = struct.unpack_from("<H", raw, base + 12)[0]
    hash_appended = raw[base + 23]
    off = base + 24
    segs = []
    for i in range(nseg):
        if off + 8 > len(raw):
            raise ValueError(f"truncated image at segment {i}")
        addr, size = struct.unpack_from("<II", raw, off)
        data = raw[off + 8: off + 8 + size]
        if len(data) != size:
            raise ValueError(f"segment {i} truncated")
        region, kind = classify_addr(addr)
        if addr != 0:
            segs.append(Segment(i, addr, bytes(data), off + 8, region, kind))
        off += 8 + size
    off += 16 - (off - base) % 16
    if hash_appended:
        off += 32
    fw = Firmware(path="", raw=raw, container="app-image", chip=CHIP_IDS.get(chip_id, f"chip-id-{chip_id}"),
                  entry=entry, segments=segs, app_offset=base, image_size=off - base)
    drom = [s for s in segs if s.region == "DROM"]
    if drom:
        fw.app_desc = parse_app_desc(drom[0].data[:256])
    fw.signature_blocks = find_signature_blocks(raw, off)
    return fw


def find_signature_blocks(raw, image_end):
    blocks = []
    start = (image_end + 0xFFF) & ~0xFFF
    for cand in sorted({start, image_end}):
        for i in range(3):
            o = cand + i * SIG_BLOCK_SIZE
            if o + SIG_BLOCK_SIZE > len(raw) or raw[o] != SIG_BLOCK_MAGIC:
                break
            blk = raw[o:o + SIG_BLOCK_SIZE]
            sb = parse_signature_block(blk, i, o)
            if sb is None:
                break
            blocks.append(sb)
        if blocks:
            break
    return blocks


def parse_signature_block(blk, index, offset):
    version = blk[1]
    crc_ok = zlib.crc32(blk[:1196]) & 0xFFFFFFFF == struct.unpack_from("<I", blk, 1196)[0]
    if version == 0x02:
        digest = blk[4:36]
        n_le = blk[36:36 + 384]
        n = int.from_bytes(n_le, "little")
        return SignatureBlock(index, offset, "RSA-PSS", n.bit_length(), None,
                              n.to_bytes(384, "big"), crc_ok, digest)
    if version == 0x03:
        sha_ver = blk[2]
        dlen = 48 if sha_ver == 1 else 32
        digest = blk[4:4 + dlen]
        curve_id = blk[4 + dlen]
        curves = {1: ("P-192", 24), 2: ("P-256", 32), 3: ("P-384", 48)}
        if curve_id not in curves:
            return None
        cname, clen = curves[curve_id]
        point = blk[5 + dlen: 5 + dlen + 2 * clen]
        return SignatureBlock(index, offset, "ECDSA", clen * 8, cname, point, crc_ok, digest)
    return None


def parse_partition_table(raw):
    parts = []
    for i in range(0, 0xC00, 32):
        o = PARTITION_TABLE_OFFSET + i
        if o + 32 > len(raw):
            break
        magic = struct.unpack_from("<H", raw, o)[0]
        if magic != PARTITION_MAGIC:
            break
        ptype, subtype, poff, psize = struct.unpack_from("<BBII", raw, o + 2)
        label = _cstr(raw[o + 12:o + 28])
        parts.append({"label": label, "type": ptype, "subtype": subtype, "offset": poff, "size": psize})
    return parts


def parse_elf(raw):
    from elftools.elf.elffile import ELFFile
    import io
    elf = ELFFile(io.BytesIO(raw))
    segs = []
    for i, sec in enumerate(elf.iter_sections()):
        if not (sec["sh_flags"] & 0x2) or sec["sh_type"] == "SHT_NOBITS" or sec["sh_size"] == 0:
            continue
        region, kind = classify_addr(sec["sh_addr"])
        if sec["sh_flags"] & 0x4:
            kind = "code"
        segs.append(Segment(i, sec["sh_addr"], sec.data(), sec["sh_offset"], region, kind))
    fw = Firmware(path="", raw=raw, container="elf", chip="ESP32 (assumed)", entry=elf["e_entry"], segments=segs)
    drom = [s for s in segs if s.region == "DROM"]
    if drom:
        fw.app_desc = parse_app_desc(drom[0].data[:256])
    if elf.get_section_by_name(".symtab") is not None:
        fw.notes.append("ELF has a symbol table; cbomscan ignores symbols so results match a stripped binary")
    return fw


def load(path):
    raw = Path(path).read_bytes()
    if raw[:4] == b"\x7fELF":
        fw = parse_elf(raw)
    elif raw and raw[0] == ESP_IMAGE_MAGIC:
        fw = parse_app_image(raw)
    elif len(raw) > PARTITION_TABLE_OFFSET + 32 and struct.unpack_from("<H", raw, PARTITION_TABLE_OFFSET)[0] == PARTITION_MAGIC:
        parts = parse_partition_table(raw)
        apps = [p for p in parts if p["type"] == 0 and p["offset"] < len(raw) and raw[p["offset"]] == ESP_IMAGE_MAGIC]
        if not apps:
            raise ValueError("flash dump has a partition table but no readable app partition")
        app = apps[0]
        fw = parse_app_image(raw[:app["offset"] + app["size"]], app["offset"])
        fw.container = "flash-dump"
        fw.partitions = parts
        fw.notes.append(f"scanned app partition '{app['label']}' at 0x{app['offset']:x}"
                        + (f"; {len(apps) - 1} other app partition(s) not scanned" if len(apps) > 1 else ""))
    else:
        raise ValueError("unrecognised input: expected ESP app image (0xE9), flash dump with partition table, or ELF")
    fw.path = str(path)
    fw.raw = raw
    return fw
