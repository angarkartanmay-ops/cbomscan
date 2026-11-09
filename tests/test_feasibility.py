import json
import subprocess
import sys
from pathlib import Path

from cbomscan import feasibility as F
from cbomscan.cbom import build_cbom
from cbomscan.detect import scan
from cbomscan.image import load
from cbomscan.validate import validate

ROOT = Path(__file__).resolve().parent.parent
SIGNED = ROOT / "dataset/out/samples/m36rom__Os__full_stack__sbv2_rsa3072/firmware.bin"
HELD = ROOT / "dataset/heldout/samples/https_mbedtls__O2/firmware.bin"


def by_action(actions):
    return {a["id"]: a for a in actions}


def test_measured_sizes_match_truth_files():
    for name, m in F.MEASURED.items():
        truth = json.loads((ROOT / "dataset/out_pqc/samples" / m["sample"] / "truth.json").read_text())
        total = sum(r["end"] - r["start"] for rs in truth["family_ranges"].values() for r in rs)
        assert total == m["bytes"], name


def test_isa_by_chip():
    assert F.isa("ESP32") == "xtensa" and F.isa("ESP32-S3") == "xtensa"
    assert F.isa("ESP32-C3") == "riscv" and F.isa("ESP32-C6") == "riscv"
    assert F.isa("ESP32 (assumed)") == "xtensa"


def test_signed_esp32_boot_migration_is_blocked():
    res = scan(load(SIGNED))
    actions, scope = F.for_result(res)
    sig = by_action(actions)["signatures"]
    assert "secure-boot" in sig["triggeredBy"] and sig["verdict"] == "blocked"
    checks = {c["check"]: c for c in sig["checks"]}
    assert checks["Flash headroom"]["status"] == "ok"
    assert "assumed 1 MB" in checks["Flash headroom"]["assumption"]
    assert scope["isa"] == "xtensa"


def test_partition_table_size_is_used(tmp_path):
    dump = tmp_path / "dump.bin"
    subprocess.run([sys.executable, str(ROOT / "dataset/make_flash_dump.py"), str(SIGNED), str(dump)], check=True)
    fw = load(dump)
    size, source = F.app_partition(fw)
    assert size == 0x100000 and "partition table" in source


def test_old_idf_warns():
    res = scan(load(HELD))
    v = F.idf_major(res.firmware)
    assert v is not None and v[0] == 5
    ka = by_action(F.for_result(res)[0])["key-agreement"]
    idf = next(c for c in ka["checks"] if c["check"] == "ESP-IDF version")
    assert idf["status"] == "warn"


def test_other_chip_skips_esp32_only_rules(tmp_path):
    raw = bytearray(SIGNED.read_bytes())
    raw[12:14] = (5).to_bytes(2, "little")
    p = tmp_path / "c3.bin"
    p.write_bytes(bytes(raw))
    fw = load(p)
    assert fw.chip == "ESP32-C3"
    res = scan(fw)
    assert "hw" not in res.groups and not any(e.group == "hw" for e in res.evidence)
    assert any("accelerator-register rules skipped" in n for n in fw.notes)
    sig = by_action(F.for_result(res)[0])["signatures"]
    boot = next(c for c in sig["checks"] if c["check"] == "Post-quantum boot verification")
    assert boot["status"] == "ok"


def test_cbom_with_feasibility_is_schema_valid():
    bom = build_cbom(scan(load(SIGNED)))
    assert validate(bom) == []
    names = {p["name"] for p in bom["metadata"]["properties"]}
    assert "cbomscan:feasibility:signatures" in names or "feasibility:signatures" in names
