"""Tests for the investigation probes (app/tools/probes.py) using generated
artifacts: EXIF-GPS JPEG, a handcrafted PCAP, and minimal Windows containers.

External-tool tests skip when the tool is missing on the host so the suite
stays green on CI runners without the forensics toolchain.
"""

from __future__ import annotations

import shutil
import struct
import subprocess
from pathlib import Path

import pytest

from app.security import format_error_response
from app.tools.probes import (
    duachuot_disk_probe,
    duachuot_forensics_triage,
    duachuot_media_probe,
    duachuot_mem_probe,
    duachuot_ocr_probe,
    duachuot_pcap_probe,
    duachuot_stego_probe,
    duachuot_win_probe,
)

requires = pytest.mark.skipif


def _has(*tools: str) -> bool:
    return all(shutil.which(tool) for tool in tools)


# ---------------------------------------------------------------- artifacts


def _make_jpeg_with_gps(path: Path) -> None:
    subprocess.run(  # noqa: S603
        ["convert", "-size", "64x64", "xc:red", str(path)],
        check=True,
        capture_output=True,
        timeout=30,
    )
    subprocess.run(  # noqa: S603
        [
            "exiftool", "-overwrite_original",
            "-GPSLatitude=21.02906", "-GPSLatitudeRef=N",
            "-GPSLongitude=105.85367", "-GPSLongitudeRef=E",
            "-GPSAltitude=5", "-GPSDOP=1.5",
            str(path),
        ],
        check=True,
        capture_output=True,
        timeout=30,
    )


def _frame(payload: bytes, sport: int = 5353, dport: int = 53) -> bytes:
    eth = b"\x00\x11\x22\x33\x44\x55\x66\x77\x88\x99\xaa\xbb\x08\x00"
    udp = struct.pack(">HHHH", sport, dport, 8 + len(payload), 0) + payload
    ip = struct.pack(
        ">BBHHHBBH4s4s",
        0x45, 0, 20 + len(udp), 1, 0, 64, 17, 0,
        bytes([10, 0, 0, 2]),
        bytes([8, 8, 8, 8]),
    )
    return eth + ip + udp


def _dns_query(name: str) -> bytes:
    header = struct.pack(">HHHHHH", 0x1234, 0x0100, 1, 0, 0, 0)
    question = b"".join(
        bytes([len(label)]) + label.encode() for label in name.split(".")
    ) + b"\x00"
    return header + question + struct.pack(">HH", 1, 1)


def _make_pcap(path: Path) -> None:
    frames = [
        _frame(_dns_query("example.com")),
        _frame(b"$GPRMC,225446,A,4916.45,N,12311.12,W,000.5,054.7,191194,020.3,E*68", sport=4567, dport=4567),
    ]
    with open(path, "wb") as handle:
        handle.write(struct.pack("<IHHiIII", 0xA1B2C3D4, 2, 4, 0, 0, 65535, 1))
        for ts, frame in enumerate(frames):
            handle.write(struct.pack("<IIII", ts, 0, len(frame), len(frame)))
            handle.write(frame)


def _make_lnk(path: Path) -> None:
    raw = bytearray(b"\x4c\x00\x00\x00" + b"\x00" * 76)
    raw[76:78] = struct.pack("<H", 4)
    raw += struct.pack("<I", 0x0000000C)
    for text in ("C:\\Windows\\notepad.exe", "flag_hint.txt"):
        encoded = text.encode("utf-16-le")
        raw += struct.pack("<H", len(encoded)) + encoded
    path.write_bytes(bytes(raw))


def _make_hive(path: Path) -> None:
    path.write_bytes(b"regf" + b"\x00" * 16 + b"SOFTWARE" + b"\x00" * 32)


def _make_prefetch(path: Path) -> None:
    path.write_bytes(b"MAM\x04" + b"\x00" * 32 + b"NOTEPAD.EXE" + b"\x00" * 32)


# ---------------------------------------------------------------- media + geo


@requires(not _has("convert", "exiftool"), reason="ImageMagick/exiftool missing")
def test_media_probe_extracts_exif_gps(tmp_path: Path) -> None:
    image = tmp_path / "gps.jpg"
    _make_jpeg_with_gps(image)
    result = duachuot_media_probe(str(image))
    assert result["ok"] is True
    assert result["exiftool"]["exit_code"] == 0
    assert "GPSLatitude" in result["metadata"]
    assert float(result["metadata"]["GPSLatitude"]) == pytest.approx(21.02906, abs=1e-4)


@requires(not _has("convert", "exiftool"), reason="ImageMagick/exiftool missing")
def test_geo_extract_roundtrip_from_generated_jpeg(tmp_path: Path) -> None:
    from app.tools.geo_tools import duachuot_geo_extract

    image = tmp_path / "gps.jpg"
    _make_jpeg_with_gps(image)
    result = duachuot_geo_extract(str(image), cross_check=True)
    assert result["ok"] is True
    gps = result["gps"]
    assert gps["lat"] == pytest.approx(21.02906, abs=1e-4)
    assert gps["lon"] == pytest.approx(105.85367, abs=1e-4)
    assert "accuracy" in result and "timezone" in result and "landmarks" in result


def test_media_probe_missing_tool_is_blocker(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(shutil, "which", lambda name: None)
    result = duachuot_media_probe(str(tmp_path / "nope.jpg"))
    assert result["ok"] is False
    assert "not available" in str(result["error"])


# ---------------------------------------------------------------- pcap


@requires(not _has("tshark"), reason="tshark missing")
def test_pcap_probe_parses_crafted_capture(tmp_path: Path) -> None:
    capture = tmp_path / "capture.pcap"
    _make_pcap(capture)
    result = duachuot_pcap_probe(str(capture))
    assert result["ok"] is True
    assert result["file"]["exit_code"] == 0
    assert result["conversations"]["exit_code"] == 0
    assert "example.com" in result["dns_queries"]["stdout"]
    assert "GPRMC" in result["geo_hints"]["hits"]


# ---------------------------------------------------------------- disk + memory


@requires(not _has("fls", "fsstat"), reason="sleuthkit missing")
def test_disk_probe_structure(tmp_path: Path) -> None:
    bogus = tmp_path / "not-a-disk.img"
    bogus.write_bytes(b"\x00" * 4096)
    result = duachuot_disk_probe(str(bogus))
    assert result["ok"] is True
    assert {"file", "fsstat", "fls"} <= set(result)
    assert result["fls"]["exit_code"] != 0  # not a real image, but probe must not crash


def test_mem_probe_missing_vol_is_blocker(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    real_which = shutil.which
    monkeypatch.setattr(shutil, "which", lambda name: None if name == "vol" else real_which(name))
    result = duachuot_mem_probe(str(tmp_path / "mem.raw"))
    assert result["ok"] is False
    assert result["error"]["code"] == "FILE_NOT_FOUND"
    assert "vol" in result["error"]["message"]


# ---------------------------------------------------------------- stego + ocr


@requires(not _has("binwalk"), reason="binwalk missing")
def test_stego_probe_structure(tmp_path: Path) -> None:
    carrier = tmp_path / "carrier.jpg"
    subprocess.run(  # noqa: S603
        ["convert", "-size", "64x64", "xc:blue", str(carrier)],
        check=True,
        capture_output=True,
        timeout=30,
    )
    result = duachuot_stego_probe(str(carrier))
    assert result["ok"] is True
    assert {"binwalk", "steghide_info"} <= set(result)


@requires(not _has("convert", "tesseract"), reason="ImageMagick/tesseract missing")
def _tesseract_has_eng() -> bool:
    if shutil.which("tesseract") is None:
        return False
    out = subprocess.run(  # noqa: S603
        ["tesseract", "--list-langs"], capture_output=True, text=True
    ).stdout.split()
    return "eng" in out


@pytest.mark.skipif(
    not _tesseract_has_eng(),
    reason="tesseract eng traineddata missing",
)
def test_ocr_probe_reads_rendered_text(tmp_path: Path) -> None:
    image = tmp_path / "text.png"
    subprocess.run(  # noqa: S603
        [
            "convert", "-size", "300x80", "xc:white",
            "-pointsize", "28", "-fill", "black",
            "-draw", "text 20,50 'HELLO CTF'",
            str(image),
        ],
        check=True,
        capture_output=True,
        timeout=30,
    )
    result = duachuot_ocr_probe(str(image))
    assert result["ok"] is True
    assert result["tesseract"]["exit_code"] == 0
    assert "HELLO" in result["tesseract"]["stdout"].upper()


# ---------------------------------------------------------------- windows


def test_win_probe_parses_lnk(tmp_path: Path) -> None:
    lnk = tmp_path / "shortcut.lnk"
    _make_lnk(lnk)
    result = duachuot_win_probe(str(lnk), kind="lnk")
    assert result["ok"] is True
    assert any("notepad" in s.lower() for s in result["lnk"]["link_strings"])


def test_win_probe_parses_hive(tmp_path: Path) -> None:
    hive = tmp_path / "SAM"
    _make_hive(hive)
    result = duachuot_win_probe(str(hive), kind="hive")
    assert result["ok"] is True
    assert result["hive"]["signature"] == "regf"
    assert "SOFTWARE" in result["hive"]["strings_hint"]


def test_win_probe_parses_prefetch(tmp_path: Path) -> None:
    prefetch = tmp_path / "NOTEPAD.EXE-1.pf"
    _make_prefetch(prefetch)
    result = duachuot_win_probe(str(prefetch), kind="prefetch")
    assert result["ok"] is True
    assert result["prefetch"]["signature"] == "MAM\\x04"
    assert isinstance(result["prefetch"]["strings_hint"], list)


def test_win_probe_unknown_container_notes_signature(tmp_path: Path) -> None:
    unknown = tmp_path / "random.bin"
    unknown.write_bytes(b"\xde\xad\xbe\xef" + b"\x00" * 16)
    result = duachuot_win_probe(str(unknown), kind="auto")
    assert result["ok"] is True
    assert "unknown container" in result["note"]


def test_format_error_response_contract() -> None:
    response = format_error_response(FileNotFoundError("missing tool 'vol'"))
    assert response["ok"] is False
    assert "vol" in str(response["error"])


def test_pcap_probe_pure_python_dissection(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    real_which = shutil.which
    monkeypatch.setattr(shutil, "which", lambda name: None if name == "tshark" else real_which(name))
    capture = tmp_path / "pure.pcap"
    _make_pcap(capture)
    result = duachuot_pcap_probe(str(capture))
    assert result["ok"] is True
    assert result["conversations"]["exit_code"] == 0
    assert "example.com" in result["dns_queries"]["stdout"]
    assert "GPRMC" in result["geo_hints"]["hits"]
    assert result["summary"]["packet_count"] == 2


def test_forensics_triage_detects_embedded_and_hashes(tmp_path: Path) -> None:
    artifact = tmp_path / "evidence.bin"
    content = bytearray(b"\xff\xd8\xff\xe0\x00\x10JFIF\x00" + b"\x00" * 118)
    content.extend(b"PK\x03\x04" + b"\x00" * 20 + b"FLAG{forensics_triage_mastery}" + b"\x00" * 20)
    artifact.write_bytes(bytes(content))

    result = duachuot_forensics_triage(str(artifact))
    assert result["ok"] is True
    assert len(result["hashes"]["md5"]) == 32
    assert len(result["hashes"]["sha256"]) == 64
    assert result["flags_found"] == ["FLAG{forensics_triage_mastery}"]
    assert any("Zip" in c["signature"] for c in result["embedded_carve_candidates"])
    assert len(result["recommendations"]) > 0


def test_png_stego_analysis_detects_trailing_overlay(tmp_path: Path) -> None:
    png = tmp_path / "stego_overlay.png"
    import zlib

    def chunk(tag: bytes, data: bytes) -> bytes:
        return struct.pack(">I", len(data)) + tag + data + struct.pack(">I", zlib.crc32(tag + data) & 0xFFFFFFFF)

    ihdr = struct.pack(">IIBBBBB", 32, 32, 8, 2, 0, 0, 0)
    row = b"\x00" + b"\x00\x00\x00" * 32
    raw_data = zlib.compress(row * 32)
    png_bytes = (
        b"\x89PNG\r\n\x1a\n"
        + chunk(b"IHDR", ihdr)
        + chunk(b"IDAT", raw_data)
        + chunk(b"IEND", b"")
    )
    trailing = b"PK\x03\x04" + b"\x00" * 10 + b"CTF{trailing_overlay_discovered}"
    png.write_bytes(png_bytes + trailing)

    result = duachuot_stego_probe(str(png))
    assert result["ok"] is True
    assert result["kind"] == "png_bmp"
    assert "png_analysis" in result
    analysis = result["png_analysis"]
    assert analysis["has_trailing_data"] is True
    assert "Zip archive" in analysis["trailing_magic"]
    assert "CTF{trailing_overlay_discovered}" in analysis["flags_found"]


def test_png_dimension_tampering_crc_repair(tmp_path: Path) -> None:
    png = tmp_path / "tampered.png"
    import zlib

    def chunk(tag: bytes, data: bytes) -> bytes:
        return struct.pack(">I", len(data)) + tag + data + struct.pack(">I", zlib.crc32(tag + data) & 0xFFFFFFFF)

    ihdr_original = struct.pack(">IIBBBBB", 64, 64, 8, 2, 0, 0, 0)
    original_crc = zlib.crc32(b"IHDR" + ihdr_original) & 0xFFFFFFFF

    ihdr_tampered = struct.pack(">IIBBBBB", 64, 1, 8, 2, 0, 0, 0)
    row = b"\x00" + b"\x00\x00\x00" * 64
    raw_data = zlib.compress(row * 64)

    tampered_chunk = struct.pack(">I", 13) + b"IHDR" + ihdr_tampered + struct.pack(">I", original_crc)
    png_bytes = (
        b"\x89PNG\r\n\x1a\n"
        + tampered_chunk
        + chunk(b"IDAT", raw_data)
        + chunk(b"IEND", b"")
    )
    png.write_bytes(png_bytes)

    result = duachuot_stego_probe(str(png))
    assert result["ok"] is True
    analysis = result["png_analysis"]
    assert analysis["ihdr_dimension_tampering"] is True
    assert analysis["suggested_height"] == 64


def test_shannon_entropy_calculation(tmp_path: Path) -> None:
    from app.tools.probes import _shannon_entropy

    zero_file = tmp_path / "zeros.bin"
    zero_file.write_bytes(b"\x00" * 10000)
    assert _shannon_entropy(str(zero_file))["entropy"] == 0.0

    random_file = tmp_path / "random.bin"
    import random

    rng = random.Random(42)
    random_file.write_bytes(bytes(rng.randrange(0, 256) for _ in range(10000)))
    entropy_result = _shannon_entropy(str(random_file))
    assert entropy_result["entropy"] > 7.5
    assert "high" in entropy_result["verdict"]


def test_cli_forensics_commands(tmp_path: Path) -> None:
    from app.cli.main import main

    evidence = tmp_path / "ev.bin"
    evidence.write_bytes(b"PK\x03\x04" + b"\x00" * 30 + b"FLAG{cli_forensics_ok}")

    ret = main(["forensics", "triage", str(evidence), "--json"])
    assert ret == 0

    ret = main(["forensics", "stego", str(evidence)])
    assert ret == 0
