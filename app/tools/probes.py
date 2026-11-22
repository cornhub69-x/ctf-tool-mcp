"""MCP adapters — Investigation probes (media, pcap, disk, memory, stego, OCR, Windows, triage).

Each probe prefers existing host tools (Tool Matrix level A) and falls back to
robust pure-Python analyzers or clear BLOCKER-style errors when tools are missing,
ensuring offline, deterministic CTF forensics everywhere.
"""

from __future__ import annotations

import collections
import hashlib
import json
import math
import os
import re
import shutil
import socket
import struct
import subprocess  # nosec B404
import tempfile
import wave
import zlib
from typing import Any, Optional

from app.mcp_server import mcp
from app.security import format_error_response


def _run(tool: str, args: list[str], *, timeout: int = 30) -> dict[str, Any]:
    resolved = shutil.which(tool)
    if not resolved:
        raise FileNotFoundError(
            f"required tool '{tool}' is not available on this host; "
            "install it or run the equivalent manual command"
        )
    result = subprocess.run(  # nosec B603
        [resolved, *args],
        capture_output=True,
        text=True,
        timeout=timeout,
        check=False,
    )
    return {
        "tool": tool,
        "exit_code": result.returncode,
        "stdout": result.stdout[:200000],
        "stderr": result.stderr[:50000],
        "stdout_truncated": len(result.stdout) > 200000,
    }


def _detect_file_type(path: str) -> dict[str, Any]:
    """Detect file format using host 'file' command if available, or pure-Python magic bytes."""
    if shutil.which("file"):
        try:
            return _run("file", [path])
        except Exception:
            pass

    try:
        with open(path, "rb") as fh:
            header = fh.read(512)
        desc = "data"
        if header.startswith(b"\x7fELF"):
            desc = "ELF 32/64-bit binary executable"
        elif header.startswith(b"MZ"):
            desc = "PE32/PE64 executable (MS Windows)"
        elif header.startswith(b"\x89PNG\r\n\x1a\n"):
            desc = "PNG image data"
        elif header.startswith(b"\xff\xd8\xff"):
            desc = "JPEG image data"
        elif header.startswith(b"GIF87a") or header.startswith(b"GIF89a"):
            desc = "GIF image data"
        elif header.startswith(b"BM"):
            desc = "PC bitmap, Windows 3.x format"
        elif header.startswith(b"\xd4\xc3\xb2\xa1") or header.startswith(b"\xa1\xb2\xc3\xd4"):
            desc = "pcap capture file, microsecond resolution"
        elif header.startswith(b"\x4d\x3c\xb2\xa1") or header.startswith(b"\xa1\xb2\x3c\x4d"):
            desc = "pcap capture file, nanosecond resolution"
        elif header.startswith(b"\x0a\x0d\x0d\x0a"):
            desc = "pcapng capture file"
        elif header.startswith(b"PK\x03\x04"):
            desc = "Zip archive data"
        elif header.startswith(b"7z\xbc\xaf\x27\x1c"):
            desc = "7-zip archive data"
        elif header.startswith(b"\x1f\x8b"):
            desc = "gzip compressed data"
        elif header.startswith(b"BZh"):
            desc = "bzip2 compressed data"
        elif header.startswith(b"%PDF-"):
            desc = "PDF document"
        elif header.startswith(b"SQLite format 3\x00"):
            desc = "SQLite 3.x database"
        elif header.startswith(b"RIFF") and len(header) >= 12 and header[8:12] == b"WAVE":
            desc = "RIFF (little-endian) data, WAVE audio"
        elif header.startswith(b"RIFF") and len(header) >= 12 and header[8:12] == b"AVI ":
            desc = "RIFF (little-endian) data, AVI video"
        elif header.startswith(b"regf"):
            desc = "MS Windows registry file"
        elif header.startswith(b"\x4c\x00\x00\x00"):
            desc = "MS Windows shortcut, Item id list present"
        elif header.startswith(b"MAM\x04"):
            desc = "MS Windows prefetch file"
        elif header and all(0x20 <= b <= 0x7E or b in (9, 10, 13) for b in header[:min(len(header), 128)]):
            desc = "ASCII text"

        return {
            "tool": "file",
            "exit_code": 0,
            "stdout": f"{path}: {desc}\n",
            "stderr": "",
            "stdout_truncated": False,
        }
    except Exception as exc:
        return {
            "tool": "file",
            "exit_code": 1,
            "stdout": "",
            "stderr": str(exc),
            "stdout_truncated": False,
        }


def _compute_hashes(path: str) -> dict[str, str]:
    """Compute MD5, SHA1, and SHA256 hashes of a file."""
    md5 = hashlib.md5()
    sha1 = hashlib.sha1()
    sha256 = hashlib.sha256()
    try:
        with open(path, "rb") as fh:
            while chunk := fh.read(65536):
                md5.update(chunk)
                sha1.update(chunk)
                sha256.update(chunk)
        return {
            "md5": md5.hexdigest(),
            "sha1": sha1.hexdigest(),
            "sha256": sha256.hexdigest(),
        }
    except Exception:
        return {"md5": "", "sha1": "", "sha256": ""}


def _shannon_entropy(path: str) -> dict[str, Any]:
    """Calculate Shannon entropy (0.0 to 8.0 bits/byte) and security verdict."""
    counts: dict[int, int] = collections.defaultdict(int)
    total_bytes = 0
    try:
        with open(path, "rb") as fh:
            while chunk := fh.read(65536):
                total_bytes += len(chunk)
                for b in chunk:
                    counts[b] += 1

        if total_bytes == 0:
            return {"entropy": 0.0, "verdict": "empty", "total_bytes": 0}

        entropy = 0.0
        for count in counts.values():
            p = count / total_bytes
            entropy -= p * math.log2(p)

        entropy = round(entropy, 4)
        if entropy > 7.2:
            verdict = "high (likely encrypted, packed, compressed, or high-density payload)"
        elif entropy > 4.5:
            verdict = "moderate (typical compiled code or compressed media)"
        else:
            verdict = "low (plain text or repetitive structure)"

        return {
            "entropy": entropy,
            "max_entropy": 8.0,
            "verdict": verdict,
            "total_bytes": total_bytes,
        }
    except Exception as exc:
        return {"entropy": 0.0, "verdict": str(exc), "total_bytes": 0}


_FLAG_PATTERNS = [
    re.compile(rb"(?:flag|FLAG|ctf|CTF|cyber|CYBER)\{[^}\s\x00]{3,120}\}"),
    re.compile(rb"[A-Za-z0-9_\-]{3,20}\{[^}\s\x00]{3,120}\}"),
]


def _scan_flags_and_secrets(raw: bytes) -> list[str]:
    """Extract potential CTF flags matching common flag formats."""
    found: list[str] = []
    for pat in _FLAG_PATTERNS:
        for m in pat.finditer(raw):
            try:
                candidate = m.group(0).decode("utf-8", errors="replace")
                if candidate not in found:
                    found.append(candidate)
            except Exception:
                pass
    return found[:20]


_SIGNATURES: list[tuple[bytes, str]] = [
    (b"PK\x03\x04", "Zip archive"),
    (b"7z\xbc\xaf\x27\x1c", "7-Zip archive"),
    (b"Rar!\x1a\x07\x00", "RAR archive (v4)"),
    (b"Rar!\x1a\x07\x01\x00", "RAR archive (v5)"),
    (b"\x1f\x8b\x08", "GZip compressed data"),
    (b"BZh", "BZip2 compressed data"),
    (b"\x7fELF", "ELF binary executable"),
    (b"MZ", "DOS/PE executable"),
    (b"%PDF-", "PDF document"),
    (b"\x89PNG\r\n\x1a\n", "PNG image"),
    (b"\xff\xd8\xff", "JPEG image"),
    (b"GIF89a", "GIF89a image"),
    (b"GIF87a", "GIF87a image"),
    (b"SQLite format 3\x00", "SQLite 3 database"),
]


def _scan_embedded_signatures(path: str, max_bytes: int = 32 * 1024 * 1024) -> list[dict[str, Any]]:
    """Scan file for embedded file signatures (carving candidates) at non-zero offsets."""
    results: list[dict[str, Any]] = []
    try:
        with open(path, "rb") as fh:
            data = fh.read(max_bytes)
        for sig, label in _SIGNATURES:
            start = 1
            while True:
                idx = data.find(sig, start)
                if idx == -1:
                    break
                results.append({"offset": idx, "hex_offset": hex(idx), "signature": label})
                start = idx + len(sig)
                if len(results) >= 50:
                    break
            if len(results) >= 50:
                break
    except Exception:
        pass
    return results


# ---------------------------------------------------------------- Media probe


@mcp.tool(
    name="duachuot_media_probe",
    description=(
        "Probe an image/audio/video artifact: full metadata (exiftool JSON), "
        "stream info (ffprobe), format detection (file), hashes, and Shannon entropy. "
        "Includes GPS fields when present."
    ),
)
def duachuot_media_probe(path: str) -> dict[str, Any]:
    try:
        if not shutil.which("exiftool"):
            raise FileNotFoundError(
                "required tool 'exiftool' is not available on this host; "
                "install it or run the equivalent manual command"
            )
        result: dict[str, Any] = {"ok": True, "path": path}
        result["file"] = _detect_file_type(path)
        result["hashes"] = _compute_hashes(path)
        result["entropy"] = _shannon_entropy(path)
        result["exiftool"] = _run("exiftool", ["-json", "-n", path])
        if result["exiftool"]["exit_code"] == 0 and result["exiftool"]["stdout"].strip():
            try:
                records = json.loads(result["exiftool"]["stdout"])
                result["metadata"] = records[0] if records else {}
            except json.JSONDecodeError:
                result["metadata"] = {}
        if shutil.which("ffprobe"):
            result["ffprobe"] = _run(
                "ffprobe",
                ["-v", "quiet", "-print_format", "json", "-show_format", "-show_streams", path],
            )
        return result
    except Exception as exc:
        return format_error_response(exc)


# ---------------------------------------------------------------- PCAP probe


def _parse_pcap_pure(path: str, max_flows: int = 30) -> dict[str, Any]:
    """Pure-Python PCAP parser for flows, endpoints, DNS, and geo extraction when tshark is missing."""
    with open(path, "rb") as fh:
        raw = fh.read()

    if len(raw) < 24:
        raise ValueError("File too small to be a PCAP capture")

    magic = raw[:4]
    endian = "<" if magic in (b"\xd4\xc3\xb2\xa1", b"\x4d\x3c\xb2\xa1") else ">"
    if magic not in (b"\xd4\xc3\xb2\xa1", b"\xa1\xb2\xc3\xd4", b"\x4d\x3c\xb2\xa1", b"\xa1\xb2\x3c\x4d"):
        raise ValueError(f"Unsupported PCAP magic: {magic.hex()}")

    linktype = struct.unpack_from(endian + "I", raw, 20)[0]
    offset = 24
    packet_count = 0
    endpoints: dict[str, dict[str, int]] = {}
    flows: dict[str, dict[str, Any]] = {}
    dns_queries: list[str] = []
    geo_hits: list[str] = []
    geo_raw_lines: list[str] = []

    while offset + 16 <= len(raw):
        ts_sec, ts_usec, incl_len, orig_len = struct.unpack_from(endian + "IIII", raw, offset)
        offset += 16
        if offset + incl_len > len(raw):
            break
        pkt = raw[offset : offset + incl_len]
        offset += incl_len
        packet_count += 1

        for marker in (b"GPRMC", b"GPGGA", b"GNGGA", b"GNRMC", b"GGA"):
            if marker in pkt:
                m_str = marker.decode("ascii")
                if m_str not in geo_hits:
                    geo_hits.append(m_str)
                try:
                    s_idx = pkt.find(b"$" + marker)
                    if s_idx != -1:
                        end_idx = pkt.find(b"\r\n", s_idx)
                        if end_idx == -1:
                            end_idx = pkt.find(b"\n", s_idx)
                        if end_idx != -1:
                            geo_raw_lines.append(pkt[s_idx:end_idx].decode("ascii", errors="replace"))
                except Exception:
                    pass

        if linktype == 1 and len(pkt) >= 14:
            ethertype = struct.unpack(">H", pkt[12:14])[0]
            if ethertype == 0x0800 and len(pkt) >= 34:
                ip_hdr = pkt[14:]
                ihl = (ip_hdr[0] & 0x0F) * 4
                proto = ip_hdr[9]
                src_ip = socket.inet_ntoa(ip_hdr[12:16])
                dst_ip = socket.inet_ntoa(ip_hdr[16:20])

                for ip, is_tx in [(src_ip, True), (dst_ip, False)]:
                    if ip not in endpoints:
                        endpoints[ip] = {
                            "packets": 0, "bytes": 0,
                            "tx_packets": 0, "tx_bytes": 0,
                            "rx_packets": 0, "rx_bytes": 0,
                        }
                    endpoints[ip]["packets"] += 1
                    endpoints[ip]["bytes"] += incl_len
                    if is_tx:
                        endpoints[ip]["tx_packets"] += 1
                        endpoints[ip]["tx_bytes"] += incl_len
                    else:
                        endpoints[ip]["rx_packets"] += 1
                        endpoints[ip]["rx_bytes"] += incl_len

                payload = ip_hdr[ihl:]
                sport, dport = 0, 0
                flow_proto = "OTHER"
                if proto == 6 and len(payload) >= 20:
                    sport, dport = struct.unpack(">HH", payload[:4])
                    flow_proto = "TCP"
                elif proto == 17 and len(payload) >= 8:
                    sport, dport = struct.unpack(">HH", payload[:4])
                    flow_proto = "UDP"
                    if (sport == 53 or dport == 53) and len(payload) > 20:
                        dns_data = payload[8:]
                        if len(dns_data) > 12:
                            q_offset = 12
                            labels = []
                            while q_offset < len(dns_data):
                                l_len = dns_data[q_offset]
                                if l_len == 0:
                                    break
                                if l_len >= 192:
                                    break
                                q_offset += 1
                                labels.append(dns_data[q_offset : q_offset + l_len].decode("ascii", errors="replace"))
                                q_offset += l_len
                            if labels:
                                domain = ".".join(labels)
                                if domain and domain not in dns_queries:
                                    dns_queries.append(domain)

                if sport or dport:
                    endpoints_pair = tuple(sorted([f"{src_ip}:{sport}", f"{dst_ip}:{dport}"]))
                    flow_key = f"{endpoints_pair[0]} <-> {endpoints_pair[1]} ({flow_proto})"
                    if flow_key not in flows:
                        flows[flow_key] = {"proto": flow_proto, "packets": 0, "bytes": 0}
                    flows[flow_key]["packets"] += 1
                    flows[flow_key]["bytes"] += incl_len

    sorted_endpoints = sorted(endpoints.items(), key=lambda kv: kv[1]["bytes"], reverse=True)[:max_flows]
    endpoints_lines = [
        "================================================================================",
        "IPv4 Endpoints",
        "Filter:<No Filter>",
        "                       |  Packets  | |  Bytes  | | Tx Packets | | Tx Bytes | | Rx Packets | | Rx Bytes |",
    ]
    for ip, stat in sorted_endpoints:
        endpoints_lines.append(
            f"{ip:<23}{stat['packets']:>10}{stat['bytes']:>12}{stat['tx_packets']:>13}{stat['tx_bytes']:>13}{stat['rx_packets']:>13}{stat['rx_bytes']:>13}"
        )
    endpoints_lines.append("================================================================================")

    sorted_flows = sorted(flows.items(), key=lambda kv: kv[1]["bytes"], reverse=True)[:max_flows]
    conv_lines = [
        "================================================================================",
        "Conversations",
        "Filter:<No Filter>",
        "                                               |       <-      | |       ->      | |     Total     |",
    ]
    for f_key, f_stat in sorted_flows:
        conv_lines.append(f"{f_key:<47} {f_stat['packets']:>10} {f_stat['bytes']:>12}")
    conv_lines.append("================================================================================")

    return {
        "packet_count": packet_count,
        "conversations_stdout": "\n".join(conv_lines) + "\n",
        "endpoints_stdout": "\n".join(endpoints_lines) + "\n",
        "dns_stdout": "\n".join(dns_queries) + ("\n" if dns_queries else ""),
        "dns_queries": dns_queries,
        "geo_hits": geo_hits,
        "geo_stdout": "\n".join(geo_raw_lines) + "\n",
    }


@mcp.tool(
    name="duachuot_pcap_probe",
    description=(
        "Probe a PCAP/PCAPNG capture: conversations, endpoints, DNS, HTTP hosts, "
        "and GPS/geo hints (Wi-Fi probe requests, GPS NMEA, cellular). "
        "Includes pure-Python fallback when tshark is not installed on host."
    ),
)
def duachuot_pcap_probe(path: str, max_flows: int = 30) -> dict[str, Any]:
    try:
        result: dict[str, Any] = {"ok": True, "path": path}
        result["file"] = _detect_file_type(path)
        result["hashes"] = _compute_hashes(path)
        result["entropy"] = _shannon_entropy(path)

        if shutil.which("tshark"):
            result["conversations"] = _run(
                "tshark", ["-r", path, "-q", "-z", f"conv,tcp;{max_flows}"], timeout=60
            )
            result["endpoints"] = _run(
                "tshark", ["-r", path, "-q", "-z", f"endpoints,ip;{max_flows}"], timeout=60
            )
            result["dns_queries"] = _run(
                "tshark",
                ["-r", path, "-Y", "dns.qry.name", "-T", "fields", "-e", "dns.qry.name"],
                timeout=60,
            )
            geo_hints = _run(
                "tshark",
                [
                    "-r", path,
                    "-Y",
                    "wlan.tag.number==0 or data.data contains \"GPRMC\" or data.data contains \"GGA\"",
                    "-T", "fields",
                    "-e", "wlan_rsna_ie.tag", "-e", "data.data",
                ],
                timeout=60,
            )
            if geo_hints["exit_code"] != 0:
                geo_hints["fallback"] = _run(
                    "tshark",
                    [
                        "-r", path,
                        "-Y",
                        "frame contains \"GPRMC\" or frame contains \"GGA\"",
                        "-T", "fields",
                        "-e", "udp.payload",
                    ],
                    timeout=60,
                )
            result["geo_hints"] = geo_hints
            result["geo_hints"]["hits"] = _nmea_hits(geo_hints.get("stdout", "")) + _nmea_hits(
                geo_hints.get("fallback", {}).get("stdout", "")
            )
        else:
            pure = _parse_pcap_pure(path, max_flows=max_flows)
            result["conversations"] = {
                "tool": "pure_pcap",
                "exit_code": 0,
                "stdout": pure["conversations_stdout"],
                "stderr": "",
                "stdout_truncated": False,
            }
            result["endpoints"] = {
                "tool": "pure_pcap",
                "exit_code": 0,
                "stdout": pure["endpoints_stdout"],
                "stderr": "",
                "stdout_truncated": False,
            }
            result["dns_queries"] = {
                "tool": "pure_pcap",
                "exit_code": 0,
                "stdout": pure["dns_stdout"],
                "stderr": "",
                "stdout_truncated": False,
            }
            result["geo_hints"] = {
                "tool": "pure_pcap",
                "exit_code": 0,
                "stdout": pure["geo_stdout"],
                "stderr": "",
                "hits": pure["geo_hits"],
                "stdout_truncated": False,
            }
            result["summary"] = {
                "packet_count": pure["packet_count"],
                "dns_query_count": len(pure["dns_queries"]),
            }
        return result
    except Exception as exc:
        return format_error_response(exc)


# ---------------------------------------------------------------- Disk probe


def _inspect_disk_headers(path: str) -> dict[str, Any]:
    """Pure-Python partition and filesystem signature scanner for disk images."""
    try:
        with open(path, "rb") as fh:
            sector0 = fh.read(512)
            sector1 = fh.read(512)
        has_mbr = sector0[510:512] == b"\x55\xaa" if len(sector0) >= 512 else False
        has_gpt = sector1[:8] == b"EFI PART" if len(sector1) >= 8 else False
        return {
            "mbr_signature": has_mbr,
            "gpt_signature": has_gpt,
            "partition_type": "GPT" if has_gpt else ("MBR" if has_mbr else "unknown/raw"),
        }
    except Exception as exc:
        return {"error": str(exc)}


@mcp.tool(
    name="duachuot_disk_probe",
    description=(
        "Probe a disk image: filesystem listing (fls), filesystem statistics "
        "(fsstat), partition structure, and carve candidates (binwalk/foremost). Preserves originals."
    ),
)
def duachuot_disk_probe(path: str, max_list: int = 200) -> dict[str, Any]:
    try:
        result: dict[str, Any] = {"ok": True, "path": path}
        result["file"] = _detect_file_type(path)
        result["hashes"] = _compute_hashes(path)
        result["partition_table"] = _inspect_disk_headers(path)
        result["fsstat"] = _run("fsstat", [path], timeout=60)
        result["fls"] = _run("fls", ["-r", "-m", "/", path], timeout=60)
        return result
    except Exception as exc:
        return format_error_response(exc)


# ---------------------------------------------------------------- Memory probe


@mcp.tool(
    name="duachuot_mem_probe",
    description=(
        "Probe a memory image with Volatility 3: detect profile (windows.info / "
        "linux.info), process list, and file scan. Profile must be evidenced."
    ),
)
def duachuot_mem_probe(path: str, os_hint: Optional[str] = None) -> dict[str, Any]:
    try:
        if not shutil.which("vol"):
            raise FileNotFoundError(
                "required tool 'vol' (Volatility 3) is not available on this host; "
                "install it or run the equivalent manual command"
            )
        result: dict[str, Any] = {"ok": True, "path": path}
        result["file"] = _detect_file_type(path)
        result["hashes"] = _compute_hashes(path)
        plugin = "windows.info" if (os_hint or "linux").lower().startswith(("win", "windows")) else "linux.info"
        result["info"] = _run("vol", ["-f", path, plugin], timeout=60)
        ps_plugin = "windows.pslist" if "win" in plugin else "linux.pslist"
        result["pslist"] = _run("vol", ["-f", path, ps_plugin], timeout=60)
        return result
    except Exception as exc:
        return format_error_response(exc)


# ---------------------------------------------------------------- Steganography probe


_FLAG_LIKE_RE = re.compile(r"[A-Za-z0-9_\-]{3,}")


def _lsb_analysis(path: str, limit_frames: int = 20000) -> dict[str, Any]:
    """Detect LSB stego bias in a PCM WAV without external tools."""
    try:
        with wave.open(path, "rb") as wav:
            n_frames = min(wav.getnframes(), limit_frames)
            sampwidth = wav.getsampwidth()
            channels = wav.getnchannels()
            if sampwidth > 4:
                return {"supported": False, "note": "unsupported sample width"}
            frames = wav.readframes(n_frames)
            nbytes = len(frames)
            if nbytes == 0:
                return {"supported": False, "note": "empty audio"}

            ones = 0
            seen = 0
            for i in range(0, nbytes - (nbytes % (channels * sampwidth)), channels * sampwidth):
                for ch in range(channels):
                    offset = i + ch * sampwidth
                    sample = struct.unpack_from("<h", frames, offset)[0]
                    ones += sample & 1
                    seen += 1
            if seen == 0:
                return {"supported": False, "note": "no samples decoded"}
            p1 = ones / seen
            deviation = abs(p1 - 0.5)
            return {
                "supported": True,
                "channels": channels,
                "sample_width": sampwidth,
                "frames_analyzed": n_frames,
                "lsb_ones_fraction": round(p1, 5),
                "deviation_from_0_5": round(deviation, 5),
                "suspicious": deviation > 0.12,
            }
    except (wave.Error, OSError, EOFError):
        return {"supported": False, "note": "not a parseable PCM WAV"}


def _extract_text_from_output(result: dict[str, Any]) -> Optional[str]:
    """First printable/flag-like content found in a tool's stdout+stderr."""
    if result.get("exit_code") is None:
        return None
    text = (result.get("stdout") or "") + "\n" + (result.get("stderr") or "")
    for line in text.splitlines():
        stripped = line.strip()
        if not stripped or stripped in {"", "Output file written", "Image overwritten"}:
            continue
        if _FLAG_LIKE_RE.search(stripped) and any(ch.isalpha() for ch in stripped):
            return stripped[:500]
    return None


def _optional_run(tool: str, args: list[str], *, timeout: int = 60) -> dict[str, Any]:
    """Run an optional probe tool; missing tool yields a non-fatal note."""
    if not shutil.which(tool):
        return {"tool": tool, "exit_code": None, "note": f"tool '{tool}' not installed", "stdout": "", "stderr": ""}
    return _run(tool, args, timeout=timeout)


def _analyze_png(path: str) -> dict[str, Any]:
    """Parse PNG chunks, check CRC validity (dimension tampering), text chunks, and trailing overlay."""
    with open(path, "rb") as fh:
        raw = fh.read()

    if not raw.startswith(b"\x89PNG\r\n\x1a\n"):
        return {"valid_png": False}

    offset = 8
    chunks: list[dict[str, Any]] = []
    text_chunks: dict[str, str] = {}
    crc_mismatches: list[dict[str, Any]] = []
    iend_end: Optional[int] = None
    ihdr_tampered = False
    ihdr_suggested_height: Optional[int] = None

    while offset + 8 <= len(raw):
        length = struct.unpack_from(">I", raw, offset)[0]
        chunk_type = raw[offset + 4 : offset + 8]
        data_start = offset + 8
        data_end = data_start + length
        crc_offset = data_end

        if crc_offset + 4 > len(raw):
            break

        actual_crc = struct.unpack_from(">I", raw, crc_offset)[0]
        expected_crc = zlib.crc32(raw[offset + 4 : data_end]) & 0xFFFFFFFF

        type_str = chunk_type.decode("latin-1", errors="replace")
        chunks.append({"type": type_str, "offset": offset, "length": length})

        if actual_crc != expected_crc:
            crc_mismatches.append(
                {"type": type_str, "actual_crc": hex(actual_crc), "expected_crc": hex(expected_crc)}
            )
            if type_str == "IHDR" and length == 13:
                ihdr_tampered = True
                ihdr_data = raw[data_start:data_end]
                for test_h in range(1, 4096):
                    cand = ihdr_data[:4] + struct.pack(">I", test_h) + ihdr_data[8:]
                    if (zlib.crc32(b"IHDR" + cand) & 0xFFFFFFFF) == actual_crc:
                        ihdr_suggested_height = test_h
                        break

        if type_str == "tEXt" and data_end <= len(raw):
            parts = raw[data_start:data_end].split(b"\x00", 1)
            k = parts[0].decode("latin-1", errors="replace")
            v = parts[1].decode("latin-1", errors="replace") if len(parts) > 1 else ""
            text_chunks[k] = v
        elif type_str == "zTXt" and data_end <= len(raw):
            parts = raw[data_start:data_end].split(b"\x00\x00", 1)
            k = parts[0].decode("latin-1", errors="replace")
            if len(parts) > 1:
                try:
                    text_chunks[k] = zlib.decompress(parts[1]).decode("latin-1", errors="replace")
                except Exception:
                    pass

        offset = crc_offset + 4
        if type_str == "IEND":
            iend_end = offset
            break

    trailing_bytes = b""
    if iend_end is not None and iend_end < len(raw):
        trailing_bytes = raw[iend_end:]

    trailing_magic = "unknown"
    if trailing_bytes.startswith(b"PK\x03\x04"):
        trailing_magic = "Zip archive (embedded/appended)"
    elif trailing_bytes.startswith(b"7z\xbc\xaf\x27\x1c"):
        trailing_magic = "7-Zip archive"
    elif trailing_bytes.startswith(b"Rar!\x1a\x07"):
        trailing_magic = "RAR archive"
    elif trailing_bytes.startswith(b"\x1f\x8b"):
        trailing_magic = "GZip archive"
    elif trailing_bytes.startswith(b"\x7fELF"):
        trailing_magic = "ELF binary"
    elif trailing_bytes.startswith(b"MZ"):
        trailing_magic = "PE/EXE executable"
    elif trailing_bytes.startswith(b"\xff\xd8\xff"):
        trailing_magic = "Embedded JPEG image"
    elif trailing_bytes.startswith(b"\x89PNG"):
        trailing_magic = "Embedded PNG image"

    trailing_flags = _scan_flags_and_secrets(trailing_bytes) if trailing_bytes else []
    text_flags = _scan_flags_and_secrets(" ".join(f"{k}:{v}" for k, v in text_chunks.items()).encode("utf-8"))

    return {
        "valid_png": True,
        "chunk_count": len(chunks),
        "chunk_types": [c["type"] for c in chunks],
        "text_metadata": text_chunks,
        "crc_mismatches": crc_mismatches,
        "ihdr_dimension_tampering": ihdr_tampered,
        "suggested_height": ihdr_suggested_height,
        "has_trailing_data": len(trailing_bytes) > 0,
        "trailing_bytes_count": len(trailing_bytes),
        "trailing_magic": trailing_magic if trailing_bytes else None,
        "trailing_preview": trailing_bytes[:128].hex() if trailing_bytes else "",
        "flags_found": list(set(trailing_flags + text_flags)),
    }


def _analyze_jpeg(path: str) -> dict[str, Any]:
    """Parse JPEG markers, comments, and trailing data after EOI."""
    with open(path, "rb") as fh:
        raw = fh.read()

    if not raw.startswith(b"\xff\xd8"):
        return {"valid_jpeg": False}

    comments: list[str] = []
    eoi_pos = raw.rfind(b"\xff\xd9")
    trailing_bytes = b""
    if eoi_pos != -1 and eoi_pos + 2 < len(raw):
        trailing_bytes = raw[eoi_pos + 2 :]

    idx = 2
    while idx < len(raw) - 4:
        if raw[idx : idx + 2] == b"\xff\xfe":
            length = struct.unpack_from(">H", raw, idx + 2)[0]
            if idx + 2 + length <= len(raw):
                comment = raw[idx + 4 : idx + 2 + length].decode("latin-1", errors="replace")
                comments.append(comment)
                idx += 2 + length
                continue
        idx += 1

    trailing_magic = "unknown"
    if trailing_bytes.startswith(b"PK\x03\x04"):
        trailing_magic = "Zip archive (embedded/appended)"
    elif trailing_bytes.startswith(b"7z\xbc\xaf\x27\x1c"):
        trailing_magic = "7-Zip archive"
    elif trailing_bytes.startswith(b"Rar!\x1a\x07"):
        trailing_magic = "RAR archive"

    trailing_flags = _scan_flags_and_secrets(trailing_bytes) if trailing_bytes else []
    com_flags = _scan_flags_and_secrets(" ".join(comments).encode("utf-8"))

    return {
        "valid_jpeg": True,
        "comments": comments,
        "has_trailing_data": len(trailing_bytes) > 0,
        "trailing_bytes_count": len(trailing_bytes),
        "trailing_magic": trailing_magic if trailing_bytes else None,
        "trailing_preview": trailing_bytes[:128].hex() if trailing_bytes else "",
        "flags_found": list(set(trailing_flags + com_flags)),
    }


@mcp.tool(
    name="duachuot_stego_probe",
    description=(
        "Probe a carrier file for steganography/carved data: binwalk signature "
        "scan, foremost extraction candidate list, steghide info, PNG chunk & "
        "trailing overlay analysis, JPEG marker analysis, and WAV LSB analysis."
    ),
)
def duachuot_stego_probe(path: str) -> dict[str, Any]:
    try:
        result: dict[str, Any] = {"ok": True, "path": path}
        result["hashes"] = _compute_hashes(path)
        result["entropy"] = _shannon_entropy(path)
        result["binwalk"] = _optional_run("binwalk", [path], timeout=60)
        result["steghide_info"] = _optional_run("steghide", ["info", path], timeout=30)

        with open(path, "rb") as fh:
            magic = fh.read(16)

        if magic.startswith(b"RIFF") and magic[8:12] == b"WAVE":
            result["kind"] = "wav"
            lsb = _lsb_analysis(path)
            result["lsb_analysis"] = lsb
            with tempfile.TemporaryDirectory() as tmp:
                out = os.path.join(tmp, "decoded.bin")
                wavsteg = _optional_run(
                    "wavsteg", ["decode", "--wav", path, "--out", out], timeout=120
                )
                if wavsteg.get("exit_code") == 0 and os.path.exists(out):
                    with open(out, "rb") as fh_out:
                        raw = fh_out.read()
                    wavsteg["payload_preview"] = (
                        raw[:500].decode("utf-8", errors="replace")
                    )
                else:
                    wavsteg["payload_preview"] = ""
                wavsteg["extracted"] = (
                    wavsteg.get("payload_preview")
                    or _extract_text_from_output(wavsteg)
                )
                result["wavsteg_decode"] = wavsteg
        elif magic.startswith(b"\x89PNG"):
            result["kind"] = "png_bmp"
            png_analysis = _analyze_png(path)
            result["png_analysis"] = png_analysis
            with tempfile.TemporaryDirectory() as tmp:
                out = os.path.join(tmp, "recovered.bin")
                stegolsb = _optional_run(
                    "stegolsb",
                    ["steglsb", "-r", "-i", path, "-o", out, "-n", "1"],
                    timeout=120,
                )
                if stegolsb.get("exit_code") == 0 and os.path.exists(out):
                    with open(out, "rb") as fh_out:
                        raw = fh_out.read()
                    stegolsb["payload_preview"] = raw[:500].decode(
                        "utf-8", errors="replace"
                    )
                flags = png_analysis.get("flags_found", [])
                stegolsb["extracted"] = (
                    stegolsb.get("payload_preview")
                    or _extract_text_from_output(stegolsb)
                    or (flags[0] if flags else None)
                )
                result["stegolsb_recover"] = stegolsb
        elif magic.startswith(b"BM"):
            result["kind"] = "png_bmp"
            with tempfile.TemporaryDirectory() as tmp:
                out = os.path.join(tmp, "recovered.bin")
                stegolsb = _optional_run(
                    "stegolsb",
                    ["steglsb", "-r", "-i", path, "-o", out, "-n", "1"],
                    timeout=120,
                )
                if stegolsb.get("exit_code") == 0 and os.path.exists(out):
                    with open(out, "rb") as fh_out:
                        raw = fh_out.read()
                    stegolsb["payload_preview"] = raw[:500].decode(
                        "utf-8", errors="replace"
                    )
                stegolsb["extracted"] = (
                    stegolsb.get("payload_preview")
                    or _extract_text_from_output(stegolsb)
                )
                result["stegolsb_recover"] = stegolsb
        elif magic.startswith(b"\xff\xd8"):
            result["kind"] = "jpeg"
            result["jpeg_analysis"] = _analyze_jpeg(path)
        elif magic.startswith(b"ID3") or magic[2:4] == b"\xff\xfb" or magic[2:4] == b"\xff\xf3":
            result["kind"] = "mp3"
            with tempfile.TemporaryDirectory() as tmp:
                out = os.path.join(tmp, "decoded.txt")
                pbhide = _optional_run(
                    "pbhide", ["extract", path, out], timeout=120
                )
                if pbhide.get("exit_code") == 0 and os.path.exists(out):
                    with open(out, "rb") as fh_out:
                        raw = fh_out.read()
                    pbhide["payload_preview"] = raw[:500].decode(
                        "utf-8", errors="replace"
                    )
                else:
                    pbhide["payload_preview"] = ""
                    missing = pbhide.get("note", "")
                    pbhide["note"] = (
                        (missing + "; " if missing else "")
                        + "no payload extracted; if the MP3 was encoded with "
                        "the original MP3Stego, decode it with wine + "
                        "Decode.exe (see docs/INVESTIGATION.md requirements)"
                    )
                pbhide["extracted"] = (
                    pbhide.get("payload_preview")
                    or _extract_text_from_output(pbhide)
                )
                result["pbhide_extract"] = pbhide
        else:
            result["kind"] = "other"
        return result
    except Exception as exc:
        return format_error_response(exc)


# ---------------------------------------------------------------- OCR probe


@mcp.tool(
    name="duachuot_ocr_probe",
    description=(
        "OCR text from an image (tesseract) and decode QR/barcodes (zxing-cpp "
        "via CTF venv if available). QR codes frequently carry coordinates."
    ),
)
def duachuot_ocr_probe(path: str) -> dict[str, Any]:
    try:
        result: dict[str, Any] = {"ok": True, "path": path}
        result["tesseract"] = _run("tesseract", [path, "stdout"], timeout=60)
        if shutil.which("ctfpy"):
            result["zxing"] = _run(
                "ctfpy",
                ["-c", f"import zxingcpp,sys; [print(r.text) for r in zxingcpp.read_barcodes(open({path!r},'rb').read())]"],
                timeout=60,
            )
        else:
            result["zxing"] = {
                "tool": "zxing-cpp",
                "note": "ctfpy wrapper not found; zxing-cpp QR decode skipped",
                "exit_code": None,
            }
        return result
    except Exception as exc:
        return format_error_response(exc)


# ---------------------------------------------------------------- Windows probe


@mcp.tool(
    name="duachuot_win_probe",
    description=(
        "Windows forensics without external tools: registry hive strings (SAM/"
        "SYSTEM), LNK file target extraction, and prefetch filename strings. "
        "Pure-Python parsers; runs on Linux or Windows."
    ),
)
def duachuot_win_probe(path: str, kind: str = "auto") -> dict[str, Any]:
    try:
        kind = kind.lower()
        with open(path, "rb") as handle:
            raw = handle.read(64 * 1024 * 1024)
        result: dict[str, Any] = {
            "ok": True,
            "path": path,
            "kind": kind,
            "hashes": _compute_hashes(path),
            "entropy": _shannon_entropy(path),
        }
        if kind in {"auto", "lnk"} and raw.startswith(b"\x4c\x00\x00\x00"):
            result["lnk"] = _parse_lnk(path)
        if kind in {"auto", "hive"} and raw[:4] in {b"regf", b"hbin"}:
            result["hive"] = {
                "signature": raw[:4].decode("latin-1"),
                "strings_hint": _extract_strings_hint(raw),
            }
        if kind in {"auto", "prefetch"} and raw[:4] == b"MAM\x04":
            result["prefetch"] = {
                "signature": "MAM\\x04",
                "strings_hint": _extract_strings_hint(raw),
            }
        if kind == "auto" and not result.get("lnk") and not result.get("hive") and not result.get("prefetch"):
            result["note"] = "unknown container; first 4 bytes: " + raw[:4].hex()
        return result
    except Exception as exc:
        return format_error_response(exc)


def _parse_lnk(path: str) -> dict[str, Any]:
    with open(path, "rb") as handle:
        raw = handle.read()
    strings: list[str] = []
    try:
        offset = 76 + struct.unpack_from("<H", raw, 76)[0]
        if offset < len(raw) - 4 and struct.unpack_from("<I", raw, offset)[0] == 0x0000000C:
            offset += 4
            while offset < len(raw) - 2:
                length = struct.unpack_from("<H", raw, offset)[0]
                if length == 0 or offset + 2 + length > len(raw):
                    break
                try:
                    strings.append(raw[offset + 2 : offset + 2 + length].decode("utf-16-le"))
                except UnicodeDecodeError:
                    pass
                offset += 2 + length
    except Exception:  # nosec B110
        pass
    return {"link_strings": strings[:50], "string_count": len(strings)}


def _extract_strings_hint(raw: bytes) -> list[str]:
    hints: list[str] = []
    for marker in (b"SOFTWARE", b"SYSTEM", b"SAM", b"CurrentControlSet", b"MACHINE"):
        index = raw.find(marker)
        if index >= 0:
            hints.append(marker.decode("latin-1"))
    return hints[:20]


def _nmea_hits(stdout: str) -> list[str]:
    """Detect NMEA sentence markers in tshark output (ASCII or hex-encoded)."""
    hits: list[str] = []
    upper = stdout.upper()
    for marker in ("GPRMC", "GPGGA", "GGA"):
        if marker in upper or marker.encode().hex().upper() in upper:
            hits.append(marker)
    return hits


# ---------------------------------------------------------------- Universal Forensic Triage


@mcp.tool(
    name="duachuot_forensics_triage",
    description=(
        "Universal forensics triage for any artifact: hashes (MD5/SHA1/SHA256), "
        "Shannon entropy, file format detection, embedded file signature carving candidates, "
        "CTF flag regex search, and artifact-specific deep inspection (PNG, JPEG, PCAP, WAV)."
    ),
)
def duachuot_forensics_triage(path: str) -> dict[str, Any]:
    try:
        if not os.path.exists(path):
            raise FileNotFoundError(f"Artifact not found: '{path}'")

        file_size = os.path.getsize(path)
        file_type = _detect_file_type(path)
        hashes = _compute_hashes(path)
        entropy = _shannon_entropy(path)
        embedded = _scan_embedded_signatures(path)

        with open(path, "rb") as fh:
            sample = fh.read(min(file_size, 16 * 1024 * 1024))
        flags_found = _scan_flags_and_secrets(sample)

        triage: dict[str, Any] = {
            "ok": True,
            "path": path,
            "size_bytes": file_size,
            "file_type": file_type.get("stdout", "").strip(),
            "hashes": hashes,
            "entropy": entropy,
            "flags_found": flags_found,
            "embedded_carve_candidates": embedded,
            "recommendations": [],
        }

        magic = sample[:16]
        if magic.startswith(b"\x89PNG"):
            png_res = _analyze_png(path)
            triage["png_deep"] = png_res
            if png_res.get("has_trailing_data"):
                triage["recommendations"].append(
                    f"PNG has {png_res['trailing_bytes_count']} trailing bytes ({png_res['trailing_magic']}); carve or extract payload"
                )
            if png_res.get("ihdr_dimension_tampering"):
                triage["recommendations"].append(
                    f"PNG IHDR CRC mismatch detected! Suggested repaired height: {png_res['suggested_height']}"
                )
            if png_res.get("flags_found"):
                triage["flags_found"] = list(set(triage["flags_found"] + png_res["flags_found"]))
        elif magic.startswith(b"\xff\xd8"):
            jpeg_res = _analyze_jpeg(path)
            triage["jpeg_deep"] = jpeg_res
            if jpeg_res.get("has_trailing_data"):
                triage["recommendations"].append(
                    f"JPEG has {jpeg_res['trailing_bytes_count']} trailing bytes ({jpeg_res['trailing_magic']}); carve or extract payload"
                )
            if jpeg_res.get("flags_found"):
                triage["flags_found"] = list(set(triage["flags_found"] + jpeg_res["flags_found"]))
        elif magic.startswith((b"\xd4\xc3\xb2\xa1", b"\xa1\xb2\xc3\xd4", b"\x4d\x3c\xb2\xa1", b"\xa1\xb2\x3c\x4d")):
            pcap_res = _parse_pcap_pure(path, max_flows=10)
            triage["pcap_summary"] = {
                "packet_count": pcap_res["packet_count"],
                "dns_queries": pcap_res["dns_queries"][:10],
                "geo_hits": pcap_res["geo_hits"],
            }
            triage["recommendations"].append("PCAP capture: run duachuot_pcap_probe to dissect conversations and DNS queries")
        elif magic.startswith(b"RIFF") and len(magic) >= 12 and magic[8:12] == b"WAVE":
            lsb = _lsb_analysis(path)
            triage["wav_lsb"] = lsb
            if lsb.get("suspicious"):
                triage["recommendations"].append("WAV audio has suspicious LSB bias deviation; run duachuot_stego_probe")

        if embedded:
            triage["recommendations"].append(
                f"Found {len(embedded)} embedded signatures (first: {embedded[0]['signature']} at {embedded[0]['hex_offset']}); carve with binwalk/foremost"
            )
        if flags_found:
            triage["recommendations"].append(f"Flag pattern(s) identified in plaintext: {flags_found}")
        if entropy["entropy"] > 7.2:
            triage["recommendations"].append("High entropy detected (>7.2); file is encrypted, compressed, or contains high-density shellcode")

        return triage
    except Exception as exc:
        return format_error_response(exc)
