"""CLI commands: geo, ops, platform (local, offline, deterministic)."""

from __future__ import annotations

from typing import Any

from app.cli.context import CLIContext
from app.cli.output import emit_json, key_values, table


def handle_geo(ctx: CLIContext, args) -> int:
    if args.geo_command == "convert":
        return handle_geo_convert(ctx, args)
    if args.geo_command == "reverse":
        return handle_geo_reverse(ctx, args)
    if args.geo_command == "verify":
        return handle_geo_verify(ctx, args)
    raise ValueError(f"Unsupported geo command: {args.geo_command}")


def handle_ops(ctx: CLIContext, args) -> int:
    if args.ops_command == "check":
        return handle_ops_check(ctx, args)
    if args.ops_command == "jitter":
        return handle_ops_jitter(ctx, args)
    raise ValueError(f"Unsupported ops command: {args.ops_command}")


def handle_forensics(ctx: CLIContext, args) -> int:
    from app.tools.probes import duachuot_forensics_triage, duachuot_pcap_probe, duachuot_stego_probe

    if args.forensics_command == "triage":
        result = duachuot_forensics_triage(args.path)
        if ctx.json_output:
            emit_json(result)
            return 0 if result.get("ok") else 1
        if not result.get("ok"):
            print(f"Error: {result.get('error', {}).get('message', 'triage failed')}")
            return 1
        rows = [
            ("Artifact", result["path"]),
            ("Size", f"{result['size_bytes']} bytes"),
            ("File Type", result["file_type"]),
            ("MD5", result["hashes"]["md5"]),
            ("SHA256", result["hashes"]["sha256"]),
            ("Entropy", f"{result['entropy']['entropy']} / 8.0 ({result['entropy']['verdict']})"),
            ("Flags Found", ", ".join(result["flags_found"]) or "none"),
            ("Embedded Carve", f"{len(result['embedded_carve_candidates'])} candidates"),
        ]
        key_values(rows)
        if result.get("recommendations"):
            print("\nRecommendations:")
            for rec in result["recommendations"]:
                print(f"  • {rec}")
        return 0

    if args.forensics_command == "stego":
        result = duachuot_stego_probe(args.path)
        if ctx.json_output:
            emit_json(result)
            return 0 if result.get("ok") else 1
        if not result.get("ok"):
            print(f"Error: {result.get('error', {}).get('message', 'stego probe failed')}")
            return 1
        rows = [
            ("Artifact", result["path"]),
            ("Carrier Kind", result.get("kind", "unknown")),
            ("MD5", result.get("hashes", {}).get("md5", "n/a")),
            ("Entropy", f"{result.get('entropy', {}).get('entropy', 'n/a')} / 8.0"),
        ]
        if "png_analysis" in result:
            png = result["png_analysis"]
            rows.extend(
                [
                    ("PNG Chunks", str(png.get("chunk_count"))),
                    (
                        "Trailing Bytes",
                        f"{png.get('trailing_bytes_count')} ({png.get('trailing_magic') or 'none'})",
                    ),
                    (
                        "Dimension Tampering",
                        f"DETECTED (suggested: {png.get('suggested_height')})"
                        if png.get("ihdr_dimension_tampering")
                        else "no",
                    ),
                    ("Flags In Stego", ", ".join(png.get("flags_found", [])) or "none"),
                ]
            )
        if "lsb_analysis" in result:
            lsb = result["lsb_analysis"]
            rows.extend(
                [
                    ("WAV LSB Deviation", str(lsb.get("deviation_from_0_5"))),
                    ("LSB Suspicious", "YES" if lsb.get("suspicious") else "no"),
                ]
            )
        key_values(rows)
        return 0

    if args.forensics_command == "pcap":
        result = duachuot_pcap_probe(args.path, max_flows=getattr(args, "max_flows", 30))
        if ctx.json_output:
            emit_json(result)
            return 0 if result.get("ok") else 1
        if not result.get("ok"):
            print(f"Error: {result.get('error', {}).get('message', 'pcap probe failed')}")
            return 1
        rows = [
            ("Capture", result["path"]),
            ("MD5", result.get("hashes", {}).get("md5", "n/a")),
            ("Packets", str(result.get("summary", {}).get("packet_count", "n/a"))),
            ("Geo Hits", ", ".join(result.get("geo_hints", {}).get("hits", [])) or "none"),
        ]
        key_values(rows)
        if result.get("dns_queries", {}).get("stdout"):
            print("\nDNS Queries:")
            for line in result["dns_queries"]["stdout"].splitlines()[:15]:
                print(f"  • {line}")
        return 0

    raise ValueError(f"Unsupported forensics command: {args.forensics_command}")


def _dump(ctx: CLIContext, payload: dict[str, Any], rows: list[tuple[str, str]]) -> int:
    if ctx.json_output:
        emit_json(payload)
        return 0
    key_values(rows)
    return 0


def handle_geo_convert(ctx: CLIContext, args) -> int:
    from app.geo.convert import datum_transform, from_utm, normalize_coordinate, to_dms, to_mgrs, to_utm

    if args.dms_lat and args.dms_lon:
        lat = normalize_coordinate(args.dms_lat, ref=args.ref, axis="lat")["decimal"]
        lon = normalize_coordinate(args.dms_lon, ref=args.ref, axis="lon")["decimal"]
    elif args.utm_zone and args.easting is not None and args.northing is not None:
        converted = from_utm(args.utm_zone, args.hemisphere, args.easting, args.northing)
        lat, lon = converted["lat"], converted["lon"]
    elif args.lat is not None and args.lon is not None:
        lat, lon = args.lat, args.lon
    else:
        raise ValueError("provide --lat/--lon, --dms-lat/--dms-lon, or --utm-zone --easting --northing")

    if args.datum_src != args.datum_dst:
        transformed = datum_transform(lat, lon, source=args.datum_src, target=args.datum_dst)
        lat, lon = transformed["lat"], transformed["lon"]
    payload = {
        "ok": True,
        "lat": lat,
        "lon": lon,
        "dms": {"lat": to_dms(lat, axis="lat"), "lon": to_dms(lon, axis="lon")},
        "utm": to_utm(lat, lon),
        "mgrs": to_mgrs(lat, lon),
    }
    rows = [
        ("Decimal", f"{lat:.7f}, {lon:.7f}"),
        ("DMS", f'{payload["dms"]["lat"]}  {payload["dms"]["lon"]}'),
        ("UTM", f'{payload["utm"]["zone"]}{payload["utm"]["hemisphere"]} {payload["utm"]["easting_m"]:.0f} {payload["utm"]["northing_m"]:.0f}'),
        ("MGRS", payload["mgrs"]["mgrs_string"]),
    ]
    return _dump(ctx, payload, rows)


def handle_geo_reverse(ctx: CLIContext, args) -> int:
    from app.geo.reverse import nearest_landmarks

    matches = nearest_landmarks(args.lat, args.lon, limit=args.limit or 5)
    payload = {"ok": True, "lat": args.lat, "lon": args.lon, "matches": matches}
    if ctx.json_output:
        emit_json(payload)
        return 0
    table(
        ["Landmark", "Distance (m)", "Bearing (deg)"],
        [[m["name"], f"{m['distance_m']:.0f}", f"{m['bearing_deg']:.0f}"] for m in matches],
    )
    return 0


def handle_geo_verify(ctx: CLIContext, args) -> int:
    from app.tools.geo_tools import duachuot_geo_verify

    result = duachuot_geo_verify(args.lat, args.lon)
    if ctx.json_output:
        emit_json(result)
        return 0
    key_values(
        [
            ("Coordinates", f"{args.lat}, {args.lon}"),
            ("Independent facts", f"{result['independent_fact_count']} / {result['required_facts']}"),
            ("Confidence", f"{result['confidence']}"),
            ("Status", "BLOCKER" if result["blocked"] else "supported"),
            ("Conclusion", result["conclusion"]),
        ]
    )
    return 1 if result["blocked"] else 0


def handle_ops_check(ctx: CLIContext, args) -> int:
    from app.ops.gate import gate_command, gate_remote_request

    result = gate_remote_request(args.target) if args.kind == "remote" else gate_command(args.target)
    if ctx.json_output:
        emit_json({"ok": True, **result})
        return 0 if result["allowed"] else 1
    status = "ALLOWED" if result["allowed"] else f"BLOCKED ({result['rule']})"
    key_values(
        [
            ("Mode", result["mode"]),
            ("Status", status),
            ("Subject", result["subject"]),
            ("Message", result["message"]),
        ]
    )
    return 0 if result["allowed"] else 1


def handle_ops_jitter(ctx: CLIContext, _args) -> int:
    from app.ops.gate import suggest_jitter_seconds

    delay = suggest_jitter_seconds()
    payload = {"ok": True, "delay_seconds": delay}
    if ctx.json_output:
        emit_json(payload)
        return 0
    print(f"wait {delay:.2f}s before the next remote request")
    return 0


def handle_platform(ctx: CLIContext, args) -> int:
    from app.platform import probe_platform, tool_supported

    probe = probe_platform()
    if args.tool:
        probe = {**probe, "tool": tool_supported(args.tool)}
    if ctx.json_output:
        emit_json({"ok": True, **probe})
        return 0
    rows = [
        ("OS", probe["os"]),
        ("Arch", probe["arch"]),
        ("Distro", probe["distro_id"] or "n/a"),
        ("Like", probe["distro_like"] or "n/a"),
        ("Shell", probe["shell"]),
        ("Package managers", ", ".join(probe["package_managers"]) or "n/a"),
        ("Python", probe["python_version"]),
    ]
    if args.tool:
        tool = probe["tool"]
        rows.append(("Tool", f'{args.tool}: {"available" if tool["available"] else "missing"} ({tool["method"]})'))
    return _dump(ctx, {"ok": True, **probe}, rows)