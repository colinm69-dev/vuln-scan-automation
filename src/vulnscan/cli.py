"""Command line interface."""

from __future__ import annotations

import argparse
import sys
from datetime import UTC, datetime
from pathlib import Path

from vulnscan import __version__, safety
from vulnscan.parser import parse_xml
from vulnscan.report import redact, to_json, to_markdown
from vulnscan.scanner import PROFILES, ScanError, ScanOptions, run_nmap
from vulnscan.scoring import BANDS, assess, exceeds, load_rules

EXIT_OK = 0
EXIT_ERROR = 1
EXIT_THRESHOLD = 2


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="vulnscan",
        description="Scan a lab network with Nmap and produce a prioritised report.",
    )
    p.add_argument("targets", nargs="*", help="IP addresses or CIDR ranges (hostnames are not accepted)")
    p.add_argument("--from-xml", metavar="FILE", help="Parse an existing Nmap XML file instead of scanning")
    p.add_argument(
        "--authorised", action="store_true", help="Confirm you have permission to scan these targets"
    )
    p.add_argument("--allow-public", action="store_true", help="Allow non-private ranges (own networks only)")
    p.add_argument(
        "--max-hosts", type=int, default=safety.DEFAULT_MAX_HOSTS, help="Refuse larger target sets"
    )
    p.add_argument("--profile", choices=sorted(PROFILES), default="standard")
    p.add_argument("--timing", type=int, default=3, help="Nmap timing template 0-5 (default 3)")
    p.add_argument("--vulners", action="store_true", help="Use the vulners NSE script for CVE data")
    p.add_argument("--rules", metavar="FILE", help="Custom rules TOML file")
    p.add_argument("--format", default="md,json", help="Comma-separated: md, json (default both)")
    p.add_argument("--output-dir", default="reports", help="Where to write reports (default ./reports)")
    p.add_argument("--name", help="Base file name (default scan-<timestamp>)")
    p.add_argument("--save-xml", action="store_true", help="Also save the raw Nmap XML")
    p.add_argument("--redact", action="store_true", help="Replace addresses and hostnames with labels")
    p.add_argument(
        "--fail-on",
        choices=[b.lower() for b in BANDS[:4]],
        help="Exit 2 if any finding is at or above this band",
    )
    p.add_argument("--version", action="version", version=f"%(prog)s {__version__}")
    return p


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)

    try:
        if args.from_xml:
            xml_text = Path(args.from_xml).read_text(encoding="utf-8")
        else:
            if not args.targets:
                print("error: give at least one target, or use --from-xml", file=sys.stderr)
                return EXIT_ERROR
            if not args.authorised:
                print(
                    "error: add --authorised to confirm you have permission to scan these targets",
                    file=sys.stderr,
                )
                return EXIT_ERROR
            networks = safety.parse_targets(args.targets)
            safety.validate(networks, allow_public=args.allow_public, max_hosts=args.max_hosts)
            opts = ScanOptions(profile=args.profile, timing=args.timing, vulners=args.vulners)
            print(
                f"Scanning {len(networks)} target range(s) with profile '{args.profile}'...", file=sys.stderr
            )
            xml_text = run_nmap([str(n) for n in networks], opts)

        meta, hosts = parse_xml(xml_text)
        results = assess(hosts, load_rules(args.rules))
        if args.redact:
            meta, results = redact(meta, results)

        formats = {f.strip().lower() for f in args.format.split(",") if f.strip()}
        unknown = formats - {"md", "json"}
        if unknown:
            print(f"error: unknown format(s): {', '.join(sorted(unknown))}", file=sys.stderr)
            return EXIT_ERROR

        out_dir = Path(args.output_dir)
        out_dir.mkdir(parents=True, exist_ok=True)
        stem = args.name or datetime.now(UTC).strftime("scan-%Y%m%d-%H%M%S")
        written: list[Path] = []
        if "md" in formats:
            path = out_dir / f"{stem}.md"
            path.write_text(to_markdown(meta, results), encoding="utf-8")
            written.append(path)
        if "json" in formats:
            path = out_dir / f"{stem}.json"
            path.write_text(to_json(meta, results), encoding="utf-8")
            written.append(path)
        if args.save_xml and not args.from_xml:
            if args.redact:
                print(
                    "note: --save-xml ignored because the raw XML contains addresses and --redact is set",
                    file=sys.stderr,
                )
            else:
                path = out_dir / f"{stem}.xml"
                path.write_text(xml_text, encoding="utf-8")
                written.append(path)
    except (safety.TargetError, ScanError, OSError, ValueError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return EXIT_ERROR

    for path in written:
        print(f"Wrote {path}")
    if args.fail_on and exceeds(results, args.fail_on.capitalize()):
        print(f"Findings at or above '{args.fail_on}' were found.", file=sys.stderr)
        return EXIT_THRESHOLD
    return EXIT_OK
