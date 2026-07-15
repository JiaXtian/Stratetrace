"""Command-line interface."""

from __future__ import annotations

import argparse
import sys
from pathlib import Path
from typing import Optional, Sequence

from . import __version__
from .backend import BackendError, PrivilegeError, RawIPv4Backend, ScriptedBackend
from .controller import TraceConfig, TraceController, resolve_ipv4
from .model import ProbeProtocol
from .report import render_json, render_text


PROFILES = {
    "fast": {"p": 0.50, "delta": 0.20, "rounds": 1, "temporal": 2, "max_probes": 256},
    "default": {"p": 0.25, "delta": 0.10, "rounds": 2, "temporal": 3, "max_probes": 512},
    "thorough": {"p": 0.10, "delta": 0.01, "rounds": 3, "temporal": 5, "max_probes": 4096},
}


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="stratatrace",
        description=(
            "Boundary-aware, confidence-bounded adaptive traceroute. "
            "Raw probing requires root/CAP_NET_RAW."
        ),
    )
    parser.add_argument("target", help="IPv4 address or hostname")
    parser.add_argument("--version", action="version", version=f"%(prog)s {__version__}")
    parser.add_argument(
        "--protocol",
        choices=[item.value for item in ProbeProtocol],
        default=ProbeProtocol.UDP.value,
        help="target traffic class (default: udp)",
    )
    parser.add_argument("-m", "--max-hops", type=int, default=30)
    parser.add_argument("-w", "--timeout", type=float, default=1.0, help="batch receive timeout in seconds")
    parser.add_argument("--pacing-ms", type=float, default=1.0, help="delay between probes in a matched batch")
    parser.add_argument(
        "--dport",
        type=int,
        help="fixed destination port (default: UDP 33434, TCP 443)",
    )
    parser.add_argument("--sport", type=int, help="fixed UDP/TCP source port")
    parser.add_argument(
        "--tcp-syn-profile",
        choices=("standard", "minimal"),
        default="standard",
        help=(
            "TCP SYN shape: standard uses common MSS/SACK/timestamp/window-scale "
            "options; minimal sends a bare SYN (default: standard)"
        ),
    )
    parser.add_argument("--source", help="explicit IPv4 source address")
    parser.add_argument(
        "--allow-benchmark-address",
        action="store_true",
        help="allow 198.18.0.0/15 only for an intentional isolated RFC 2544 lab",
    )
    parser.add_argument("--payload-size", type=int, default=32)
    parser.add_argument("--profile", choices=PROFILES, default="default")
    parser.add_argument(
        "--min-detectable-prob",
        type=float,
        help="p_min: smallest behavior mass covered by the CAP bound",
    )
    parser.add_argument(
        "--miss-prob",
        type=float,
        help="delta: maximum modeled probability of missing behavior >= p_min",
    )
    parser.add_argument("--baseline-rounds", type=int)
    parser.add_argument(
        "--temporal-samples",
        type=int,
        help="fixed-flow repeat target for local behavior evidence",
    )
    parser.add_argument("--canary-flows", type=int, default=1)
    parser.add_argument(
        "--tail-guard-hops",
        type=int,
        default=3,
        help="silent TTL guard retained in baseline repeats (default: 3)",
    )
    parser.add_argument(
        "--global-cap",
        action="store_true",
        help="apply the CAP coverage guarantee to every TTL (higher probe cost)",
    )
    parser.add_argument("--max-probes", type=int)
    parser.add_argument("--seed", type=int, help="repeatable flow-token generation")
    parser.add_argument(
        "--simulate",
        type=Path,
        metavar="SCENARIO.json",
        help="use a deterministic scenario instead of raw sockets",
    )
    parser.add_argument("--json", action="store_true", help="emit machine-readable JSON")
    parser.add_argument(
        "--include-observations",
        action="store_true",
        help="include individual probes in JSON (can be large)",
    )
    parser.add_argument("-v", "--verbose", action="store_true")
    return parser


def main(argv: Optional[Sequence[str]] = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    profile = PROFILES[args.profile]
    protocol = ProbeProtocol(args.protocol)
    destination_port = (
        args.dport
        if args.dport is not None
        else 443
        if protocol == ProbeProtocol.TCP
        else 33434
    )
    config = TraceConfig(
        protocol=protocol,
        max_hops=args.max_hops,
        timeout=args.timeout,
        pacing_ms=args.pacing_ms,
        baseline_rounds=(
            args.baseline_rounds
            if args.baseline_rounds is not None
            else int(profile["rounds"])
        ),
        temporal_samples=(
            args.temporal_samples
            if args.temporal_samples is not None
            else int(profile["temporal"])
        ),
        canary_flows=args.canary_flows,
        tail_guard_hops=args.tail_guard_hops,
        global_cap=args.global_cap,
        min_detectable_probability=(
            args.min_detectable_prob
            if args.min_detectable_prob is not None
            else float(profile["p"])
        ),
        miss_probability=(
            args.miss_prob if args.miss_prob is not None else float(profile["delta"])
        ),
        max_probes=(
            args.max_probes if args.max_probes is not None else int(profile["max_probes"])
        ),
        destination_port=destination_port,
        source_port=args.sport,
        tcp_syn_profile=args.tcp_syn_profile,
        seed=args.seed,
        payload_size=args.payload_size,
    )
    backend = None
    try:
        config.validate()
        if args.simulate:
            backend = ScriptedBackend(args.simulate)
        else:
            destination = resolve_ipv4(args.target)
            backend = RawIPv4Backend(
                destination=destination,
                source=args.source,
                timeout=config.timeout,
                pacing_ms=config.pacing_ms,
                allow_benchmark_address=args.allow_benchmark_address,
                protocol=config.protocol,
                tcp_syn_profile=config.tcp_syn_profile,
            )
        result = TraceController(backend, config).run(args.target)
        if args.json:
            print(render_json(result, include_observations=args.include_observations))
        else:
            print(render_text(result, verbose=args.verbose))
        if result.interrupted:
            return 130
        return 0 if result.reached else 1
    except PrivilegeError as exc:
        print(f"stratatrace: permission error: {exc}", file=sys.stderr)
        return 3
    except (BackendError, OSError, ValueError) as exc:
        print(f"stratatrace: {exc}", file=sys.stderr)
        return 2
    except KeyboardInterrupt:
        print("stratatrace: interrupted", file=sys.stderr)
        return 130
    finally:
        if backend is not None:
            backend.close()
