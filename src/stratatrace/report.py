"""Human and JSON reporting with explicit epistemic labels."""

from __future__ import annotations

import json
from typing import List

from .model import SegmentType, TraceResult


def render_json(result: TraceResult, include_observations: bool = False) -> str:
    return json.dumps(
        result.to_dict(include_observations=include_observations),
        indent=2,
        sort_keys=True,
        ensure_ascii=False,
    )


def render_text(result: TraceResult, verbose: bool = False) -> str:
    lines: List[str] = []
    lines.append(
        f"StrataTrace to {result.target} ({result.destination}) from {result.source}, "
        f"{result.protocol.value.upper()}, {len(result.hops)} hops analyzed"
    )
    lines.append(
        f"policy: p_min={result.policy['min_detectable_probability']:.3f}, "
        f"delta={result.policy['requested_miss_probability']:.3f}, "
        f"required complete samples={result.policy['required_complete_samples']}"
    )
    lines.append("")
    for hop in result.hops:
        if hop.primary is None:
            line = f"{hop.ttl:2d}  *"
        else:
            rtt = f"{hop.rtt_median_ms:.3f} ms" if hop.rtt_median_ms is not None else "n/a"
            alternatives = ""
            if len(hop.responders) > 1:
                alternatives = "  {" + ", ".join(
                    f"{address} x{count}" for address, count in hop.responders
                ) + "}"
            line = f"{hop.ttl:2d}  {hop.primary:<39} {rtt}{alternatives}"
        evidence = []
        if hop.mpls_labels:
            evidence.append(
                "MPLS "
                + ",".join(
                    f"label={item.label}/tc={item.traffic_class}/s={int(item.bottom_of_stack)}/ttl={item.ttl}"
                    for item in hop.mpls_labels
                )
            )
        if hop.interfaces:
            evidence.append(
                "interface "
                + ",".join(
                    f"{item.role}:{item.address or item.name or item.ifindex or '?'}"
                    for item in hop.interfaces
                )
            )
        if hop.mutations:
            evidence.append("mutation " + ",".join(hop.mutations))
        if evidence:
            line += "  [" + "; ".join(evidence) + "]"
        lines.append(line)

    special = [
        item
        for item in result.segments
        if item.type != SegmentType.DIRECT or result.policy.get("global_cap")
    ]
    if special:
        lines.append("")
        lines.append("Behavior boundaries:")
        for segment in special:
            arrow = "=>" if segment.type == SegmentType.OPAQUE else "->"
            boundaries = f"{segment.ingress or '?'} {arrow} {segment.egress or '?'}"
            certificate = segment.certificate
            status = "CERTIFIED" if certificate.certified else "BUDGET-LIMITED"
            lines.append(
                f"  TTL {segment.first_ttl}-{segment.last_ttl}  "
                f"{segment.type.value.upper():<10} {boundaries}"
            )
            if segment.explicit_mechanism:
                lines.append(f"    explicit evidence: {segment.explicit_mechanism}")
            lines.append(
                f"    coverage: {status}; n={certificate.sample_count}, "
                f"P(miss behavior with p>={certificate.min_detectable_probability:.3f}) "
                f"<={certificate.miss_probability_bound:.4f}"
            )
            if segment.empirical_stability is not None:
                lines.append(f"    fixed-flow empirical stability: {segment.empirical_stability:.3f}")
            for reason in segment.reasons:
                lines.append(f"    - {reason}")
            if verbose:
                if segment.fixed_outcomes:
                    lines.append("    fixed: " + _format_outcomes(segment.fixed_outcomes))
                if segment.varied_outcomes:
                    lines.append("    varied: " + _format_outcomes(segment.varied_outcomes))
    else:
        lines.append("")
        lines.append("Behavior boundaries: none detected")

    lines.append("")
    lines.append(
        f"probes: {result.probe_count} total = {result.baseline_probe_count} baseline + "
        f"{result.adaptive_probe_count} adaptive; duration {result.duration_ms:.1f} ms; "
        f"destination {'reached' if result.reached else 'not reached'}"
    )
    for warning in result.warnings:
        lines.append(f"warning: {warning}")
    lines.append(
        "note: OPAQUE means a repeatable observation gap between visible boundaries; "
        "it does not, by itself, identify hidden devices or a tunnel protocol."
    )
    return "\n".join(lines)


def _format_outcomes(outcomes: object) -> str:
    return "; ".join(f"{signature} x{count}" for signature, count in outcomes)  # type: ignore[misc]
