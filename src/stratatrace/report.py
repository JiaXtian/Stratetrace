"""Human and JSON reporting with explicit epistemic labels."""

from __future__ import annotations

import json
from typing import List

from .model import ReplyKind, SegmentType, TraceResult


def render_json(result: TraceResult, include_observations: bool = False) -> str:
    return json.dumps(
        result.to_dict(include_observations=include_observations),
        indent=2,
        sort_keys=True,
        ensure_ascii=False,
    )


def render_text(result: TraceResult, verbose: bool = False) -> str:
    lines: List[str] = []
    span = f", TTL 1-{result.probed_max_ttl} probed" if result.probed_max_ttl > len(result.hops) else ""
    partial = ", PARTIAL" if result.interrupted else ""
    destination_port = result.policy.get("destination_port")
    traffic_class = result.protocol.value.upper()
    if destination_port:
        traffic_class += f"/{destination_port}"
    lines.append(
        f"StrataTrace to {result.target} ({result.destination}) from {result.source}, "
        f"{traffic_class}, {len(result.hops)} TTL positions analyzed{span}{partial}"
    )
    lines.append(
        f"policy: p_min={result.policy['min_detectable_probability']:.3f}, "
        f"delta={result.policy['requested_miss_probability']:.3f}, "
        f"required flow samples={result.policy['required_complete_samples']}; "
        f"fixed temporal samples={result.policy['temporal_samples']}"
    )
    if result.protocol.value == "tcp":
        lines[-1] += f"; TCP SYN profile={result.policy.get('tcp_syn_profile', 'standard')}"
    if result.tcp_connect_control is not None:
        control = result.tcp_connect_control
        transport_evidence = (
            "; positive transport response"
            if control.positive_transport_response
            else "; no positive transport response"
        )
        lines.append(
            f"TCP kernel control: {control.status.value.upper()}{transport_evidence}; "
            f"{control.duration_ms:.1f} ms; source={control.source or '?'} "
            "(separate reachability evidence, not a path hop)"
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
        if hop.sent and hop.answered < hop.sent:
            evidence.append(f"ICMP replies {hop.answered}/{hop.sent}")
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
            arrow = (
                "=>"
                if segment.type == SegmentType.OPAQUE
                else "~>"
                if segment.type == SegmentType.SILENT_TAIL
                else "->"
            )
            boundaries = f"{segment.ingress or '?'} {arrow} {segment.egress or '?'}"
            certificate = segment.certificate
            lines.append(
                f"  TTL {segment.first_ttl}-{segment.last_ttl}  "
                f"{segment.type.value.upper():<10} {boundaries}"
            )
            if segment.explicit_mechanism:
                lines.append(f"    explicit evidence: {segment.explicit_mechanism}")
            if certificate.method == "silent_tail_observation":
                lines.append(
                    f"    tail evidence: OBSERVED; n={certificate.sample_count} complete "
                    "fixed-flow sweep(s); open-ended/no egress, so no CAP certification"
                )
            elif certificate.method == "flow_variant_coverage":
                status = "CERTIFIED" if certificate.certified else "BUDGET-LIMITED"
                lines.append(
                    f"    flow coverage: {status}; n={certificate.sample_count}/"
                    f"{certificate.required_sample_count}, "
                    f"P(miss behavior with p>={certificate.min_detectable_probability:.3f}) "
                    f"<={certificate.miss_probability_bound:.4f}"
                )
            else:
                status = "REPEATED" if certificate.certified else "PARTIAL"
                lines.append(
                    f"    fixed-flow evidence: {status}; n={certificate.sample_count}/"
                    f"{certificate.required_sample_count} temporal samples; "
                    "no cross-flow coverage claim"
                )
            if segment.empirical_stability is not None:
                lines.append(
                    f"    fixed-flow responder stability: {segment.empirical_stability:.3f}"
                )
            if segment.response_rate is not None:
                lines.append(f"    fixed-flow response rate: {segment.response_rate:.3f}")
            for ttl, responders in segment.branches:
                lines.append(
                    f"    TTL {ttl} branches: "
                    + ", ".join(
                        f"{address} x{count}" for address, count in responders
                    )
                )
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
    if result.reached:
        reachability = "destination reached"
        if result.termination and result.termination.tcp_flags is not None:
            reachability += " (" + _tcp_flag_name(result.termination.tcp_flags) + ")"
    elif result.termination:
        reachability = "destination not confirmed; " + _format_termination(result)
    else:
        reachability = "destination not reached (no terminal response)"
    lines.append(
        f"probes: {result.probe_count} total = {result.baseline_probe_count} baseline + "
        f"{result.adaptive_probe_count} adaptive; duration {result.duration_ms:.1f} ms; "
        f"{reachability}"
    )
    for warning in result.warnings:
        lines.append(f"warning: {warning}")
    lines.append(
        "note: OPAQUE means a repeatable observation gap between visible boundaries; "
        "it does not, by itself, identify hidden devices or a tunnel protocol."
    )
    if any(item.type == SegmentType.SILENT_TAIL for item in result.segments):
        lines.append(
            "note: SILENT_TAIL means probes continued beyond the last visible responder "
            "without a visible egress; it is not evidence that those TTLs are router hops."
        )
    return "\n".join(lines)


def _format_outcomes(outcomes: object) -> str:
    return "; ".join(f"{signature} x{count}" for signature, count in outcomes)  # type: ignore[misc]


_UNREACHABLE_CODES = {
    0: "network unreachable",
    1: "host unreachable",
    2: "protocol unreachable",
    3: "port unreachable",
    4: "fragmentation needed",
    5: "source route failed",
    9: "network administratively prohibited",
    10: "host administratively prohibited",
    13: "communication administratively prohibited",
}


def _format_termination(result: TraceResult) -> str:
    termination = result.termination
    if termination is None:
        return "no terminal response"
    if termination.kind == ReplyKind.UNREACHABLE and termination.icmp_type == 3:
        detail = _UNREACHABLE_CODES.get(
            termination.icmp_code,
            f"unreachable code {termination.icmp_code}",
        )
    else:
        detail = termination.kind.value.replace("_", " ")
    return (
        f"terminal ICMP {detail} at TTL {termination.ttl} from "
        f"{termination.responder or '?'}"
    )


def _tcp_flag_name(flags: int) -> str:
    if flags & 0x04:
        return "TCP RST-ACK"
    if flags & 0x02 and flags & 0x10:
        return "TCP SYN-ACK"
    return f"TCP flags=0x{flags:02x}"
