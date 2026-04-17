from __future__ import annotations

"""
Reference narratives for how common security controls react.
"""

DETECTION_RESPONSE: dict[str, dict[str, str]] = {
    "malware_c2_burst": {
        "likely_detectors": (
            "NGFW with IPS, sandbox file analysis, EDR on endpoints, "
            "DNS/firewall logging for rare FQDNs, TLS inspection (where policy allows)."
        ),
        "typical_response": (
            "Alerts correlated to a single host; automated block of malicious IP/DNS, "
            "quarantine of payload hash, optional TCP reset or session deny on egress."
        ),
        "operator_actions": (
            "Incident ticket, host isolation, PCAP retention for forensics, "
            "threat-intel feed update, user notification if phishing vector."
        ),
    },
    "intrusion_port_scan": {
        "likely_detectors": (
            "IDS/IPS signature for horizontal scans, flow telemetry (NetFlow/IPFIX), "
            "RST/FIN anomalies, honeypot tripwires, cloud VPC flow logs."
        ),
        "typical_response": (
            "Rate-limit or shun source IP, temporary ACL deny, "
            "increase logging verbosity on targeted segments."
        ),
        "operator_actions": (
            "Validate false-positive risk, block at perimeter, "
            "search for successful follow-on connections from same source."
        ),
    },
}


def mitigation_strategies() -> list[tuple[str, str]]:
    return [
        (
            "Segmentation & least privilege",
            "Restrict east-west paths so malware staging and scans hit fewer targets; "
            "micro-segmentation or VLAN ACLs reduce blast radius.",
        ),
        (
            "Threat-informed IPS tuning",
            "Enable balanced IPS policies with suppression for noisy signatures; "
            "correlate with asset criticality.",
        ),
        (
            "East-west visibility",
            "NetFlow plus DNS logging to spot beaconing and lateral movement early.",
        ),
        (
            "Capacity headroom",
            "Size NGFW/IPS for attack+legitimate peaks; enable hardware offload where available.",
        ),
        (
            "Automation with human review",
            "SOAR playbooks for block/quarantine with analyst checkpoints for business-critical apps.",
        ),
    ]
