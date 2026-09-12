from __future__ import annotations
import json
from pathlib import Path

RECORDS = Path(__file__).resolve().parents[1] / "private" / "catalogs" / "_source" / "ecc_records.json"

CURATION: dict[str, tuple[int, str]] = {
    "1-5-3-1": (3, "project management gate at project start; process, declaration only"),
    "1-5-3-2": (3, "gate before major infrastructure change; process, declaration"),
    "1-5-3-3": (3, "gate during third party service planning; process, declaration"),
    "1-5-3-4": (3, "gate before new service or product release; process, declaration"),
    "1-6-2-1": (3, "vuln assessment as a project gate; the gate itself is a process claim, declaration"),
    "1-6-2-2": (3, "config and hardening review before launch; process gate, declaration"),
    "1-6-3-1": (3, "use of secure coding standards; internal SDLC policy, declaration"),
    "1-6-3-2": (3, "trusted and licensed dev sources; internal SDLC policy, declaration"),
    "1-6-3-3": (3, "software compliance testing; marginal (T2 if test reports treated as evidence) but a project-management process claim, kept T3 with the rest of 1-6-3"),
    "1-6-3-4": (3, "secure integration between applications; internal SDLC practice, declaration"),
    "1-6-3-5": (3, "config and hardening review before software release; process, declaration"),
    "1-9-3-1": (3, "employment contract security and NDA clauses; HR, declaration"),
    "1-9-3-2": (3, "screening and vetting for sensitive positions; HR, declaration"),
    "1-9-4-1": (3, "security awareness at onboarding and during employment; behavioral, declaration"),
    "1-9-4-2": (3, "compliance with security policies by personnel; behavioral, declaration"),
    "1-10-3-1": (3, "awareness on phishing and email handling; training content, declaration"),
    "1-10-3-2": (3, "awareness on mobile and storage media; training content, declaration"),
    "1-10-3-3": (3, "awareness on secure browsing; training content, declaration"),
    "1-10-3-4": (3, "awareness on social media use; training content, declaration"),
    "1-10-4-1": (3, "specialized awareness for the cybersecurity function; training audience, declaration"),
    "1-10-4-2": (3, "specialized awareness for developers and asset custodians; training audience, declaration"),
    "1-10-4-3": (3, "specialized awareness for executives; training audience, declaration"),
    "2-2-3": (1, "IAM umbrella; subcontrols 2-2-3-1/2 (exposed management port) are externally observable -> best-child T1"),
    "2-3-3": (1, "information systems protection umbrella; 2-3-3-3 (end of life exposed software) is externally observable -> best-child T1"),
    "2-4-3": (1, "email protection umbrella; 2-4-3-5 (SPF/DKIM/DMARC/MTA-STS) is externally observable -> best-child T1"),
    "2-5-3": (1, "network security umbrella; 2-5-3-1/2/5/7/9 (ports, dev env, DNSSEC, DDoS) are externally observable -> best-child T1"),
    "2-8-3": (1, "cryptography umbrella; 2-8-3-3 (TLS version, cipher, certificate) is externally observable -> best-child T1"),
    "2-10-3": (1, "vulnerability management umbrella; 2-10-3-1/4 (outdated exposed software) are externally observable -> best-child T1"),
    "2-15-3": (1, "external web application protection umbrella; 2-15-3-1/2/3/5 (WAF, DDoS, headers, login) are externally observable -> best-child T1"),
    "2-6-3": (2, "mobile and BYOD security; internal MDM and containerization config, not externally observable"),
    "2-9-3": (2, "backup and recovery; internal backup config and restore test evidence"),
    "2-11-3": (2, "penetration testing; internal process producing pentest reports as evidence"),
    "2-12-3": (2, "event logs and monitoring; internal SIEM and log retention, not externally observable"),
    "2-13-3": (2, "incident and threat management; internal IR plan and ticket records exist as evidence (T3 considered; tier is by evidence capability, not a given SME's maturity)"),
    "2-14-3": (3, "physical protection of assets; never externally observable, declaration"),
    "3-1-3": (3, "business continuity management; governance and process, declaration"),
    "4-1-2-1": (3, "third party NDA and secure data removal clauses; contractual, declaration"),
    "4-1-2-2": (3, "third party incident communication procedures; contractual, declaration"),
    "4-1-2-3": (3, "obligating third party to entity policies; contractual, declaration"),
    "4-1-3-1": (3, "third party risk assessment before contract; process, declaration"),
    "4-1-3-2": (3, "managed SOC remote access located in KSA; data residency, not reliably externally observable, declaration"),
    "4-2-3": (2, "cloud computing and hosting security; entity cloud security config and CSP contract (using cloud is partly external, securing it is not) -> internal assessment"),
}


def main() -> None:
    from collections import Counter

    records = json.loads(RECORDS.read_text(encoding="utf-8"))
    by_id = {r["id"]: r for r in records}
    assert set(CURATION) <= set(by_id), "curation references control ids absent from the catalog"

    pending = [r for r in records if r.get("tier_source") == "default-pending-expert"]
    changed_tier = []
    if pending:
        assert {r["id"] for r in pending} == set(CURATION), (
            f"pending defaults {{{len(pending)}}} do not match the 42 curation ids"
        )
        for cid, (intended, _why) in CURATION.items():
            rec = by_id[cid]
            if rec["tier"] != intended:
                changed_tier.append((cid, rec["tier"], intended))
            rec["tier"] = intended
            rec["tier_source"] = "author-curated"
        RECORDS.write_text(json.dumps(records, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
        print(f"applied curation to 42 rows; tier values changed on {len(changed_tier)}: {changed_tier}")
    else:
        print("curation already applied; running as a gate")

    for cid, (intended, _why) in CURATION.items():
        rec = by_id[cid]
        assert rec["tier"] == intended, (
            f"catalog drift: {cid} is tier {rec['tier']} but curated to {intended}"
        )
        assert rec.get("tier_source") == "author-curated", (
            f"{cid} tier_source is {rec.get('tier_source')}, expected author-curated"
        )
    assert sum(1 for r in records if r.get("tier_source") == "author-curated") == 42
    assert not any(r.get("tier_source") == "default-pending-expert" for r in records)
    print("gate ok: 42 author-curated, 0 default-pending-expert")
    print("tier_source:", dict(Counter(r["tier_source"] for r in records)))
    print("tier split:", dict(Counter(r["tier"] for r in records)))


if __name__ == "__main__":
    main()
