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

LATER: dict[str, tuple[int, str]] = {
    "1-5-3": (3, "risk assessment cases umbrella; its four subcontrols are declarations -> best-child T3"),
    "1-6-2": (2, "project management umbrella; 1-6-2-1 and 1-6-2-2 are T2 (rule 2) -> best-child T2"),
    "1-6-2-1": (2, "vulnerability assessment before launch leaves an assessment report -> rule 2, T2"),
    "1-6-2-2": (2, "configuration and hardening review before launch leaves a review record -> rule 2, T2"),
    "1-6-3": (2, "software development umbrella; 1-6-3-3 and 1-6-3-5 are T2 (rule 2) -> best-child T2"),
    "1-6-3-3": (2, "software compliance testing leaves test reports -> rule 2, T2"),
    "1-6-3-5": (2, "configuration and hardening review before release leaves a review record -> rule 2, T2"),
    "1-9-3": (3, "pre-employment umbrella (shall include as a minimum); both subcontrols T3 -> T3"),
    "1-9-4": (3, "during-employment umbrella (shall include as a minimum); both subcontrols T3 -> T3"),
    "1-10-3": (3, "awareness programme umbrella (including:); all four subcontrols T3 -> T3"),
    "1-10-4": (3, "specialised training umbrella (including:); all three subcontrols T3 -> T3"),
    "2-7-1": (2, "data protection requirements; its NCNICC subcontrols 2-7-1-2 and 2-7-1-3 are T2 -> T2"),
    "2-12-1": (2, "event log requirements; its NCNICC subcontrol 2-12-1-2 is T2 -> T2"),
    "2-9-3-3": (2, "periodic testing of backup recovery is a backup restoration test (the rubric's example) -> T2"),
    "2-11-3-2": (2, "periodic penetration tests leave a penetration test report (the rubric's example) -> T2"),
    "2-14-3-2": (2, "access and monitoring logs are logs (the rubric's example) -> T2"),
    "2-14-3": (2, "physical protection umbrella; 2-14-3-2 is T2 (rule 2) -> best-child T2"),
}

RECODE_2026_10_20: dict[str, tuple[int, str]] = {
    "2-2-3-1": (2, "an exposed SSH/RDP port shows no authentication requirement unmet; password configuration -> T2"),
    "2-2-3-2": (2, "an exposed SSH/RDP port does not show MFA absent; MFA configuration -> T2"),
    "2-2-3": (2, "IAM umbrella; every subcontrol T2 -> best-child T2"),
    "2-5-3-2": (2, "a dev server reachable from the internet does not show networks unisolated; firewall config -> T2"),
    "2-5-3-9": (2, "a missing DDoS fingerprint cannot show protection absent (upstream scrubbing is invisible) -> T2"),
    "2-10-3-1": (2, "an outdated version shows a patch not applied, not that assessment is not done; scan reports -> T2"),
    "2-15-3-1": (2, "the WAF read is passive, so a silent WAF is missed and absence is not shown; WAF config -> T2"),
    "2-15-3-2": (2, "multi-tier architecture is not observable from outside; design and config -> T2"),
    "2-15-3-5": (2, "a reachable login shows authentication exists, not that its factors are inadequate -> T2"),
    "2-8-3-1": (1, "TLS 1.0/1.1, a weak suite or a weak certificate key observed in a handshake is outside the NCS -> T1"),
    "2-8-3-2": (1, "an expired certificate in service, or a key created below strength, shows key lifecycle unmet -> T1"),
    "2-7-1": (1, "data protection requirements; its NCNICC subcontrol 2-7-1-3 is T1 -> best-child T1"),
    "1-2-2": (2, "who fills each position is in HR records (contracts, registration, qualifications) -> T2"),
    "1-6-3-1": (2, "use of secure coding standards leaves code review or static analysis records -> T2"),
    "1-6-3-2": (2, "trusted and licensed sources leave dependency manifests and licence records -> T2"),
    "1-6-3-4": (2, "secure integration leaves integration configuration -> T2"),
    "1-8-2": (2, "review and audit by other parties leaves their audit reports -> T2"),
    "1-9-3-1": (2, "the clauses are in the signed employment contracts -> T2"),
    "1-9-3-2": (2, "screening or vetting leaves its results -> T2"),
    "1-9-3": (2, "pre-employment umbrella; both subcontrols T2 -> best-child T2"),
    "1-9-4-1": (2, "awareness at onboarding and during employment leaves training completion records -> T2"),
    "1-9-4": (2, "during-employment umbrella; 1-9-4-1 is T2 -> best-child T2"),
    "1-10-4-1": (2, "specialised training leaves completion records -> T2"),
    "1-10-4-2": (2, "specialised training leaves completion records -> T2"),
    "1-10-4-3": (2, "specialised training leaves completion records -> T2"),
    "1-10-4": (2, "specialised training umbrella; all three subcontrols T2 -> best-child T2"),
    "2-2-3-5": (2, "an access review leaves recertification and revocation records in the IAM system -> T2"),
    "2-4-3-3": (2, "email archiving and backup leave configuration and backup logs -> T2"),
    "2-4-3-4": (2, "email APT protection leaves sandbox configuration and logs -> T2"),
    "2-5-3-8": (2, "browsing APT protection leaves proxy and sandbox configuration -> T2"),
    "2-10-3-5": (2, "subscriptions to vulnerability sources leave subscription records -> T2"),
    "2-13-3-3": (2, "reports to the NCA are submissions to another party -> T2"),
    "2-13-3-4": (2, "notifications shared with the NCA are submissions to another party -> T2"),
    "2-14-3-1": (2, "authorised access to critical areas leaves access lists and badge logs -> T2"),
    "2-14-3-3": (2, "protecting access and monitoring logs leaves logging configuration -> T2"),
    "2-14-3-4": (2, "secure destruction leaves destruction certificates and records -> T2"),
    "2-14-2": (2, "physical protection implemented (rule 4); its list 2-14-3 is T2 -> T2"),
    "2-15-3-4": (2, "the secure usage notice is served on the site (not decidable anonymously: it may sit behind login) -> T2"),
    "3-1-3-1": (2, "continuity of systems and procedures leaves continuity test results -> T2"),
    "3-1-3": (2, "business continuity umbrella; 3-1-3-1 is T2 -> best-child T2"),
    "3-1-2": (2, "business continuity implemented (rule 4); its list 3-1-3 is T2 -> T2"),
    "4-1-2-1": (2, "the clauses are in the executed third-party contracts -> T2"),
    "4-1-2-2": (2, "the procedures are in the executed third-party contracts -> T2"),
    "4-1-2-3": (2, "the obligation is in the executed third-party contracts -> T2"),
    "4-1-2": (2, "third-party contracts umbrella; every subcontrol T2 -> best-child T2"),
    "4-1-3-2": (2, "contracts and service records show where the managed SOC operates -> T2"),
    "4-1-3": (2, "outsourcing contracts umbrella; 4-1-3-2 is T2 -> best-child T2"),
    "2-10-3-3": (2, "remediation follows a plan and timeline set by classification (GECC); no observation shows that plan unmet -> T2"),
    "1-5-2": (2, "implementing the risk methodology leaves its risk register and assessment reports -> T2"),
    "1-5-3": (2, "risk assessment cases umbrella; its four subcontrols are T2 -> best-child T2"),
    "1-5-3-1": (2, "a risk assessment at the start of a project leaves its report (GECC expected output) -> T2"),
    "1-5-3-2": (2, "a risk assessment before a major infrastructure change leaves its report -> T2"),
    "1-5-3-3": (2, "a risk assessment when planning third-party services leaves its report -> T2"),
    "1-5-3-4": (2, "a risk assessment before releasing a service or product leaves its report -> T2"),
    "4-1-3-1": (2, "the third-party risk assessment before signing leaves its report beside the contract -> T2"),
    "2-14-3-5": (2, "security of devices and equipment leaves maintenance and inspection records (GECC), as its siblings -> T2"),
    "1-9-4-2": (2, "personnel compliance leaves each employee's signed policy acknowledgement (GECC expected output), as 1-9-3-1 -> T2"),
    "1-8-3": (2, "documenting and presenting audit results leaves the audit reports (GECC), the record that makes 1-8-2 T2 -> T2"),
    "1-10-3-1": (2, "awareness on phishing and email leaves proof the content was delivered (GECC), as 1-10-2 and 1-9-4-1 -> T2"),
    "1-10-3-2": (2, "awareness on mobile devices and media leaves proof the content was delivered (GECC), as 1-10-2 -> T2"),
    "1-10-3-3": (2, "awareness on secure browsing leaves proof the content was delivered (GECC), as 1-10-2 -> T2"),
    "1-10-3-4": (2, "awareness on social media leaves proof the content was delivered (GECC), as 1-10-2 -> T2"),
    "1-10-3": (2, "awareness programme umbrella; all four subcontrols T2 -> best-child T2"),
    "1-3-2": (3, "the department's own checks that policies are implemented are its own review -> T3"),
    "1-3-3": (3, "technical security standards are the organisation's own documents -> T3"),
    "1-6-1": (3, "requirements included in the project and change methodology: a methodology document -> T3"),
    "1-7-1": (3, "identifying and complying with international commitments: the organisation's own register -> T3"),
    "2-13-3-1": (3, "incident response plans and escalation procedures are plans, as 3-1-3-2 and 3-1-3-3 -> T3"),
}
NCNICC_RECORDS = RECORDS.with_name("ncnicc_exclusive.json")
NCNICC_STATUS_CORRECTIONS: dict[str, tuple[str | None, str | None]] = {
    "2-8-3-2": (None, None),
    "2-5-3-1": ("M", "R"),
    **dict.fromkeys(
        (
            "2-1-3", "2-1-4", "2-4-3-3", "2-6-3-1", "2-6-3-2", "2-6-3-3", "2-6-3-4", "2-9-3-2", "2-10-3-5",
            "2-12-3-2", "2-12-3-3", "2-12-3-4", "2-12-3-5", "2-13-3-2", "2-13-3-5",
            "1-2-3", "1-3-3", "1-4-2", "1-5-3", "1-8-3", "1-10-4", "2-5-3-8", "2-11-3-2", "4-1-3",
        ),
        (None, None),
    ),
}
NCNICC_STATUS_ADDITIONS: dict[str, tuple[str, str, str]] = {
    "4-1-2-1": ("1-3", "M", "R"),
    "4-1-2-2": ("1-3", "M", "R"),
    "1-10-3-1": ("5-1", "M", "R"),
    "1-10-3-4": ("5-1", "M", "R"),
}
NCNICC_ADDITIONS_2026_10_21: dict[str, dict[str, object]] = {
    "2-7-1-1": {
        "id": "2-7-1-1",
        "kind": "ncnicc_exclusive",
        "class_a": "M",
        "class_b": "R",
        "clause_en": "Use data leakage prevention and rights management technologies.",
        "clause_en_source": "authors-paraphrase",
        "method_en": "Inspect the configuration and policies of the deployed data leakage prevention and rights "
        "management tools.",
        "tier": 2,
        "reading_en": "Data leakage prevention and rights management tools are deployed with policies covering "
        "the entity's classified data.",
        "remediation_en": "Deploy data leakage prevention and rights management tools and set policies by data "
        "classification.",
    },
}
NCNICC_AR_SOURCES = (
    Path(__file__).resolve().parent.parent / "spec" / "regulations" / "NCNICC-1-2025-clean-Arabic.md",
    Path.home() / "atlas" / "spec" / "regulations" / "NCNICC-1-2025-clean-Arabic.md",
)
NCNICC_RECODE_2026_10_20: dict[str, tuple[int, str]] = {
    "2-7-1-3": (1, "a print service reachable from the internet shows the use of the printer not secured -> T1"),
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
    recoded = [
        cid
        for cid, (t, _why) in LATER.items()
        if (by_id[cid]["tier"], by_id[cid].get("tier_source")) != (t, "author-curated")
    ]
    if recoded:
        for cid, (intended, _why) in LATER.items():
            by_id[cid]["tier"], by_id[cid]["tier_source"] = intended, "author-curated"
        RECORDS.write_text(json.dumps(records, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
        print(f"applied the later decisions to {len(recoded)} rows: {recoded}")
    moved = [
        cid
        for cid, (t, _why) in RECODE_2026_10_20.items()
        if (by_id[cid]["tier"], by_id[cid].get("tier_source")) != (t, "author-curated")
    ]
    if moved:
        for cid, (intended, _why) in RECODE_2026_10_20.items():
            by_id[cid]["tier"], by_id[cid]["tier_source"] = intended, "author-curated"
        RECORDS.write_text(json.dumps(records, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
        print(f"applied the 2026-10-20 recode to {len(moved)} rows: {moved}")
    ncnicc = json.loads(NCNICC_RECORDS.read_text(encoding="utf-8"))
    missing = [cid for cid in NCNICC_ADDITIONS_2026_10_21 if cid not in {r["id"] for r in ncnicc}]
    if missing:
        from extract_regulations import parse_ncnicc_arabic

        source = next((p for p in NCNICC_AR_SOURCES if p.exists()), None)
        assert source is not None, "the NCNICC Arabic text is needed to add the new NCNICC rows"
        arabic = parse_ncnicc_arabic(set(missing), md_text=source.read_text(encoding="utf-8"))
        for cid in missing:
            assert cid in arabic, f"{cid} not found in {source}"
            ncnicc.append({**NCNICC_ADDITIONS_2026_10_21[cid], "clause_ar": arabic[cid], "clause_ar_source": "ncnicc-md"})
        ncnicc.sort(key=lambda r: [int(x) for x in r["id"].split("-")])
        NCNICC_RECORDS.write_text(json.dumps(ncnicc, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
        print(f"added the NCNICC rows: {missing}")
    for cid, spec in NCNICC_ADDITIONS_2026_10_21.items():
        rec = next(r for r in ncnicc if r["id"] == cid)
        assert (rec["tier"], rec["class_a"], rec["class_b"]) == (spec["tier"], spec["class_a"], spec["class_b"]), cid
    if any(r["tier"] != NCNICC_RECODE_2026_10_20[r["id"]][0] for r in ncnicc if r["id"] in NCNICC_RECODE_2026_10_20):
        for rec in ncnicc:
            if rec["id"] in NCNICC_RECODE_2026_10_20:
                rec["tier"] = NCNICC_RECODE_2026_10_20[rec["id"]][0]
        NCNICC_RECORDS.write_text(json.dumps(ncnicc, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
        print(f"applied the 2026-10-20 NCNICC recode: {sorted(NCNICC_RECODE_2026_10_20)}")

    def _status(cid: str, key: str) -> str | None:
        mapping = by_id[cid][key]
        return mapping["status"] if mapping else None

    def _set(cid: str, key: str, status: str | None) -> None:
        by_id[cid][key] = None if status is None else {**by_id[cid][key], "status": status}

    if any((_status(c, "ncnicc_class_a"), _status(c, "ncnicc_class_b")) != v for c, v in NCNICC_STATUS_CORRECTIONS.items()):
        for cid, (class_a, class_b) in NCNICC_STATUS_CORRECTIONS.items():
            _set(cid, "ncnicc_class_a", class_a)
            _set(cid, "ncnicc_class_b", class_b)
        RECORDS.write_text(json.dumps(records, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
        print(f"applied the NCNICC status corrections: {sorted(NCNICC_STATUS_CORRECTIONS)}")
    for cid, pair in NCNICC_STATUS_CORRECTIONS.items():
        assert (_status(cid, "ncnicc_class_a"), _status(cid, "ncnicc_class_b")) == pair, cid
    if any((_status(c, "ncnicc_class_a"), _status(c, "ncnicc_class_b")) != (a, b) for c, (_, a, b) in NCNICC_STATUS_ADDITIONS.items()):
        for cid, (sub, class_a, class_b) in NCNICC_STATUS_ADDITIONS.items():
            by_id[cid]["ncnicc_class_a"] = {"subcomponent": sub, "status": class_a}
            by_id[cid]["ncnicc_class_b"] = {"subcomponent": sub, "status": class_b}
        RECORDS.write_text(json.dumps(records, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
        print(f"applied the NCNICC status additions: {sorted(NCNICC_STATUS_ADDITIONS)}")

    for cid, (intended, _why) in CURATION.items():
        rec = by_id[cid]
        intended = LATER.get(cid, (intended, ""))[0]
        intended = RECODE_2026_10_20.get(cid, (intended, ""))[0]
        assert rec["tier"] == intended, (
            f"catalog drift: {cid} is tier {rec['tier']} but curated to {intended}"
        )
        assert rec.get("tier_source") == "author-curated", (
            f"{cid} tier_source is {rec.get('tier_source')}, expected author-curated"
        )
    for cid, (intended, _why) in (LATER | RECODE_2026_10_20).items():
        assert by_id[cid]["tier"] == intended and by_id[cid].get("tier_source") == "author-curated", cid
    ncnicc_tiers = {r["id"]: r["tier"] for r in json.loads(NCNICC_RECORDS.read_text(encoding="utf-8"))}
    for cid, (intended, _why) in NCNICC_RECODE_2026_10_20.items():
        assert ncnicc_tiers[cid] == intended, cid
    curated = len(set(CURATION) | set(LATER) | set(RECODE_2026_10_20))
    assert sum(1 for r in records if r.get("tier_source") == "author-curated") == curated
    assert not any(r.get("tier_source") == "default-pending-expert" for r in records)
    print(f"gate ok: {curated} author-curated, 0 default-pending-expert")
    print("tier_source:", dict(Counter(r["tier_source"] for r in records)))
    print("tier split:", dict(Counter(r["tier"] for r in records)))


if __name__ == "__main__":
    main()
