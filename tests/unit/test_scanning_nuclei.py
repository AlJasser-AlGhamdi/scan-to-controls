from __future__ import annotations

from pathlib import Path

import pytest

from p2c.discovery.runner import CommandResult
from p2c.scanning.nuclei import NucleiRunner, parse_nuclei
from p2c.scanning.signing import TemplateSigner

KEY = b"nuclei-test-key"
NUCLEI_JSONL = (
    '{"template-id":"atlas-missing-hsts","host":"x","matched-at":"http://x/",'
    '"info":{"name":"Missing HSTS","severity":"medium",'
    '"metadata":{"atlas-check-id":"missing_hsts","control-id":"2-15-3-3"}}}\n'
)
CVE_JSONL = (
    '{"template-id":"CVE-2099-0001","host":"x","matched-at":"http://x/",'
    '"info":{"severity":"high","metadata":{"control-id":"2-10-3-4"}}}\n'
)


class FakeRunner:
    def __init__(self, stdout: str) -> None:
        self._stdout = stdout
        self.calls: list[list[str]] = []

    def run(self, argv: list[str], *, stdin: str | None = None, timeout: float = 120.0) -> CommandResult:
        self.calls.append(list(argv))
        return CommandResult(list(argv), 0, self._stdout, "")


def test_parse_nuclei_extracts_metadata() -> None:
    result = parse_nuclei(NUCLEI_JSONL)[0]
    assert result.template_id == "atlas-missing-hsts"
    assert result.check_id == "missing_hsts"
    assert result.control_ids == ("2-15-3-3",)


def test_parse_nuclei_drops_malformed_control_ids() -> None:
    line = (
        '{"template-id":"t","host":"x","matched-at":"http://x/",'
        '"info":{"severity":"low","metadata":{"control-id":"2-15-3-3, DROP TABLE, 9-9-9-9"}}}\n'
    )
    result = parse_nuclei(line)[0]
    assert result.control_ids == ("2-15-3-3", "9-9-9-9")


def test_parse_nuclei_reads_classification_cvss() -> None:
    line = (
        '{"template-id":"CVE-2099-1","host":"x","matched-at":"http://x/","info":{"severity":"high",'
        '"classification":{"cvss-metrics":"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N","cvss-score":7.5}}}\n'
    )
    result = parse_nuclei(line)[0]
    assert result.cvss_score == 7.5
    assert result.cvss_vector.startswith("CVSS:3.1/")


def test_runner_maps_atlas_template_to_catalog_finding(tmp_path: Path) -> None:
    (tmp_path / "atlas-missing-hsts.yaml").write_text("id: atlas-missing-hsts\n")
    signer = TemplateSigner(KEY)
    signer.write_manifest(tmp_path)
    fake = FakeRunner(NUCLEI_JSONL)
    findings = NucleiRunner(fake, signer).run("http://x/", tmp_path, consent_ref="C1")
    assert findings[0].control_ids == ["2-15-3-3", "2-8-3-3"]
    assert findings[0].source_tool == "nuclei"
    assert any("atlas-missing-hsts.yaml" in a for a in fake.calls[0])


def test_runner_maps_cve_template_by_nuclei_severity(tmp_path: Path) -> None:
    (tmp_path / "cve.yaml").write_text("id: cve\n")
    signer = TemplateSigner(KEY)
    signer.write_manifest(tmp_path)
    findings = NucleiRunner(FakeRunner(CVE_JSONL), signer).run("http://x/", tmp_path, consent_ref="C1")
    assert findings[0].severity.value == "HIGH"
    assert findings[0].control_ids == ["2-10-3-4"]


def test_runner_generic_finding_normalizes_cvss(tmp_path: Path) -> None:
    (tmp_path / "cve.yaml").write_text("id: cve\n")
    signer = TemplateSigner(KEY)
    signer.write_manifest(tmp_path)
    jsonl = (
        '{"template-id":"CVE-2099-2","host":"x","matched-at":"http://x/","info":{"severity":"high",'
        '"classification":{"cvss-metrics":"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N","cvss-score":7.5}}}\n'
    )
    finding = NucleiRunner(FakeRunner(jsonl), signer).run("http://x/", tmp_path, consent_ref="C1")[0]
    assert finding.cvss_base_score == 7.5
    assert finding.cvss_v3_1_vector and finding.cvss_v3_1_vector.startswith("CVSS:3.1/")
    assert finding.severity.value == "HIGH"


def test_runner_rejects_when_no_signed_templates(tmp_path: Path) -> None:
    (tmp_path / "unsigned.yaml").write_text("id: u\n")
    runner = NucleiRunner(FakeRunner(NUCLEI_JSONL), TemplateSigner(KEY))
    with pytest.raises(ValueError, match="no signed"):
        runner.run("http://x/", tmp_path, consent_ref="C1")
