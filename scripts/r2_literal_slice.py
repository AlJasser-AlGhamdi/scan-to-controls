import json
import sys

sys.path.insert(0, "src")
from p2c.evaluation import metrics as M
from p2c.evaluation.synthetic import expert_key, generate_cases
from p2c.mapping.rules import MappingEngine, check_id_from_finding
from p2c.scanning.catalog import LIVE_CHECKS, CheckId

ADDED_IN_REVISION = {
    CheckId.DIRECTORY_LISTING_ENABLED, CheckId.EXPOSED_SENSITIVE_FILE, CheckId.EXPOSED_LOGIN_PANEL,
    CheckId.OUTDATED_EXPOSED_SOFTWARE, CheckId.EOL_SOFTWARE_EXPOSED, CheckId.WAF_ABSENT,
    CheckId.NO_DDOS_PROTECTION, CheckId.DNS_ZONE_TRANSFER_OPEN,
    CheckId.EXPOSED_PRINTER_SERVICE,
}
live = set(LIVE_CHECKS) - ADDED_IN_REVISION
assert len(live) == 23, len(live)
key = expert_key()
universe = {c for chk, gold in key.items() if chk in live for c in gold}
cases = generate_cases(100, seed=1337)
engine = MappingEngine()
out: dict[str, object] = {"n_controls": len(universe), "submitted_live_detectors": len(live)}
for label, drop_truth in (("findings_only", False), ("findings_and_truth", True)):
    pairs = []
    for case in cases:
        found = [x for x in case.findings() if check_id_from_finding(x) in live]
        pred = {m.control_id for m in engine.map_findings(found)} & universe
        gold = ({c for i in case.true_injected if i.check in live for c in key[i.check]} if drop_truth
                else set(case.ground_truth.control_ids)) & universe
        pairs.append((pred, gold))
    m = M.micro_prf(pairs)
    base = sum(len(g) for _, g in pairs) / (len(pairs) * len(universe))
    out[label] = {"precision": round(m.precision, 4), "recall": round(m.recall, 4), "f1": round(m.f1, 4),
                  "predict_all_f1": round(2 * base / (base + 1), 4)}
json.dump(out, open("evaluation/r2_literal_slice.json", "w"), indent=2)
print(json.dumps(out, indent=1))
