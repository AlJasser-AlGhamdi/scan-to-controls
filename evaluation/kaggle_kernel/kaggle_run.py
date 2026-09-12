import atexit
import base64
import hashlib
import json
import os
import pathlib
import platform
import re
import shutil
import signal
import subprocess
import time
import traceback
import urllib.request

WORK = pathlib.Path("/kaggle/working")
MODELS_DIR = pathlib.Path("/kaggle/temp/ollama_models")
DATA_B64 = "__DATA_B64__"
_IS_TEMPLATE = "_" in DATA_B64
DATA_BYTES = b"" if _IS_TEMPLATE else base64.b64decode(DATA_B64)
DATA = json.loads(DATA_BYTES) if DATA_BYTES else {}
DATA_SHA256 = hashlib.sha256(DATA_BYTES).hexdigest() if DATA_BYTES else ""
if not _IS_TEMPLATE:
    pathlib.Path("kaggle_baseline_data.json").write_bytes(DATA_BYTES)

SEED = 1337
NUM_PREDICT = 2048
MODELS = [
    "gemma3:12b",
    "qwen2.5:7b",
    "iKhalid/ALLaM:7b",
    "hf.co/mradermacher/jais-adapted-7b-chat-GGUF:Q4_K_M",
    "hf.co/mradermacher/SILMA-9B-Instruct-v1.0-GGUF:Q4_K_M",
    "command-r7b-arabic:7b",
    "phi4:14b",
    "qwen3:14b",
    "deepseek-r1:14b",
    "gpt-oss:20b",
    "mistral-small:24b",
    "qwen3:32b",
]
CONDITIONS = [
    ("title", 5120, "title", False),
    ("full_text", 8192, "full_text", False),
    ("multi_full_text", 8192, "full_text", True),
]
SYSTEM = (
    "You are a cybersecurity compliance expert mapping one external scan finding to the single "
    "ECC-2:2024 control subcontrol it evidences. Choose from the provided candidate ids only. "
    "You may reason briefly, but end your reply with just that one control id on its own line."
)
SYSTEM_MULTI = (
    "You are a cybersecurity compliance expert mapping one external scan finding to the ECC-2:2024 "
    "control subcontrols it evidences. Choose from the provided candidate ids only. A finding may "
    "evidence more than one control. You may reason briefly, but end your reply with every applicable "
    "control id, one per line, and nothing else."
)
HOST = "http://127.0.0.1:11434"
GEN_TIMEOUT = 1800.0
PULL_TIMEOUT = 7200
PULL_RETRIES = 3
BUDGET_SECONDS = 37800
BUDGET_32B_START = 21600
_ID_RE = re.compile(r"\d(?:-\d{1,2}){2,3}")
VALID = set(DATA.get("valid_ids", []))
RUN_START = time.time()

_STATE = {"results": {}, "predictions": {}, "provenance": {}}
_OLLAMA_PROC = None


def free_gb(path):
    try:
        st = os.statvfs(str(path))
        return round(st.f_bavail * st.f_frsize / 1e9, 1)
    except Exception:
        return None


def save():
    try:
        WORK.mkdir(parents=True, exist_ok=True)
        (WORK / "baseline_ladder_results.json").write_text(json.dumps(_STATE["results"], indent=2))
        (WORK / "baseline_ladder_predictions.json").write_text(json.dumps(_STATE["predictions"], indent=2))
        (WORK / "kaggle_provenance.json").write_text(json.dumps(_STATE["provenance"], indent=2))
    except Exception as exc:
        print(f"[save] WARN could not flush: {str(exc)[:160]}", flush=True)


atexit.register(save)


def _on_sigterm(signum, frame):
    print(f"[signal] {signum} received; flushing partial results and exiting 0", flush=True)
    save()
    os._exit(0)


signal.signal(signal.SIGTERM, _on_sigterm)


def ollama_up():
    try:
        with urllib.request.urlopen(f"{HOST}/api/tags", timeout=10) as resp:
            resp.read()
        return True
    except Exception:
        return False


def start_ollama(env):
    global _OLLAMA_PROC
    _OLLAMA_PROC = subprocess.Popen(["ollama", "serve"], env=env)
    for _ in range(30):
        time.sleep(2)
        if ollama_up():
            return True
    return ollama_up()


def ensure_ollama(env):
    if ollama_up():
        return True
    print("[ollama] daemon down; respawning", flush=True)
    return start_ollama(env)


def ollama_generate(model, prompt, num_ctx, timeout, system=SYSTEM):
    body = {
        "model": model,
        "prompt": prompt,
        "system": system,
        "stream": False,
        "options": {"temperature": 0.0, "seed": SEED, "num_predict": NUM_PREDICT, "num_ctx": num_ctx},
    }
    req = urllib.request.Request(
        f"{HOST}/api/generate", data=json.dumps(body).encode(), headers={"Content-Type": "application/json"}
    )
    with urllib.request.urlopen(req, timeout=timeout) as resp:
        d = json.loads(resp.read())
    return str(d.get("response", "")), str(d.get("thinking", ""))


def _scan(text):
    return [m for m in _ID_RE.findall(text or "") if m in VALID]


def extract_id(response, thinking):
    clean = re.sub(r"<think>.*?</think>", " ", response or "", flags=re.S)
    ids = _scan(clean)
    if ids:
        return ids[-1]
    tids = _scan(thinking)
    if tids:
        return tids[-1]
    rids = _scan(response)
    return rids[-1] if rids else None


def extract_ids(response, thinking):
    clean = re.sub(r"<think>.*?</think>", " ", response or "", flags=re.S)
    for text in (clean, thinking, response):
        ids = list(dict.fromkeys(_scan(text)))
        if ids:
            return ids
    return []


def micro_f1(preds, checks=None, multi=False):
    checks = DATA["checks"] if checks is None else checks
    tp = fp = fn = 0
    for row in checks:
        gold = set(row["gold_ids"])
        raw = preds.get(row["check"])
        pred = set(raw or []) if multi else ({raw} if raw else set())
        w = row["frequency"]
        tp += w * len(pred & gold)
        fp += w * len(pred - gold)
        fn += w * len(gold - pred)
    prec = tp / (tp + fp) if (tp + fp) else 0.0
    rec = tp / (tp + fn) if (tp + fn) else 0.0
    f1 = 0.0 if (prec + rec) == 0 else 2 * prec * rec / (prec + rec)
    return {"micro_f1": round(f1, 4), "precision": round(prec, 4), "recall": round(rec, 4)}


def run_condition(model, name, num_ctx, scope, multi, env):
    catalog = DATA["catalog_full"] if scope == "full_text" else DATA["catalog_title"]
    block = "\n".join(f"{cid}: {txt}" for cid, txt in catalog.items())
    system = SYSTEM_MULTI if multi else SYSTEM
    instruction = (
        "List every applicable control id, one per line, and nothing else."
        if multi
        else "Reply with the single best control id and end with just that id."
    )
    preds = {}
    unanswered = 0
    for row in DATA["checks"]:
        prompt = (
            f"Scan finding: {row['query_text']}\n\n"
            f"Candidate controls (id: text):\n{block}\n\n{instruction}"
        )
        val = [] if multi else None
        try:
            resp, think = ollama_generate(model, prompt, num_ctx, GEN_TIMEOUT, system)
            val = extract_ids(resp, think) if multi else extract_id(resp, think)
        except Exception as exc:
            print(f"  err {row['check']}: {str(exc)[:80]}", flush=True)
            ensure_ollama(env)
        if (val is None) or (multi and not val):
            unanswered += 1
        preds[row["check"]] = val
    agg = micro_f1(preds, multi=multi)
    agg["unanswered"] = unanswered
    return agg, preds


def model_digest(model):
    try:
        with urllib.request.urlopen(f"{HOST}/api/tags", timeout=60) as resp:
            tags = json.loads(resp.read()).get("models", [])
        for m in tags:
            if m.get("name") == model or m.get("model") == model:
                return {
                    "digest": m.get("digest"),
                    "size": m.get("size"),
                    "details": m.get("details"),
                    "modified_at": m.get("modified_at"),
                }
    except Exception as exc:
        return {"digest": None, "error": str(exc)[:120]}
    return {"digest": None, "error": "not found in /api/tags"}


def pull_model(model):
    last = ""
    for attempt in range(1, PULL_RETRIES + 1):
        pr = subprocess.run(["ollama", "pull", model], capture_output=True, timeout=PULL_TIMEOUT, check=False)
        if pr.returncode == 0:
            return True, ""
        last = pr.stderr.decode(errors="ignore")[-300:]
        print(f"[pull] {model} attempt {attempt}/{PULL_RETRIES} rc={pr.returncode}: {last[-160:]}", flush=True)
        time.sleep(15 * attempt)
    return False, last


def remove_model(model):
    subprocess.run(["ollama", "stop", model], capture_output=True, check=False)
    subprocess.run(["ollama", "rm", model], capture_output=True, check=False)


def pkg_versions():
    out = {}
    for mod in ("ollama", "torch", "numpy", "requests", "urllib3"):
        try:
            import importlib.metadata as md

            out[mod] = md.version(mod)
        except Exception:
            out[mod] = None
    return out


def score_one_model(model, env):
    prov = _STATE["provenance"]["models"]
    try:
        if not ensure_ollama(env):
            prov[model] = {"status": "daemon_down"}
            _STATE["results"][model] = {"error": "daemon_down"}
            return
        print(f"[pull] {model}  disk_free(/kaggle/temp)={free_gb('/kaggle/temp')}GB", flush=True)
        ok, stderr = pull_model(model)
        if not ok:
            prov[model] = {"status": "pull_failed", "stderr": stderr}
            _STATE["results"][model] = {"error": "pull_failed"}
            print(f"[SKIP] {model}: pull failed after {PULL_RETRIES} tries", flush=True)
            return
        digest = model_digest(model)
        entry, preds_entry, t0 = {}, {}, time.time()
        for cond, ctx, scope, multi in CONDITIONS:
            try:
                agg, preds = run_condition(model, cond, ctx, scope, multi, env)
                entry[cond] = agg
                preds_entry[cond] = preds
                print(
                    f"[done] {model} [{cond}]: F1={agg['micro_f1']:.4f} P={agg['precision']:.3f} "
                    f"R={agg['recall']:.3f} unanswered={agg['unanswered']}",
                    flush=True,
                )
            except Exception as exc:
                entry[cond] = {"error": str(exc)[:200]}
                preds_entry[cond] = {}
                print(f"[FAIL] {model} [{cond}]: {str(exc)[:120]}", flush=True)
                ensure_ollama(env)
        entry["secs"] = round(time.time() - t0)
        _STATE["results"][model] = entry
        _STATE["predictions"][model] = preds_entry
        prov[model] = {"status": "ok", "secs": entry["secs"], **digest}
    except Exception as exc:
        prov[model] = {"status": "crashed", "error": str(exc)[:200], "trace": traceback.format_exc()[-400:]}
        _STATE["results"].setdefault(model, {"error": "crashed"})
        print(f"[CRASH] {model}: {str(exc)[:160]}", flush=True)
    finally:
        remove_model(model)
        save()


def main():
    MODELS_DIR.mkdir(parents=True, exist_ok=True)
    if subprocess.run(["which", "ollama"], capture_output=True).returncode != 0:
        subprocess.run("apt-get update -qq && apt-get install -y -qq zstd", shell=True, check=False)
        subprocess.run("curl -fsSL https://ollama.com/install.sh | sh", shell=True, check=True)
    env = {
        **os.environ,
        "OLLAMA_HOST": "127.0.0.1:11434",
        "OLLAMA_KEEP_ALIVE": "30m",
        "OLLAMA_MODELS": str(MODELS_DIR),
    }
    os.environ["OLLAMA_HOST"] = "127.0.0.1:11434"
    if not start_ollama(env):
        print("[ollama] FATAL: daemon would not start; nothing to run", flush=True)

    ollama_version = subprocess.run(["ollama", "--version"], capture_output=True, text=True).stdout.strip()
    nvidia = subprocess.run(
        ["nvidia-smi", "--query-gpu=name,memory.total,driver_version", "--format=csv,noheader"],
        capture_output=True, text=True,
    ).stdout.strip()

    _STATE["provenance"] = {
        "run_date_utc": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "seed": SEED,
        "temperature": 0.0,
        "num_predict": NUM_PREDICT,
        "conditions": {c: {"num_ctx": ctx, "multi_label": multi} for c, ctx, _scope, multi in CONDITIONS},
        "ollama_version": ollama_version,
        "python_version": platform.python_version(),
        "packages": pkg_versions(),
        "gpu": nvidia,
        "disk_free_gb_start": {"kaggle_temp": free_gb("/kaggle/temp"), "working": free_gb("/kaggle/working")},
        "data_sha256": DATA_SHA256,
        "n_checks": len(DATA["checks"]),
        "n_candidate_controls": len(DATA["valid_ids"]),
        "weighted_findings": sum(c["frequency"] for c in DATA["checks"]),
        "models_requested": list(MODELS),
        "models": {},
    }
    multi = sum(1 for c in DATA["checks"] if len(c["gold_ids"]) > 1)
    print(
        f"31 checks, {len(VALID)} candidate controls, {multi} multi-gold; data sha256 {DATA_SHA256[:12]}; "
        f"ollama {ollama_version}; gpu [{nvidia}]; models_dir={MODELS_DIR} free={free_gb('/kaggle/temp')}GB",
        flush=True,
    )
    save()

    for model in MODELS:
        elapsed = time.time() - RUN_START
        is_32b = "32b" in model
        if elapsed > BUDGET_SECONDS or (is_32b and elapsed > BUDGET_32B_START):
            _STATE["provenance"]["models"][model] = {
                "status": "not_run", "reason": f"wall_clock_guard at {int(elapsed)}s"
            }
            print(f"[BUDGET] skip {model} (elapsed {int(elapsed)}s)", flush=True)
            save()
            continue
        print(f"\n=== {model} (elapsed {int(elapsed)}s) ===", flush=True)
        score_one_model(model, env)

    _STATE["provenance"]["total_secs"] = round(time.time() - RUN_START)
    save()
    print("\n=== LADDER COMPLETE ===", flush=True)
    for m, r in _STATE["results"].items():
        ft = r.get("full_text", {})
        ml = r.get("multi_full_text", {})
        print(f"  {m:52s} full_text F1={ft.get('micro_f1')} multi_label F1={ml.get('micro_f1')}", flush=True)
    ok = [m for m, v in _STATE["provenance"]["models"].items() if v.get("status") == "ok"]
    print(f"\nmodels ok: {len(ok)}/{len(MODELS)} -> {ok}", flush=True)
    print("OUTPUTS -> /kaggle/working/{baseline_ladder_results,baseline_ladder_predictions,kaggle_provenance}.json")


if __name__ == "__main__":
    try:
        main()
    except BaseException as exc:
        print(f"[TOP] run aborted: {type(exc).__name__}: {str(exc)[:200]}", flush=True)
        print(traceback.format_exc()[-800:], flush=True)
    finally:
        save()
