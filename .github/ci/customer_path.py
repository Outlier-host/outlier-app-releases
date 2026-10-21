#!/usr/bin/env python3
"""Outlier on the oldest macOS it declares, the way a buyer gets it: the DMG installed in /Applications, then

  1. the floor: every Mach-O in the bundle and the highest minos any of them declares;
  2. the module walk: the engine's own `--outlier-import-walk` loads every bundled .so/.dylib (dyld binds their
     imports then, so a symbol this macOS lacks fails HERE, by file) and imports every module in its frozen archive;
  3. the app: Outlier.app opened as a person opens it; its engine must answer /health with the expected version;
  4. one request with no model: a .docx (made by macOS's own textutil) uploaded and parsed (python-docx, lxml);
  5. the OCR helper (Swift, Vision) reads a picture of a line of text (rendered by Quick Look).

A runner is a VM with no GPU and ~7 GB: no model is loaded here and no speed figure from here means anything. The
walk's import failures are compared, by the person running this, with the same walk on the build Mac — some optional
modules fail to import everywhere; a failure only here is the floor's. A dlopen failure is a failure outright.
Standard library only. usage: customer_path.py --app /Applications/Outlier.app --out DIR --expect-version 1.11.952
"""
import argparse
import json
import os
import re
import subprocess
import sys
import time
import urllib.error
import urllib.request
import uuid

PORT = 8766


def sh(cmd, timeout=600, env=None):
    p = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout, env=env)
    return p.returncode, p.stdout, p.stderr


def machos(app):
    out = []
    for root, _dirs, files in os.walk(app):
        for f in files:
            p = os.path.join(root, f)
            if os.path.islink(p) or not os.path.isfile(p):
                continue
            with open(p, "rb") as fh:
                head = fh.read(4)
            if head in (b"\xcf\xfa\xed\xfe", b"\xca\xfe\xba\xbe", b"\xce\xfa\xed\xfe"):
                out.append(p)
    return out


def minos_of(path):
    _rc, out, _err = sh(["otool", "-l", path], timeout=60)
    found = re.findall(r"minos (\d+(?:\.\d+)*)", out) or re.findall(r"cmd LC_VERSION_MIN_MACOSX\s+cmdsize \d+\s+version (\S+)", out)
    return max((tuple(int(x) for x in v.split(".")) for v in found), default=None)


def health():
    try:
        with urllib.request.urlopen(f"http://127.0.0.1:{PORT}/health", timeout=5) as r:
            return json.load(r)
    except Exception:
        return None


def key_header():
    p = os.path.expanduser("~/.outlier/local_api_token")
    try:
        k = open(p).read().strip()
    except OSError:
        return {}
    return {"X-Outlier-Token": k} if 32 <= len(k) <= 256 else {}


def upload(path):
    data = open(path, "rb").read()
    bnd = "----outlierci" + uuid.uuid4().hex
    name = os.path.basename(path)
    payload = (f"--{bnd}\r\nContent-Disposition: form-data; name=\"file\"; filename=\"{name}\"\r\n"
               "Content-Type: application/vnd.openxmlformats-officedocument.wordprocessingml.document\r\n\r\n").encode() \
        + data + f"\r\n--{bnd}\r\nContent-Disposition: form-data; name=\"tier\"\r\n\r\nnano\r\n--{bnd}--\r\n".encode()
    req = urllib.request.Request(f"http://127.0.0.1:{PORT}/upload", data=payload, method="POST",
                                 headers={**key_header(), "Content-Type": f"multipart/form-data; boundary={bnd}"})
    try:
        with urllib.request.urlopen(req, timeout=180) as r:
            return r.status, json.load(r)
    except urllib.error.HTTPError as e:
        return e.code, json.loads(e.read() or b"{}")


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--app", required=True)
    ap.add_argument("--out", required=True)
    ap.add_argument("--expect-version", required=True)
    a = ap.parse_args()
    os.makedirs(a.out, exist_ok=True)
    res = {"macos": sh(["sw_vers", "-productVersion"])[1].strip(), "arch": os.uname().machine, "checks": {}}
    major = int(res["macos"].split(".")[0])
    C = res["checks"]

    # 1. the floor
    bins = machos(a.app)
    highest, worst = None, None
    for b in bins:
        m = minos_of(b)
        if m and (highest is None or m > highest):
            highest, worst = m, os.path.relpath(b, a.app)
    C["floor"] = {"ok": bool(bins) and highest is not None and highest[0] <= major, "machos": len(bins),
                  "highest_minos": ".".join(map(str, highest or ())), "file": worst}

    # 2. the module walk
    engine = os.path.join(a.app, "Contents", "Resources", "outlier-cli", "outlier-cli")
    walk_out = os.path.join(a.out, "walk.json")
    env = {**os.environ, "OUTLIER_IMPORT_WALK_OUT": walk_out}
    t0 = time.time()
    rc, out, err = sh([engine, "--outlier-import-walk"], timeout=1800, env=env)
    open(os.path.join(a.out, "walk.stderr.txt"), "w").write(err[-20000:])
    try:
        w = json.load(open(walk_out))
    except Exception as e:  # noqa: BLE001
        w = {"error": f"no report ({type(e).__name__}); exit {rc}"}
    # the same walk on the build Mac (macOS 26): what fails there too is not the floor's — the walk loads each library
    # by path, out of the context its module loads it in, and some optional modules fail to import everywhere
    base_file = os.path.join(os.path.dirname(os.path.abspath(__file__)), "baseline", f"{a.expect_version}-macos26.json")
    try:
        base = json.load(open(base_file))
    except OSError:
        base = None
    only_dl = sorted(set(w.get("dlopen_failed") or {}) - set((base or {}).get("dlopen_failed") or []))
    only_im = sorted(set(w.get("import_failed") or {}) - set((base or {}).get("import_failed") or []))
    C["walk"] = {"ok": rc == 0 and "error" not in w and w.get("frozen") is True and w.get("archive_modules", 0) > 0
                 and base is not None and not only_dl and not only_im
                 and w.get("dylibs") == base.get("dylibs") and w.get("modules") == base.get("modules"),
                 "exit": rc, "seconds": round(time.time() - t0, 1), "dylibs": w.get("dylibs"),
                 "modules": w.get("modules"), "archive_modules": w.get("archive_modules"),
                 "baseline": os.path.basename(base_file) if base else "MISSING — the walk cannot be judged",
                 "dlopen_failed_only_here": {k: (w.get("dlopen_failed") or {})[k][:300] for k in only_dl},
                 "import_failed_only_here": {k: (w.get("import_failed") or {})[k][:300] for k in only_im},
                 "dlopen_failed": len(w.get("dlopen_failed") or {}), "import_failed": len(w.get("import_failed") or {}),
                 "error": w.get("error")}

    # 2b. the packages the app's features stand on, each imported by the engine itself with nothing loaded before it
    # (`--outlier-run-module PKG`: a package that imported then says it "cannot be directly executed"). The walk loads
    # every library first, and that alone makes scipy.interpolate and mlx_whisper fail to import on EVERY macOS — they
    # import fine this way (checked on the build Mac) — so for these the walk proves nothing and this does.
    # (mlx_vlm is left out: its top-level import fails in 1.11.951 and 1.11.952 alike; Vision 3.8 does not use it.)
    key = ["mlx_whisper", "scipy.interpolate", "mlx_lm", "docx", "pptx", "openpyxl", "pypdf", "trafilatura", "lxml",
           "PIL", "numpy", "tokenizers", "transformers"]
    home = os.path.join(a.out, "run-module-home")
    os.makedirs(home, exist_ok=True)
    bad = {}
    for m in key:
        _rc, o, e = sh([engine, "--outlier-run-module", m], timeout=300,
                       env={**os.environ, "HOME": home, "OUTLIER_PORT": "18998"})
        line = next((l for l in (o + e).splitlines() if "--outlier-run-module" in l), "")
        if "cannot be directly executed" not in line:
            bad[m] = (line or (o + e)[-300:])[:300]
    C["key_imports"] = {"ok": not bad, "checked": len(key), "failed": bad}

    # 3. the app, opened as a person opens it
    rc, _o, err = sh(["open", a.app], timeout=60)
    h, t0 = None, time.time()
    for _ in range(120):                                  # up to ~10 minutes for a first launch
        h = health()
        if h and h.get("status") == "ok":
            break
        time.sleep(5)
    _rc, ps, _e = sh(["pgrep", "-fl", "Outlier.app/Contents/MacOS"], timeout=30)
    C["app"] = {"ok": bool(h) and h.get("status") == "ok" and h.get("version") == a.expect_version,
                "open_exit": rc, "seconds_to_health": round(time.time() - t0, 1), "app_process": ps.strip()[:300],
                "health": {k: (h or {}).get(k) for k in ("status", "version", "model_loaded", "engine_boot")}}

    # 4. a no-model request: a .docx made by textutil, uploaded and parsed
    txt = os.path.join(a.out, "budget.txt")
    open(txt, "w").write("Quarterly budget: $184,800 approved in December by Vikram Ostrowski.\n")
    docx = os.path.join(a.out, "budget.docx")
    sh(["textutil", "-convert", "docx", "-output", docx, txt], timeout=60)
    if C["app"]["ok"] and os.path.exists(docx):
        status, j = upload(docx)
        body = json.dumps(j)
        C["upload_docx"] = {"ok": status == 200 and "184,800" in body, "status": status, "reply": body[:400]}
    else:
        C["upload_docx"] = {"ok": False, "skipped": "the engine never answered" if not C["app"]["ok"] else "no docx"}

    # 5. the OCR helper reads a picture of text
    ocr = os.path.join(a.app, "Contents", "Resources", "outlier-ocr")
    note = os.path.join(a.out, "ocr-line.txt")
    open(note, "w").write("OUTLIER READS THIS LINE\n")
    sh(["qlmanage", "-t", "-s", "1200", "-o", a.out, note], timeout=120)
    png = note + ".png"
    if os.path.exists(png) and os.path.exists(ocr):
        rc, o, err = sh([ocr, png], timeout=120)
        C["ocr"] = {"ok": rc == 0 and "READS THIS" in o.upper(), "exit": rc, "text": o.strip()[:200], "stderr": err[-300:]}
    else:
        C["ocr"] = {"ok": False, "skipped": "no picture" if not os.path.exists(png) else "no outlier-ocr"}

    sh(["osascript", "-e", 'tell application "Outlier" to quit'], timeout=60)
    res["ok"] = all(c.get("ok") for c in C.values())
    json.dump(res, open(os.path.join(a.out, "result.json"), "w"), indent=1)
    print(json.dumps(res, indent=1))
    return 0 if res["ok"] else 1


if __name__ == "__main__":
    sys.exit(main())
