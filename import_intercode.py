"""Convert the InterCode-CTF dataset into our challenge.json layout.

InterCode: princeton-nlp/intercode -> data/ctf/{ic_ctf.json, task_assets/<id>/}
Each task -> challenges/<out>/<id>/ with challenge.json + the task's files,
EXCLUDING the `solution/` dir (that would leak the answer to the solver).

Usage:
  python import_intercode.py /path/to/intercode/data/ctf  [-o challenges/intercode]
"""
import argparse
import json
import shutil
from pathlib import Path


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("ctf_dir", help="intercode/data/ctf")
    ap.add_argument("-o", "--out", default="challenges/intercode")
    args = ap.parse_args()

    src = Path(args.ctf_dir)
    tasks = json.loads((src / "ic_ctf.json").read_text())
    out = Path(args.out)
    out.mkdir(parents=True, exist_ok=True)

    n = 0
    for t in tasks:
        tid = t["task_id"]
        d = out / str(tid)
        # Task files go in files/ (the ONLY thing the agent sees). challenge.json
        # holds the gold flag and stays in the parent, out of the sandbox, so the
        # solver can't read the answer.
        fdir = d / "files"
        fdir.mkdir(parents=True, exist_ok=True)
        assets = src / "task_assets" / str(tid)
        if assets.is_dir():
            for item in assets.iterdir():
                if item.name == "solution":       # answer walkthrough — never expose
                    continue
                dst = fdir / item.name
                if item.is_dir():
                    shutil.copytree(item, dst, dirs_exist_ok=True)
                else:
                    shutil.copy2(item, dst)
        (d / "challenge.json").write_text(json.dumps({
            "name": f"intercode_{tid}",
            "category": (t.get("tags") or ["misc"])[0],
            "prompt": t["query"],
            "flag": t["gold"],
        }, indent=2))
        n += 1
    print(f"wrote {n} challenges to {out}")


if __name__ == "__main__":
    main()
