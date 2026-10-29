"""Replay-verify a bundle produced with the registry_snapshot profile.

    python verify_bundle.py <bundle_dir>

Stock `nandatown verify` replays the evaluator with the validators it
already knows and never imports plugin files named inside a bundle, because
a bundle is untrusted input. On these bundles it therefore prints
"evaluator replay mismatch": its own lab-0.2.6 has no registry_rotation
validator. That message here means "out-of-tree validator not loaded", not
tampering.

This wrapper first reads the validator version and the profile's sha256
that the run recorded in its registry_snapshot event and refuses to replay
when this checkout's profile differs (a later edit to the rules cannot be
told apart from a bad bundle otherwise). Only then does it import
registry_snapshot.py from this directory, by the operator's choice, and run
the stock verify unchanged.
"""

from __future__ import annotations

import importlib.util
import json
import sys
from pathlib import Path

from nandatown.cli import main as nandatown

HERE = Path(__file__).resolve().parent


def recorded(bundle: Path) -> dict | None:
    for line in (bundle / "events.jsonl").read_text(encoding="utf-8").splitlines():
        event = json.loads(line)
        if event.get("kind") in ("registry_snapshot_loaded",
                                 "registry_snapshot_unavailable"):
            return event.get("detail", {})
    return None


def main(argv: list[str]) -> int:
    if len(argv) != 1:
        print(__doc__)
        return 2
    bundle = Path(argv[0])
    spec = importlib.util.spec_from_file_location(
        "registry_snapshot_profile", HERE / "registry_snapshot.py")
    profile = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(profile)
    rec = recorded(bundle)
    if rec is None:
        print("problem: no registry_snapshot event in this bundle; it was not"
              " produced with this profile")
        return 1
    mine = (profile.VALIDATOR_VERSION, profile.profile_sha256())
    theirs = (rec.get("validator_version"), rec.get("profile_sha256"))
    if mine != theirs:
        print(f"version difference: the bundle was judged by {theirs[0]} with"
              f" profile {theirs[1]}; this checkout has {mine[0]} with profile"
              f" {mine[1]}. Replay not attempted.")
        return 3
    print(f"profile {mine[0]} {mine[1]} matches the bundle")
    return nandatown(["verify", str(bundle)])


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
