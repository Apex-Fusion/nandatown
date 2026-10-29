"""Vector adapter: write scenarios/rotation_vector_mainnet.yaml from two signed claims.

    python make_scenario.py --did <did> --current-skey k2.skey --former-skey k1.skey

The operator signs one claim per agent with the controller keys, once,
here: k2 for provider-current, k1 for provider-former. Off-chain signatures
only; nothing is submitted, and no key enters a Lab run. Ed25519 signatures
are deterministic, so the same keys reproduce the same file.
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE.parents[1]))
from sign_claim import load_key, sign_claim  # noqa: E402

POLICY = "be1a0a2912da180757ed3cd61b56bb8eab0188c19dc3c0e3912d2c01"
DESCRIPTION = ("Vector mainnet snapshot. vector-rotation-demo was registered under K1"
               " and transferred to K2 on Vector mainnet; snapshots/vector-mainnet.json"
               " records both transactions. Each provider presents a claim its"
               " controller key signed once, off-chain, before the run. K1's claim is"
               " refused on the record before any traffic; K2 is verified and paid."
               " Both claimants are Apex Fusion's, first-party; the identity was minted"
               " for this demo on 2026-10-29. No chain call and no private key in the run.")


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--did", required=True)
    ap.add_argument("--current-skey", required=True)
    ap.add_argument("--former-skey", required=True)
    a = ap.parse_args()
    current = sign_claim(load_key(a.current_skey, None), "provider-current", a.did, POLICY)
    former = sign_claim(load_key(a.former_skey, None), "provider-former", a.did, POLICY)
    text = f"""name: rotation_vector_mainnet
description: {json.dumps(DESCRIPTION)}
seed: 42
validator: registry_rotation
plugin_files: [../registry_snapshot.py]
layers:
  identity: claims.v1
  auth: ed25519.v1
  registry: snapshot.vector-mainnet.v1
agents:
  - name: provider-current
    role: seller
    config: {{sku: text-stats, ask_cents: 1995, floor_cents: 1700, stock: 10, balance_cents: 0, claim: {json.dumps(current)}}}
  - name: provider-former
    role: former_controller
    config: {{sku: text-stats, ask_cents: 1500, floor_cents: 1200, stock: 10, balance_cents: 0, claim: {json.dumps(former)}}}
  - name: buyer-1
    role: buyer
    config: {{sku: text-stats, quantity: 1, cap_cents: 1900, balance_cents: 10000, rounds: 1}}
max_time: 60
"""
    out = HERE.parents[1] / "scenarios" / "rotation_vector_mainnet.yaml"
    out.write_text(text, encoding="utf-8", newline="\n")
    print(f"wrote {out}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
