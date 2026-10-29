"""Vector adapter: capture a registry-snapshot/v1 file from Vector mainnet.

    python capture.py --did did:vector:agent:<policy>:<asset> [--did ...] \
        [--out vector-mainnet.json] [--force] [--record-fixture koios.json]

Reads Vector's public Koios API (keyless, read-only) and records, for each
agent identity: every transaction that ever moved its registry token, in
chain order (block height, then position in the block), the controller key
hash after each one (registry datum field 0, a verification-key
credential), and the registry output that holds it now. The chain tip is
read after the histories, and every history slot must be at or before it.
The network is identified by its genesis (system start, network magic,
security parameter), and each identity's depth is recorded against that
security parameter, so a reader can see how settled the record was.

Everything in the file is public chain data; each transaction can be
re-checked on chain. Run once, before a Lab run; the Lab never calls a chain.
Refuses to overwrite an existing file without --force.
"""

from __future__ import annotations

import argparse
import json
import sys
import urllib.request
from pathlib import Path

HERE = Path(__file__).resolve().parent
KOIOS = "https://v2.koios.vector.mainnet.apexfusion.org/api/v1"
POLICY = "be1a0a2912da180757ed3cd61b56bb8eab0188c19dc3c0e3912d2c01"
DID_PREFIX = "did:vector:agent:"
PAGE = 1000


RECORDED: dict | None = None


def koios(path: str, body: dict | None = None):
    """One Koios call. With --record-fixture, every response is also kept,
    keyed by the request, so a test can replay the capture offline."""
    req = urllib.request.Request(
        KOIOS + path, data=None if body is None else json.dumps(body).encode(),
        headers={"accept": "application/json", "content-type": "application/json",
                 "user-agent": "registry-snapshot-capture/1"})
    with urllib.request.urlopen(req, timeout=60) as resp:
        out = json.loads(resp.read())
    if RECORDED is not None:
        RECORDED[request_key(path, body)] = out
    return out


def request_key(path: str, body: dict | None) -> str:
    return path if body is None else path + " " + json.dumps(body, sort_keys=True)


def parse_did(did: str) -> str:
    if not did.startswith(DID_PREFIX):
        raise SystemExit(f"not a Vector agent DID: {did}")
    policy, _, asset = did[len(DID_PREFIX):].partition(":")
    if policy != POLICY or not asset:
        raise SystemExit(f"{did}: not an identity of registry {POLICY}")
    return asset


def owner_of(output: dict) -> str:
    datum = output.get("inline_datum") or {}
    try:
        cred = datum["value"]["fields"][0]
        if cred.get("constructor") != 0:
            raise SystemExit(f"{output['tx_hash']}: owner is not a key credential")
        return cred["fields"][0]["bytes"]
    except (KeyError, IndexError, TypeError):
        raise SystemExit(f"{output.get('tx_hash')}: no registry datum owner")


def holder(tx: dict, asset: str) -> dict | None:
    for o in tx["outputs"]:
        if any(a.get("policy_id") == POLICY and a.get("asset_name") == asset
               for a in o.get("asset_list") or []):
            cred = (o.get("payment_addr") or {}).get("cred")
            if cred != POLICY:
                raise SystemExit(f"{tx['tx_hash']}: token left the registry script"
                                 f" (payment credential {cred})")
            return o
    return None


def asset_txs(asset: str) -> list[str]:
    hashes, offset = [], 0
    while True:
        page = koios(f"/asset_txs?_asset_policy={POLICY}&_asset_name={asset}"
                     f"&_history=true&order=block_height.asc,tx_hash.asc"
                     f"&offset={offset}&limit={PAGE}")
        hashes += [t["tx_hash"] for t in page]
        if len(page) < PAGE:
            return list(dict.fromkeys(hashes))
        offset += PAGE


def capture_identity(did: str) -> dict:
    asset = parse_did(did)
    hashes = asset_txs(asset)
    if not hashes:
        raise SystemExit(f"{did}: no registry transactions")
    infos = []
    for i in range(0, len(hashes), 50):
        infos += koios("/tx_info", {"_tx_hashes": hashes[i:i + 50], "_inputs": True,
                                    "_assets": True, "_scripts": True})
    infos.sort(key=lambda t: (t["block_height"], t["tx_block_index"]))
    history, owner, ref = [], None, None
    for tx in infos:
        step = {"tx": tx["tx_hash"], "slot": tx["absolute_slot"],
                "block_height": tx["block_height"]}
        out = holder(tx, asset)
        if out is None:
            history.append(dict(step, event="retired", from_pkh=owner))
            owner, ref = None, None
            continue
        after = owner_of(dict(out, tx_hash=tx["tx_hash"]))
        if not history:
            history.append(dict(step, event="registered", owner_pkh=after))
        elif after != owner:
            history.append(dict(step, event="controller_rotated",
                                from_pkh=owner, to_pkh=after))
        else:
            history.append(dict(step, event="updated", owner_pkh=after))
        owner, ref = after, f"{tx['tx_hash']}#{out['tx_index']}"
    return {"status": "active" if owner else "retired", "owner_pkh": owner,
            "registry_ref": ref, "history": history}


def capture(dids: list[str]) -> dict:
    identities = {d: capture_identity(d) for d in sorted(set(dids))}
    tip = koios("/tip")[0]
    genesis = koios("/genesis")[0]
    k = int(genesis["securityparam"])
    for did, rec in identities.items():
        late = [h["tx"] for h in rec["history"] if h["slot"] > tip["abs_slot"]]
        if late:
            raise SystemExit(f"{did}: history after the tip {late}")
        rec["blocks_deep_at_tip"] = tip["block_height"] - rec["history"][-1]["block_height"]
    return {
        "schema": "registry-snapshot/v1",
        "source": "vector-mainnet",
        "network": {"name": "vector-mainnet", "koios": KOIOS,
                    "system_start": int(genesis["systemstart"]),
                    "network_magic": int(genesis["networkmagic"]),
                    "security_param": k},
        "registry": POLICY,
        "key_hash": "blake2b-224 of the raw Ed25519 public key",
        "tip": {"slot": tip["abs_slot"], "block_height": tip["block_height"],
                "block_hash": tip["hash"]},
        "identities": identities,
    }


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--did", action="append", required=True)
    ap.add_argument("--out", default=str(HERE / "vector-mainnet.json"))
    ap.add_argument("--force", action="store_true")
    ap.add_argument("--record-fixture", help="also write every Koios response here")
    a = ap.parse_args(argv)
    out = Path(a.out)
    if out.exists() and not a.force:
        raise SystemExit(f"REFUSING: {out} exists (pinned); pass --force to recapture")
    global RECORDED
    if a.record_fixture:
        RECORDED = {}
    snap = capture(a.did)
    out.write_text(json.dumps(snap, indent=2, sort_keys=True) + "\n",
                   encoding="utf-8", newline="\n")
    for did, rec in snap["identities"].items():
        print(f"{did}: {rec['status']}, {len(rec['history'])} txs,"
              f" {rec['blocks_deep_at_tip']} blocks deep (k = {snap['network']['security_param']})")
    from nandatown.records import fingerprint
    print(f"wrote {out} at tip slot {snap['tip']['slot']}, fingerprint {fingerprint(snap)}"
          " (pin it in vector_snapshot.py)")
    if a.record_fixture:
        Path(a.record_fixture).write_text(json.dumps(RECORDED, indent=1, sort_keys=True)
                                          + "\n", encoding="utf-8", newline="\n")
    return 0


if __name__ == "__main__":
    sys.exit(main())
