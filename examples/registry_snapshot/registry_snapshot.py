"""Registry snapshot profile: identity claims checked against a record that
outlives the run.

A card may carry a claim that an external registry identity speaks through
this agent. The claim is a statement signed, once and outside any run, by
the identity's controller key:

    {"statement": "registry-claim/v1", "agent": <town agent name>,
     "identity": <identity id>, "registry": <registry id>}

The registry layer checks the claim when the card is published: the
statement must verify under the controller key it presents, and the hash of
that key must be the identity's current controller in a pinned registry
snapshot. A key the snapshot recorded for the identity and has since moved
away from is refused as a former controller, however valid its signatures.
A signature cannot see a transfer; only a record that outlives the run can.

The snapshot is captured before the run (adapters/vector/capture.py is the
first source), pinned by fingerprint below, and recorded in the trace with
every identity record, so the validator recomputes each decision from
events.jsonl. No chain call, wall clock or private controller key enters a
run: agents sign town messages with seeded per-run keys.

    identity  claims.v1                          seeded Ed25519 town keys;
                                                 cards carry configured claims
    auth      ed25519.v1                         Ed25519 under the sender's own
                                                 town key; refuses senders the
                                                 registry recorded as unbound
    registry  snapshot.mock.v1                   synthetic snapshot
              snapshot.vector-mainnet.v1         captured Vector mainnet snapshot
              snapshot.*.sigonly.v1              controls: the claim signature
                                                 is checked, the record is not
    validator registry_rotation                  version registry-rotation-0.1

The registries extend index.owned.v1: only a name's own town key changes
its listing, as before.
"""

from __future__ import annotations

import hashlib
import json
from pathlib import Path
from typing import Any

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

from nandatown.layers import register
from nandatown.layers.registry_layer import OwnedIndex
from nandatown.records import StageResult, canonical_json, fingerprint
from nandatown.sim.agents import Seller, role
from nandatown.sim.validators import Trace, validator

HERE = Path(__file__).resolve().parent
SCHEMA = "registry-snapshot/v1"
STATEMENT = "registry-claim/v1"
VALIDATOR_VERSION = "registry-rotation-0.1"
PINNED = {
    "mock": "sha256:77ab614f48fdc852c568e5c1c825c76f1dba7ef4c5a37359d6913ed4bdcb6a4e",
    "vector-mainnet": "sha256:695ed8e3cbe66a4c749bdf3819cb541fbac49a372743b0c2e8ca72b4b33ec2ac",
}


def profile_sha256() -> str:
    """sha256 of this file with line endings normalized, so a checkout on
    any platform reports the same value."""
    raw = Path(__file__).read_bytes().replace(b"\r\n", b"\n")
    return "sha256:" + hashlib.sha256(raw).hexdigest()


def key_hash(pub_key_hex: str) -> str:
    """blake2b-224 of the raw Ed25519 public key, as Vector hashes keys."""
    return hashlib.blake2b(bytes.fromhex(pub_key_hex),
                           digest_size=28).hexdigest()


def claim_statement(agent: str, identity: str, registry: str) -> dict:
    return {"statement": STATEMENT, "agent": agent, "identity": identity,
            "registry": registry}


def signed_by(pub_key_hex: Any, payload: Any, signature: Any) -> bool:
    try:
        Ed25519PublicKey.from_public_bytes(bytes.fromhex(pub_key_hex)).verify(
            bytes.fromhex(signature), canonical_json(payload).encode())
        return True
    except (InvalidSignature, ValueError, TypeError):
        return False


def replay_history(record: dict, tip_slot: int) -> str:
    """Why a record is inconsistent, or "" when its history derives exactly
    its status and controller, in order, at or before the tip."""
    owner, status, last = None, None, -1
    for i, h in enumerate(record.get("history", [])):
        slot = h.get("slot")
        if not isinstance(slot, int) or slot < last or slot > tip_slot:
            return f"history entry {i} has slot {slot} out of order or after the tip"
        last = slot
        event = h.get("event")
        if i == 0:
            if event != "registered":
                return "history must start with registered"
            owner, status = h.get("owner_pkh"), "active"
        elif status != "active":
            return f"history entry {i} follows retirement"
        elif event == "controller_rotated":
            if h.get("from_pkh") != owner:
                return f"history entry {i} rotates from a key that was not the controller"
            owner = h.get("to_pkh")
        elif event == "retired":
            owner, status = None, "retired"
        elif event != "updated":
            return f"history entry {i} has unknown event {event!r}"
    if status is None:
        return "record has no history"
    if record.get("status") != status or record.get("owner_pkh") != owner:
        return "status or controller does not match its own history"
    return ""


def former_rotation(record: dict, pkh: str) -> dict | None:
    """The last rotation that moved control away from pkh, if any."""
    moved = [h for h in record.get("history", [])
             if h.get("event") == "controller_rotated" and h.get("from_pkh") == pkh]
    return moved[-1] if moved else None


# -- identity ------------------------------------------------------------

@register("identity", "claims.v1")
class ClaimsIdentity:
    """Seeded Ed25519 town keys; a card may carry a configured registry claim."""

    def __init__(self, engine):
        self.engine = engine
        self.identities: dict[str, dict[str, Any]] = {}
        self._seq = 0
        self.claims = {a.name: a.config["claim"] for a in engine.spec.agents
                       if isinstance(a.config.get("claim"), dict)}

    def create(self, name: str) -> dict[str, Any]:
        if name in self.identities:
            return self.identities[name]
        self._seq += 1
        sk = Ed25519PrivateKey.from_private_bytes(
            bytes(self.engine.rng.getrandbits(8) for _ in range(32)))
        pub = sk.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw).hex()
        ident = {"name": name, "agent_id": f"aid-{self._seq}", "sk": sk,
                 "pub_key_hex": pub}
        self.identities[name] = ident
        self.engine.emit("town", "identity_created", name,
                         {"agent_id": ident["agent_id"], "town_key": pub})
        return ident

    def key(self, name: str) -> str | None:
        """A town-local secret, for hmac.v1."""
        ident = self.identities.get(name)
        return hashlib.sha256(ident["sk"].private_bytes_raw()).hexdigest() \
            if ident else None

    def public_key(self, name: str) -> str | None:
        ident = self.identities.get(name)
        return ident["pub_key_hex"] if ident else None

    def card(self, name: str, capabilities: list[str],
             facts: dict[str, Any]) -> dict[str, Any]:
        ident = self.create(name)
        facts = dict(facts)
        if name in self.claims:
            facts["registry_claim"] = dict(self.claims[name])
        return {"name": name, "agent_id": ident["agent_id"],
                "capabilities": capabilities, "facts": facts}


# -- auth ----------------------------------------------------------------

@register("auth", "ed25519.v1")
class Ed25519Auth:
    """Ed25519 under the sender's own town key; refuses unbound senders.

    Every call is judged the same way, whatever the payload looks like:
    the signature must verify under the town key of the name it claims.
    A name the registry layer recorded as unbound (its own claim was
    refused) cannot sign anything that verifies.
    """

    def __init__(self, engine):
        self.engine = engine

    def sign_as(self, name: str, payload: Any) -> str:
        sk = self.engine.layers["identity"].create(name)["sk"]
        return sk.sign(canonical_json(payload).encode()).hex()

    def verify(self, claimed_name: str, payload: Any, signature: str,
               subject: str = "") -> bool:
        unbound = getattr(self.engine.layers["registry"], "unbound", {})
        if claimed_name in unbound:
            self.engine.emit("town", "registry_sender_unbound",
                             subject or claimed_name,
                             {"sender": claimed_name,
                              "identity": unbound[claimed_name]})
            return False
        identity = self.engine.layers["identity"]
        ok = signed_by(identity.public_key(claimed_name), payload, signature)
        if not ok:
            self.engine.emit("town", "signature_invalid",
                             subject or claimed_name, {"claimed": claimed_name})
        return ok


# -- registry ------------------------------------------------------------

class SnapshotIndex(OwnedIndex):
    """index.owned.v1 plus a registry-claim check at publish time."""

    source = ""
    compare_records = True

    def __init__(self, engine):
        super().__init__(engine)
        self.unbound: dict[str, str] = {}
        self._announced = False
        self.snapshot, self.problem = self._load(
            HERE / "snapshots" / f"{self.source}.json")

    def _load(self, path: Path) -> tuple[dict | None, str]:
        try:
            snap = json.loads(path.read_text(encoding="utf-8"))
        except FileNotFoundError:
            return None, f"no snapshot at snapshots/{path.name}"
        except ValueError:
            return None, f"snapshots/{path.name} is not JSON"
        if not isinstance(snap, dict) or snap.get("schema") != SCHEMA:
            return None, f"snapshots/{path.name} is not a {SCHEMA} snapshot"
        if fingerprint(snap) != PINNED.get(self.source):
            return None, (f"snapshots/{path.name} fingerprint {fingerprint(snap)}"
                          f" is not the pinned {PINNED.get(self.source)}")
        if snap.get("source") != self.source:
            return None, f"snapshot source {snap.get('source')!r} is not {self.source!r}"
        tip = snap.get("tip", {}).get("slot")
        for ident, record in snap.get("identities", {}).items():
            why = replay_history(record, tip if isinstance(tip, int) else -1)
            if why:
                return None, f"inconsistent record for {ident}: {why}"
        return snap, ""

    def _announce(self) -> None:
        if self._announced:
            return
        self._announced = True
        base = {"source": self.source, "compare_records": self.compare_records,
                "validator_version": VALIDATOR_VERSION,
                "profile_sha256": profile_sha256()}
        if self.snapshot is None:
            self.engine.emit("town", "registry_snapshot_unavailable", "registry",
                             dict(base, reason=self.problem))
            return
        s = self.snapshot
        self.engine.emit("town", "registry_snapshot_loaded", "registry", dict(
            base, fingerprint=fingerprint(s), network=s.get("network"),
            registry=s.get("registry"), key_hash=s.get("key_hash"),
            tip=s.get("tip"), identities=s.get("identities")))

    def lookup(self, capability: str, include_unverified: bool = False):
        self._announce()
        return super().lookup(capability, include_unverified)

    def publish(self, publisher: str, card: dict[str, Any],
                signature: str) -> bool:
        self._announce()
        facts = card.get("facts") if isinstance(card.get("facts"), dict) else {}
        claim = facts.get("registry_claim")
        if claim is None:
            return super().publish(publisher, card, signature)
        name = card["name"]

        def refuse(reason: str, **more) -> bool:
            return self._refuse_claim(publisher, card, reason, claim, more)

        configured = self.engine.layers["identity"].claims.get(name)
        if not isinstance(claim, dict) or configured is None \
                or claim.get("identity") != configured.get("identity"):
            return refuse("claim_not_configured_for_agent")
        if self.snapshot is None:
            return refuse("snapshot_unavailable", detail=self.problem)
        statement = claim_statement(name, claim["identity"],
                                    self.snapshot.get("registry"))
        if not signed_by(claim.get("controller_pub"), statement,
                         claim.get("signature")):
            return refuse("claim_signature_invalid")
        evidence = {"identity": claim["identity"],
                    "controller_pub": claim["controller_pub"],
                    "controller_pkh": key_hash(claim["controller_pub"]),
                    "signature": claim["signature"],
                    "card": fingerprint(card)}
        if not self.compare_records:
            self.engine.emit("town", "registry_claim_unchecked", name,
                             dict(evidence, reason="record comparison disabled"))
            return super().publish(publisher, card, signature)
        record = self.snapshot.get("identities", {}).get(claim["identity"])
        if record is None:
            return refuse("identity_unknown", **evidence)
        if record["status"] != "active":
            return refuse("identity_retired", **evidence)
        if record["owner_pkh"] != evidence["controller_pkh"]:
            moved = former_rotation(record, evidence["controller_pkh"])
            return refuse("controller_mismatch", **evidence,
                          owner_pkh=record["owner_pkh"],
                          rotation_tx=moved and moved.get("tx"))
        self.engine.emit("town", "registry_claim_resolved", name,
                         dict(evidence, owner_pkh=record["owner_pkh"],
                              registry_ref=record.get("registry_ref")))
        return super().publish(publisher, card, signature)

    def _refuse_claim(self, publisher: str, card: dict[str, Any], reason: str,
                      claim: Any, more: dict) -> bool:
        name = card["name"]
        if publisher == name:
            # Only an agent's own failed claim unbinds it; another agent's
            # forgery in its name changes nothing about it.
            self.unbound[name] = claim.get("identity") if isinstance(claim, dict) else None
        self.engine.emit("town", "registry_claim_refused", name,
                         dict(more, reason=reason, publisher=publisher))
        return self._refuse(card, publisher, f"registry claim refused: {reason}")


@register("registry", "snapshot.mock.v1")
class MockSnapshotIndex(SnapshotIndex):
    """Registry claims checked against the synthetic mock snapshot."""
    source = "mock"


@register("registry", "snapshot.mock.sigonly.v1")
class MockSigOnlyIndex(MockSnapshotIndex):
    """Control: claim signatures checked, the mock snapshot record not."""
    compare_records = False


@register("registry", "snapshot.vector-mainnet.v1")
class VectorMainnetIndex(SnapshotIndex):
    """Registry claims checked against the captured Vector mainnet snapshot."""
    source = "vector-mainnet"


@register("registry", "snapshot.vector-mainnet.sigonly.v1")
class VectorMainnetSigOnlyIndex(VectorMainnetIndex):
    """Control: claim signatures checked, the Vector mainnet record not."""
    compare_records = False


@role("former_controller")
class FormerController(Seller):
    """A seller whose claim is signed by a key the registry has since moved
    the identity away from. Its signatures are all valid. It prices below
    the current controller and delivers honestly, so a buyer that cannot
    see the transfer has every reason to pick it."""


# -- validator -----------------------------------------------------------

def _passed(name, evidence, note=""):
    return StageResult(name=name, status="passed", evidence=evidence[:8], note=note)


def _failed(name, evidence, note):
    return StageResult(name=name, status="failed", evidence=evidence[:8], note=note)


def _missing(name, note):
    return StageResult(name=name, status="not_enough_evidence", note=note)


def _not_tested(name, note):
    return StageResult(name=name, status="not_tested", note=note)


def _ids(events) -> list[str]:
    return [e.event_id for e in events]


def _recomputes(event, snap: dict, agent: str) -> str:
    """Why a claim event's recorded evidence does not support it, or ""."""
    d = event.detail
    statement = claim_statement(agent, d.get("identity"), snap.get("registry"))
    if not signed_by(d.get("controller_pub"), statement, d.get("signature")):
        return "the recorded claim signature does not verify"
    if key_hash(d.get("controller_pub", "")) != d.get("controller_pkh"):
        return "the recorded key hash is not the hash of the recorded key"
    return ""


def _not_former(event, records: dict) -> str:
    """Why a refusal's key is not a former controller of its identity in
    the recorded snapshot, or ""."""
    record = records.get(event.detail.get("identity"), {})
    pkh = event.detail.get("controller_pkh")
    if record.get("status") != "active" or record.get("owner_pkh") == pkh:
        return "the recorded identity is not active under another key"
    if not former_rotation(record, pkh):
        return "the recorded history never moved control away from this key"
    return ""


@validator("registry_rotation")
def registry_rotation(spec, trace: Trace) -> list:
    """Recomputed from events.jsonl alone, per agent: every former
    controller is refused on the snapshot record before any traffic with
    it and gets no traffic and no money; every current controller resolves
    to the recorded controller and is paid for an order placed after that.
    Without a loaded snapshot nothing can be judged: every stage is
    not_enough_evidence, never failed and never passed."""
    stages = []
    formers = [a.name for a in spec.agents if a.role == "former_controller"]
    currents = [a.name for a in spec.agents if a.role == "seller"
                and isinstance(a.config.get("claim"), dict)]
    names = ["former_controller_refused", "former_controller_contained",
             "current_controller_verified", "current_controller_paid"]

    loaded = trace.find("registry_snapshot_loaded")
    unavailable = trace.find("registry_snapshot_unavailable")
    snap_event = loaded[0] if loaded and not unavailable else None
    snap = snap_event.detail if snap_event else {}
    if snap_event and snap.get("validator_version") != VALIDATOR_VERSION:
        return [_missing("snapshot_loaded",
                         f"bundle judged by {snap.get('validator_version')}, this"
                         f" validator is {VALIDATOR_VERSION}")] + \
            [_missing(n, "validator version differs") for n in names]
    if snap_event is None:
        why = unavailable[0].detail.get("reason") if unavailable else "no snapshot event"
        return [_missing("snapshot_loaded", f"no registry snapshot: {why}")] + \
            [_missing(n, "needs a loaded registry snapshot") for n in names]
    tip = (snap.get("tip") or {}).get("slot", -1)
    inconsistent = [f"{i}: {w}" for i, r in (snap.get("identities") or {}).items()
                    if (w := replay_history(r, tip))]
    if inconsistent:
        return [_failed("snapshot_loaded", _ids([snap_event]),
                        "recorded snapshot is inconsistent: " + "; ".join(inconsistent))] + \
            [_missing(n, "needs a consistent registry snapshot") for n in names]
    stages.append(_passed(
        "snapshot_loaded", _ids([snap_event]),
        f"{snap.get('source')} snapshot {snap.get('fingerprint')}, tip slot {tip};"
        f" records compared: {snap.get('compare_records')}"))
    records = snap.get("identities") or {}

    def sent_to(agent):
        return [e for e in trace.find("message_sent") if e.detail.get("to") == agent]

    failed_ids = {e.subject for e in trace.find("delivery_failed")}
    delivered_ids = {e.subject for e in trace.find("message_delivered")}

    def accepted_from(agent):
        return [e for e in trace.find("message_sent") if e.observer == agent
                and e.subject in delivered_ids and e.subject not in failed_ids]

    def paid(agent):
        return [e for e in trace.find("escrow_released") + trace.find("payment_settled")
                if e.detail.get("to") == agent]

    # Former controllers: refused for the record, before any traffic.
    if not formers:
        stages.append(_missing("former_controller_refused",
                               "the scenario has no former controller"))
        stages.append(_missing("former_controller_contained",
                               "the scenario has no former controller"))
    else:
        ok, evidence, notes = True, [], []
        for agent in formers:
            traffic = sent_to(agent) + accepted_from(agent)
            first = min((trace.index(e) for e in traffic), default=len(trace.events))
            good = []
            for e in trace.find("registry_claim_refused", reason="controller_mismatch"):
                if e.subject != agent or trace.index(e) > first:
                    continue
                why = _recomputes(e, snap, agent) or _not_former(e, records)
                if why:
                    notes.append(f"{agent} ({e.event_id}): {why}")
                else:
                    good.append(e)
            if not good:
                ok = False
                notes.append(f"{agent} was not refused as a former controller before"
                             f" its first traffic")
                evidence += _ids(traffic[:2] + trace.find("card_registered", verified=True))
            evidence += _ids(good[:1])
        if snap.get("compare_records") is False:
            notes.append("control: records not compared")
        stages.append(_passed("former_controller_refused", evidence,
                              "; ".join(notes)) if ok and evidence
                      else _failed("former_controller_refused",
                                   evidence or trace.ids("run_finished"),
                                   "; ".join(notes)))

        ok, evidence, counts = True, [], []
        for agent in formers:
            bad = sent_to(agent) + accepted_from(agent) + paid(agent)
            counts.append(f"{agent}: {len(sent_to(agent))} sent to,"
                          f" {len(accepted_from(agent))} accepted from,"
                          f" {len(trace.find('escrow_released', to=agent))} escrow"
                          f" release(s), {len(trace.find('payment_settled', to=agent))}"
                          f" settlement(s)")
            if bad:
                ok = False
                evidence += _ids(bad)
        stages.append(_passed("former_controller_contained", trace.ids("run_finished"),
                              "; ".join(counts)) if ok
                      else _failed("former_controller_contained", evidence,
                                   "the former controller must get no traffic and no"
                                   " money; " + "; ".join(counts)))

    # Current controllers: resolved to the recorded controller, then paid.
    if not currents:
        stages.append(_missing("current_controller_verified",
                               "the scenario has no claiming seller"))
        stages.append(_missing("current_controller_paid",
                               "the scenario has no claiming seller"))
        return stages
    if snap.get("compare_records") is False:
        stages.append(_not_tested("current_controller_verified",
                                  "control: the registry does not compare records"))
    resolved_at = {}
    ok, evidence, notes = True, [], []
    for agent in currents:
        resolutions = [e for e in trace.find("registry_claim_resolved")
                       if e.subject == agent]
        registered = [e for e in trace.find("card_registered", verified=True)
                      if e.subject == agent]
        good = [e for e in resolutions if not _recomputes(e, snap, agent)
                and records.get(e.detail.get("identity"), {}).get("owner_pkh")
                == e.detail.get("controller_pkh")]
        keys = {e.detail.get("controller_pkh") for e in resolutions}
        after = [c for c in registered if good and trace.index(c) > trace.index(good[0])]
        if good and after and len(keys) == 1:
            resolved_at[agent] = trace.index(good[0])
            evidence += _ids([good[0], after[0]])
        else:
            ok = False
            evidence += _ids(resolutions + registered)
            notes.append(f"{agent}: needs one recomputable resolution to the recorded"
                         f" controller, then a verified card, and no other key")
    if snap.get("compare_records") is not False:
        if ok:
            stages.append(_passed("current_controller_verified", evidence))
        elif evidence:
            stages.append(_failed("current_controller_verified", evidence,
                                  "; ".join(notes)))
        else:
            stages.append(_missing("current_controller_verified", "; ".join(notes)))

    paid_ok, evidence = True, []
    for agent in currents:
        orders = {}
        for e in trace.find("message_sent", kind="purchase_order"):
            body = e.detail.get("body")
            if (e.detail.get("to") == agent and agent in resolved_at
                    and trace.index(e) > resolved_at[agent] and isinstance(body, dict)
                    and isinstance(body.get("order_id"), str)):
                orders[body["order_id"]] = trace.index(e)
        releases = [e for e in trace.find("escrow_released", to=agent)
                    if e.subject in orders and trace.index(e) > orders[e.subject]]
        if releases:
            evidence += _ids(releases[:1])
        else:
            paid_ok = False
    if paid_ok:
        stages.append(_passed("current_controller_paid", evidence))
    elif resolved_at or snap.get("compare_records") is False:
        stages.append(_failed("current_controller_paid",
                              evidence or _ids(trace.find("escrow_released"))
                              or trace.ids("run_finished"),
                              "the current controller must be paid for an order"
                              " placed after its claim resolved"))
    else:
        stages.append(_missing("current_controller_paid",
                               "no current controller resolved, so no order can be"
                               " judged"))
    return stages
