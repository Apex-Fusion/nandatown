"""examples/registry_snapshot: a claim is checked against a registry record
that outlives the run; a former controller with valid signatures is refused
before any traffic, and the validator recomputes every decision."""

import copy
import importlib.util
import json
import shutil
import subprocess
import sys
from pathlib import Path

import pytest
import yaml

from nandatown.layers import resolve
from nandatown.records import TownEvent
from nandatown.sim.engine import Engine
from nandatown.sim.runner import run_lab
from nandatown.sim.scenario import AgentSpec, ScenarioSpec, load_scenario_file
from nandatown.sim.validators import Trace

PROFILE = Path(__file__).resolve().parents[1] / "examples" / "registry_snapshot"
SCENARIOS = PROFILE / "scenarios"
MOCK = json.loads((PROFILE / "snapshots" / "mock.json").read_text(encoding="utf-8"))
IDENTITY = "mock:rotation-demo"


def load(path: Path, name: str):
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


# Importing registers the plugins, the role and the validator. A scenario
# naming the file in plugin_files imports it again; tests use the classes
# the layer registry resolves, not this module's copies.
rs = load(PROFILE / "registry_snapshot.py", "registry_snapshot_under_test")
sys.path.insert(0, str(PROFILE))
mock = load(PROFILE / "make_mock.py", "make_mock_under_test")


def scenario_claims(name: str) -> dict:
    doc = yaml.safe_load((SCENARIOS / name).read_text(encoding="utf-8"))
    return {a["name"]: a["config"]["claim"] for a in doc["agents"]
            if "claim" in a["config"]}


CLAIMS = scenario_claims("rotation_mock.yaml")
STRANGER = mock.sign_claim(mock.keys()["k3"], "stranger", IDENTITY, "mock-registry")


def stages(result):
    return {s.name: s.status for s in result.stages}


def events_of(bundle):
    return [TownEvent.model_validate(json.loads(line)) for line in
            (Path(bundle) / "events.jsonl").read_text(encoding="utf-8").splitlines()]


# -- whole runs ------------------------------------------------------------

def test_mock_pass(tmp_path):
    _, result = run_lab(str(SCENARIOS / "rotation_mock.yaml"), str(tmp_path))
    assert result.verdict == "passed"
    assert stages(result) == {
        "snapshot_loaded": "passed", "former_controller_refused": "passed",
        "former_controller_contained": "passed",
        "current_controller_verified": "passed",
        "current_controller_paid": "passed", "ledger_conserved": "passed",
        "privacy": "not_tested"}


def test_signature_only_control_pays_the_former_controller(tmp_path):
    bundle, result = run_lab(
        str(SCENARIOS / "rotation_mock_sigonly_control.yaml"), str(tmp_path))
    assert result.verdict == "failed"
    s = stages(result)
    assert s["former_controller_refused"] == "failed"
    assert s["former_controller_contained"] == "failed"
    assert s["current_controller_verified"] == "not_tested"
    assert s["current_controller_paid"] == "failed"
    released = [e for e in events_of(bundle) if e.kind == "escrow_released"]
    assert [e.detail["to"] for e in released] == ["provider-former"]
    unchecked = [e for e in events_of(bundle) if e.kind == "registry_claim_unchecked"]
    assert {e.subject for e in unchecked} == {"provider-current", "provider-former"}


def test_vector_mainnet_scenario_needs_no_key(tmp_path):
    """The conftest NANDATOWN_HOME is empty: the run reads no key."""
    snap = json.loads((PROFILE / "snapshots" / "vector-mainnet.json").read_text(encoding="utf-8"))
    bundle, result = run_lab(str(SCENARIOS / "rotation_vector_mainnet.yaml"),
                             str(tmp_path))
    assert result.verdict == "passed"
    refused, = [e for e in events_of(bundle) if e.kind == "registry_claim_refused"]
    record = next(iter(snap["identities"].values()))
    rotation = record["history"][-1]
    assert rotation["event"] == "controller_rotated"
    assert refused.detail["rotation_tx"] == rotation["tx"]
    assert refused.detail["controller_pkh"] == rotation["from_pkh"]


def test_mainnet_claims_match_the_recorded_history():
    snap = json.loads((PROFILE / "snapshots" / "vector-mainnet.json").read_text(encoding="utf-8"))
    (did, record), = snap["identities"].items()
    claims = scenario_claims("rotation_vector_mainnet.yaml")
    for agent, claim in claims.items():
        statement = rs.claim_statement(agent, did, snap["registry"])
        assert rs.signed_by(claim["controller_pub"], statement, claim["signature"])
    assert rs.key_hash(claims["provider-current"]["controller_pub"]) == record["owner_pkh"]
    assert rs.key_hash(claims["provider-former"]["controller_pub"]) == \
        record["history"][0]["owner_pkh"]


def test_wrapper_verifies_and_stock_verify_cannot(tmp_path):
    bundle, _ = run_lab(str(SCENARIOS / "rotation_mock.yaml"), str(tmp_path))
    wrapper = subprocess.run([sys.executable, str(PROFILE / "verify_bundle.py"), bundle],
                             capture_output=True, text=True)
    assert wrapper.returncode == 0, wrapper.stdout + wrapper.stderr
    assert "bundle verified" in wrapper.stdout
    stock = subprocess.run(
        [sys.executable, "-c", "import sys; from nandatown.cli import main;"
         " sys.exit(main(['verify', sys.argv[1]]))", bundle],
        capture_output=True, text=True)
    assert stock.returncode != 0
    assert "evaluator replay mismatch" in stock.stdout + stock.stderr


def test_wrapper_refuses_a_changed_profile(tmp_path):
    bundle, _ = run_lab(str(SCENARIOS / "rotation_mock.yaml"), str(tmp_path / "out"))
    edited = tmp_path / "edited"
    edited.mkdir()
    shutil.copy(PROFILE / "verify_bundle.py", edited)
    text = (PROFILE / "registry_snapshot.py").read_text(encoding="utf-8")
    (edited / "registry_snapshot.py").write_text(text + "\n# edited\n", encoding="utf-8")
    run = subprocess.run([sys.executable, str(edited / "verify_bundle.py"), bundle],
                         capture_output=True, text=True)
    assert run.returncode == 3
    assert "version difference" in run.stdout


@pytest.mark.parametrize("name", [
    "auction", "capability_spoofing", "capability_spoofing_weak_auth",
    "capped_influence", "capped_influence_uncapped_control", "consensus",
    "marketplace", "registry_eviction", "registry_eviction_unowned",
    "supply_chain", "voting"])
def test_drop_in_identity_and_auth_keep_bundled_verdicts(tmp_path, name):
    """claims.v1 + ed25519.v1 in place of keys.v1 + the scenario's auth.
    Only capability_spoofing_weak_auth changes, by design: the swap
    replaces the plain.v1 it exists to demonstrate."""
    plugin = [str(PROFILE / "registry_snapshot.py")]
    _, base = run_lab(name, str(tmp_path / "base"), plugins=plugin)
    _, swapped = run_lab(name, str(tmp_path / "swap"), plugins=plugin,
                         layer_overrides={"identity": "claims.v1",
                                          "auth": "ed25519.v1"})
    if name == "capability_spoofing_weak_auth":
        assert (base.verdict, swapped.verdict) == ("failed", "passed")
    else:
        assert swapped.verdict == base.verdict


def test_mock_data_is_reproducible():
    for rel, render in mock.FILES.items():
        assert (PROFILE / rel).read_text(encoding="utf-8") == render(), rel


# -- the registry check, unit level ------------------------------------------

def town(*agents, registry="snapshot.mock.v1", snapshot=None):
    """Agents: (name, role, claim or None)."""
    spec = ScenarioSpec(
        name="registry-unit",
        agents=[AgentSpec(name=n, role=r, config={"claim": c} if c else {})
                for n, r, c in agents],
        layers={"identity": "claims.v1", "auth": "ed25519.v1", "registry": registry})
    engine = Engine(spec)
    if snapshot is not None:
        engine.layers["registry"].snapshot = snapshot
        engine.layers["registry"].problem = ""
    return engine


def publish(engine, name, card=None, signer=None):
    identity, auth = engine.layers["identity"], engine.layers["auth"]
    card = card or identity.card(name, ["sell.text-stats"], {})
    return engine.layers["registry"].publish(
        signer or name, card, auth.sign_as(signer or name, card))


def kinds(engine, kind):
    return [e for e in engine.events if e.kind == kind]


def test_current_resolves_and_former_is_refused_with_its_rotation():
    e = town(("provider-current", "seller", CLAIMS["provider-current"]),
             ("provider-former", "former_controller", CLAIMS["provider-former"]))
    assert publish(e, "provider-current")
    assert not publish(e, "provider-former")
    resolved, = kinds(e, "registry_claim_resolved")
    refused, = kinds(e, "registry_claim_refused")
    record = MOCK["identities"][IDENTITY]
    assert resolved.detail["owner_pkh"] == record["owner_pkh"]
    assert refused.detail["reason"] == "controller_mismatch"
    assert refused.detail["rotation_tx"] == record["history"][1]["tx"]
    assert e.layers["registry"].names_with("sell.text-stats") == ["provider-current"]


def test_a_key_that_never_controlled_is_refused_without_a_rotation():
    e = town(("stranger", "seller", STRANGER))
    assert not publish(e, "stranger")
    refused, = kinds(e, "registry_claim_refused")
    assert refused.detail["reason"] == "controller_mismatch"
    assert refused.detail["rotation_tx"] is None


def test_a_copied_controller_key_fails_on_the_claim_signature():
    copied = dict(STRANGER, controller_pub=CLAIMS["provider-current"]["controller_pub"])
    e = town(("copycat", "seller", copied))
    assert not publish(e, "copycat")
    assert kinds(e, "registry_claim_refused")[0].detail["reason"] == "claim_signature_invalid"


def test_a_claim_signed_for_another_agent_does_not_transfer():
    e = town(("thief", "seller", CLAIMS["provider-current"]))
    assert not publish(e, "thief")
    assert kinds(e, "registry_claim_refused")[0].detail["reason"] == "claim_signature_invalid"


def test_unknown_and_retired_identities_are_refused():
    snap = copy.deepcopy(MOCK)
    rec = snap["identities"][IDENTITY]
    rec["status"], rec["owner_pkh"] = "retired", None
    rec["history"].append({"event": "retired", "slot": 900, "block_height": 450,
                           "tx": "mock-retire", "from_pkh": MOCK["identities"][IDENTITY]["owner_pkh"]})
    e = town(("provider-current", "seller", CLAIMS["provider-current"]), snapshot=snap)
    assert not publish(e, "provider-current")
    assert kinds(e, "registry_claim_refused")[0].detail["reason"] == "identity_retired"
    snap2 = copy.deepcopy(MOCK)
    snap2["identities"] = {}
    e2 = town(("provider-current", "seller", CLAIMS["provider-current"]), snapshot=snap2)
    assert not publish(e2, "provider-current")
    assert kinds(e2, "registry_claim_refused")[0].detail["reason"] == "identity_unknown"


@pytest.mark.parametrize("mutate,why", [
    (lambda s: s.update(tampered=True), "fingerprint"),
    (lambda s: s["identities"][IDENTITY].update(
        owner_pkh=s["identities"][IDENTITY]["history"][0]["owner_pkh"]), "fingerprint"),
])
def test_an_edited_snapshot_is_unavailable_not_trusted(tmp_path, monkeypatch, mutate, why):
    snap = copy.deepcopy(MOCK)
    mutate(snap)
    (tmp_path / "mock.json").write_text(json.dumps(snap), encoding="utf-8")
    monkeypatch.setattr(rs, "HERE", tmp_path.parent)
    cls = resolve("registry", "snapshot.mock.v1")
    loaded, problem = cls._load(cls.__new__(cls), tmp_path / "mock.json")
    assert loaded is None and why in problem


@pytest.mark.parametrize("edit,why", [
    (lambda r: r.update(owner_pkh=r["history"][0]["owner_pkh"]), "does not match its own history"),
    (lambda r: r["history"][1].update(slot=5000), "after the tip"),
    (lambda r: r["history"][1].update(from_pkh="ab" * 28), "not the controller"),
    (lambda r: r["history"].reverse(), "start with registered"),
])
def test_an_inconsistent_record_is_rejected(edit, why):
    record = copy.deepcopy(MOCK["identities"][IDENTITY])
    edit(record)
    assert why in rs.replay_history(record, MOCK["tip"]["slot"])
    assert rs.replay_history(MOCK["identities"][IDENTITY], MOCK["tip"]["slot"]) == ""


def test_missing_snapshot_refuses_every_claim_as_unavailable(tmp_path):
    e = town(("provider-current", "seller", CLAIMS["provider-current"]))
    e.layers["registry"].snapshot, e.layers["registry"].problem = None, "gone"
    assert not publish(e, "provider-current")
    assert kinds(e, "registry_claim_refused")[0].detail["reason"] == "snapshot_unavailable"
    assert kinds(e, "registry_snapshot_unavailable")


def test_a_foreign_claim_cannot_rewrite_another_listing():
    """The #303 invariant holds: a rival with its own valid claim republishes
    provider-current's card under that name; it is refused and the listing
    stays."""
    rival_claim = mock.sign_claim(mock.keys()["k3"], "provider-current", IDENTITY,
                                  "mock-registry")
    e = town(("provider-current", "seller", CLAIMS["provider-current"]),
             ("rival", "seller", None))
    assert publish(e, "provider-current")
    card = e.layers["identity"].card("provider-current", [], {})
    card["facts"]["registry_claim"] = rival_claim
    card["version"] = 2
    assert not publish(e, "provider-current", card=card, signer="rival")
    assert e.layers["registry"].names_with("sell.text-stats") == ["provider-current"]
    assert "provider-current" not in e.layers["registry"].unbound


def test_only_an_agents_own_failed_claim_unbinds_it():
    e = town(("provider-current", "seller", CLAIMS["provider-current"]),
             ("rival", "seller", None))
    card = e.layers["identity"].card("provider-current", ["sell.text-stats"], {})
    card["facts"]["registry_claim"] = STRANGER
    assert not publish(e, "provider-current", card=card, signer="rival")
    assert "provider-current" not in e.layers["registry"].unbound
    assert publish(e, "provider-current")


def test_a_refused_sender_cannot_deliver_even_card_shaped_bodies():
    e = town(("provider-former", "former_controller", CLAIMS["provider-former"]))
    assert not publish(e, "provider-former")
    body = e.layers["identity"].card("provider-former", ["sell.text-stats"], {})
    sig = e.layers["auth"].sign_as("provider-former", body)
    assert not e.layers["auth"].verify("provider-former", body, sig, subject="m-1")
    assert kinds(e, "registry_sender_unbound")[0].detail["sender"] == "provider-former"


def test_a_card_shaped_message_cannot_harm_another_agent():
    """An agent with no claim sends a body that names provider-current: auth
    judges it under the sender's own key and nothing changes for the named
    agent."""
    e = town(("provider-current", "seller", CLAIMS["provider-current"]),
             ("jammer", "seller", None))
    assert publish(e, "provider-current")
    body = {"name": "provider-current", "agent_id": "x", "capabilities": [],
            "facts": {"registry_claim": STRANGER}}
    sig = e.layers["auth"].sign_as("jammer", body)
    assert e.layers["auth"].verify("jammer", body, sig, subject="m-9")
    assert e.layers["registry"].unbound == {}
    reply = {"sku": "text-stats", "unit_cents": 1995}
    assert e.layers["auth"].verify("provider-current", reply,
                                   e.layers["auth"].sign_as("provider-current", reply))


# -- the validator, on hand-built traces -----------------------------------

@pytest.fixture(scope="module")
def base(tmp_path_factory):
    spec = load_scenario_file(str(SCENARIOS / "rotation_mock.yaml"))
    bundle, result = run_lab(str(SCENARIOS / "rotation_mock.yaml"),
                             str(tmp_path_factory.mktemp("base")))
    assert result.verdict == "passed"
    return spec, events_of(bundle)


def judge(spec, events):
    return {s.name: s.status for s in rs.registry_rotation(spec, Trace(events))}


def ev(events, event_kind, **match):
    return next(e for e in events if e.kind == event_kind
                and all(e.detail.get(k) == v for k, v in match.items()))


def put_before(events, moving, anchor):
    out = [e for e in events if e is not moving]
    out.insert(out.index(anchor), moving)
    return out


def new_event(events, **kw):
    n = len(events) + 100
    return TownEvent(event_id=f"ev-x{n}", run_id=events[0].run_id, at=99.0,
                     detail=kw.pop("detail", {}), **kw)


def test_validator_passes_the_real_trace(base):
    spec, events = base
    assert set(judge(spec, events).values()) == {"passed"}


def test_refusal_after_first_contact_fails(base):
    spec, events = base
    contact = new_event(events, observer="buyer-1", kind="message_sent",
                        subject="m-x", detail={"to": "provider-former", "kind": "quote_request"})
    refusal = ev(events, "registry_claim_refused")
    trace = events[:events.index(refusal)] + [contact] + events[events.index(refusal):]
    assert judge(spec, trace)["former_controller_refused"] == "failed"


def test_accepted_traffic_from_the_former_fails_containment(base):
    spec, events = base
    sent = new_event(events, observer="provider-former", kind="message_sent",
                     subject="m-y", detail={"to": "buyer-1", "kind": "quote_response"})
    delivered = new_event(events, observer="town", kind="message_delivered",
                          subject="m-y", detail={"to": "buyer-1"})
    assert judge(spec, events + [sent, delivered])["former_controller_contained"] == "failed"
    dropped = new_event(events, observer="town", kind="delivery_failed",
                        subject="m-y", detail={"to": "buyer-1", "reason": "bad signature"})
    assert judge(spec, events + [sent, delivered, dropped])["former_controller_contained"] == "passed"


def test_a_settlement_alone_to_the_former_fails_containment(base):
    spec, events = base
    settled = new_event(events, observer="town", kind="payment_settled", subject="o",
                        detail={"to": "provider-former", "cents": 1})
    assert judge(spec, events + [settled])["former_controller_contained"] == "failed"


def test_every_former_must_be_refused(base):
    spec, events = base
    two = spec.model_copy(deep=True)
    two.agents = list(two.agents) + [AgentSpec(name="former-2", role="former_controller",
                                               config={})]
    contact = new_event(events, observer="buyer-1", kind="message_sent", subject="m-z",
                        detail={"to": "former-2", "kind": "quote_request"})
    s = judge(two, events + [contact])
    assert s["former_controller_refused"] == "failed"
    assert s["former_controller_contained"] == "failed"


def test_no_former_means_not_enough_evidence(base):
    spec, events = base
    none = spec.model_copy(deep=True)
    none.agents = [a for a in none.agents if a.role != "former_controller"]
    s = judge(none, events)
    assert s["former_controller_refused"] == "not_enough_evidence"
    assert s["former_controller_contained"] == "not_enough_evidence"


def test_a_refusal_whose_evidence_does_not_recompute_fails(base):
    spec, events = base
    refusal = ev(events, "registry_claim_refused")
    forged = refusal.model_copy(update={"detail": dict(
        refusal.detail, controller_pub=CLAIMS["provider-current"]["controller_pub"])})
    trace = [forged if e is refusal else e for e in events]
    assert judge(spec, trace)["former_controller_refused"] == "failed"


def test_a_refused_key_that_never_controlled_does_not_count(base):
    spec, events = base
    refusal = ev(events, "registry_claim_refused")
    stranger = refusal.model_copy(update={"detail": dict(
        refusal.detail, controller_pub=STRANGER["controller_pub"],
        controller_pkh=rs.key_hash(STRANGER["controller_pub"]),
        signature=mock.sign_claim(mock.keys()["k3"], "provider-former", IDENTITY,
                                  "mock-registry")["signature"])})
    trace = [stranger if e is refusal else e for e in events]
    assert judge(spec, trace)["former_controller_refused"] == "failed"


def test_a_refusal_for_another_reason_does_not_count(base):
    spec, events = base
    refusal = ev(events, "registry_claim_refused")
    other = refusal.model_copy(update={"detail": dict(refusal.detail,
                                                      reason="claim_signature_invalid")})
    trace = [other if e is refusal else e for e in events]
    assert judge(spec, trace)["former_controller_refused"] == "failed"


def test_registration_before_resolution_fails_verification(base):
    spec, events = base
    resolved = ev(events, "registry_claim_resolved")
    card = next(e for e in events if e.kind == "card_registered" and e.subject == "provider-current")
    trace = [e for e in events if e is not card]
    trace.insert(trace.index(resolved), card)
    assert judge(spec, trace)["current_controller_verified"] != "passed"


def test_a_second_key_for_the_same_agent_fails_verification(base):
    spec, events = base
    resolved = ev(events, "registry_claim_resolved")
    other = resolved.model_copy(update={"event_id": "ev-dup", "detail": dict(
        resolved.detail, controller_pkh="ab" * 28)})
    assert judge(spec, events + [other])["current_controller_verified"] == "failed"


def test_payment_before_its_order_does_not_count(base):
    spec, events = base
    release = ev(events, "escrow_released", to="provider-current")
    order = ev(events, "message_sent", kind="purchase_order")
    assert judge(spec, put_before(events, release, order))["current_controller_paid"] == "failed"


def test_an_order_before_resolution_does_not_count(base):
    spec, events = base
    resolved = ev(events, "registry_claim_resolved")
    order = ev(events, "message_sent", kind="purchase_order")
    assert judge(spec, put_before(events, order, resolved))["current_controller_paid"] != "passed"


def test_without_a_snapshot_every_stage_is_not_enough_evidence(base):
    spec, events = base
    loaded = ev(events, "registry_snapshot_loaded")
    gone = loaded.model_copy(update={"kind": "registry_snapshot_unavailable",
                                     "detail": {"reason": "missing"}})
    s = judge(spec, [gone if e is loaded else e for e in events])
    assert set(s.values()) == {"not_enough_evidence"}


def test_an_inconsistent_recorded_snapshot_fails_loading(base):
    spec, events = base
    loaded = ev(events, "registry_snapshot_loaded")
    idents = copy.deepcopy(loaded.detail["identities"])
    idents[IDENTITY]["owner_pkh"] = idents[IDENTITY]["history"][0]["owner_pkh"]
    bad = loaded.model_copy(update={"detail": dict(loaded.detail, identities=idents)})
    s = judge(spec, [bad if e is loaded else e for e in events])
    assert s["snapshot_loaded"] == "failed"
    assert s["former_controller_refused"] == "not_enough_evidence"


def test_a_bundle_from_another_validator_version_is_not_judged(base):
    spec, events = base
    loaded = ev(events, "registry_snapshot_loaded")
    old = loaded.model_copy(update={"detail": dict(loaded.detail, validator_version="registry-rotation-0.0")})
    s = judge(spec, [old if e is loaded else e for e in events])
    assert set(s.values()) == {"not_enough_evidence"}


def test_run_level_missing_snapshot_is_incomplete(tmp_path):
    """A checkout without its snapshot file: every claim is refused as
    unavailable and the run is incomplete, not failed and not passed."""
    copy_dir = tmp_path / "registry_snapshot"
    shutil.copytree(PROFILE, copy_dir, ignore=shutil.ignore_patterns(
        "mock.json", "__pycache__"))
    _, result = run_lab(str(copy_dir / "scenarios" / "rotation_mock.yaml"),
                        str(tmp_path / "out"))
    assert result.verdict == "incomplete"
    assert stages(result)["snapshot_loaded"] == "not_enough_evidence"


def test_contradictory_snapshot_events_are_not_judged(base):
    spec, events = base
    loaded = ev(events, "registry_snapshot_loaded")
    also = loaded.model_copy(update={"event_id": "ev-also",
                                     "kind": "registry_snapshot_unavailable",
                                     "detail": {"reason": "missing"}})
    assert set(judge(spec, events + [also]).values()) == {"not_enough_evidence"}


def test_an_unconfigured_claim_is_refused_even_when_validly_signed():
    """Claims come from agent config. A role that injects a claim it was not
    configured with is refused, even one the current controller signed."""
    endorsed = mock.sign_claim(mock.keys()["k2"], "rival", IDENTITY, "mock-registry")
    e = town(("rival", "seller", None))
    card = e.layers["identity"].card("rival", ["sell.text-stats"], {})
    card["facts"]["registry_claim"] = endorsed
    assert not publish(e, "rival", card=card)
    assert kinds(e, "registry_claim_refused")[0].detail["reason"] == \
        "claim_not_configured_for_agent"


def test_an_inconsistent_pinned_snapshot_is_still_unavailable(tmp_path, monkeypatch):
    """Even a snapshot whose fingerprint is pinned must replay its own
    history before it loads."""
    snap = copy.deepcopy(MOCK)
    rec = snap["identities"][IDENTITY]
    rec["owner_pkh"] = rec["history"][0]["owner_pkh"]
    path = tmp_path / "mock.json"
    path.write_text(json.dumps(snap), encoding="utf-8")
    cls = resolve("registry", "snapshot.mock.v1")
    monkeypatch.setitem(cls._load.__globals__["PINNED"], "mock", rs.fingerprint(snap))
    loaded, problem = cls._load(cls.__new__(cls), path)
    assert loaded is None and "does not match its own history" in problem
