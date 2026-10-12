"""A single observer must not be able to move a reputation without limit.

reputation.v1 sums every receipt it is handed, so one agent that never
trades can drive a counterparty's score arbitrarily low, and
reputation_consistent approves each step. reputation.capped.v1 caps any
one observer at 1 and gives an observer with no settled trade no weight.
"""

import pytest

from nandatown.sim.api import TownAPI
from nandatown.bundle import verify_bundle
from nandatown.sim.engine import Engine, SubscriptionLoop
from nandatown.sim.runner import build_engine, run_lab
from nandatown.sim.scenario import load_bundled
from nandatown.sim.validators import (
    Trace, evaluate_scenario, reputation_capped, reputation_consistent,
)

CAPPED = "reputation.capped.v1"


def slander(trust_plugin: str, times: int = 5):
    """One observer with no settled trade rates one seller bad, repeatedly."""
    spec = load_bundled("marketplace")
    spec.layers["trust"] = trust_plugin
    engine = Engine(spec)
    engine.layers["identity"].create("slanderer")
    api = TownAPI(engine, "slanderer")
    for _ in range(times):
        api.rate("seller-a", "bad")
    return engine, api


@pytest.mark.parametrize("trust_plugin,want", [
    (CAPPED, 0),           # no settled trade: the reports carry no weight
    ("reputation.v1", -5),  # the gap this change addresses, kept pinned
])
def test_one_observer_with_no_trade_history(trust_plugin, want):
    """Five reports from one voice. Bounded moves nothing; v1 moves five."""
    _, api = slander(trust_plugin)
    assert api.reputation("seller-a") == want


def test_unbounded_slander_still_satisfies_the_reference_arithmetic_check():
    """reputation_consistent replays the +1/-1 formula and finds the
    slander correct, so it cannot detect the attack."""
    engine, _ = slander("reputation.v1")
    assert reputation_consistent(Trace(engine.events)).status == "passed"


def test_an_established_observer_is_still_capped_at_one_point():
    """The weight rule alone would let one trading agent shout."""
    spec = load_bundled("marketplace")
    spec.layers["trust"] = CAPPED
    engine = Engine(spec)
    engine.layers["identity"].create("buyer-real")
    engine.emit("town", "payment_settled", "order-x",
                {"from": "buyer-real", "to": "seller-a", "cents": 10,
                 "via": "escrow"})
    api = TownAPI(engine, "buyer-real")
    for _ in range(4):
        api.rate("seller-a", "good")
    assert api.reputation("seller-a") == 1
    deltas = [e.detail["delta"] for e in engine.events
              if e.kind == "reputation_updated"]
    assert deltas == [1, 0, 0, 0], "only the first report may move the score"


def test_distinct_observers_still_accumulate():
    """The cap is per observer, not a cap on the score itself."""
    spec = load_bundled("marketplace")
    spec.layers["trust"] = CAPPED
    engine = Engine(spec)
    for who in ("buyer-x", "buyer-y"):
        engine.layers["identity"].create(who)
        engine.emit("town", "payment_settled", f"order-{who}",
                    {"from": who, "to": "seller-a", "cents": 10,
                     "via": "escrow"})
        TownAPI(engine, who).rate("seller-a", "good")
    assert engine.layers["trust"].score("seller-a") == 2


def test_a_discarded_report_is_still_recorded():
    """A report that did not count must not vanish from the trace."""
    engine, _ = slander(CAPPED, times=2)
    updates = [e for e in engine.events if e.kind == "reputation_updated"]
    assert len(updates) == 2
    for event in updates:
        assert event.detail["delta"] == 0
        assert event.detail["observer_weight"] == 0
        assert event.detail["reason"] == "observer_has_no_settled_trade"


# -- the companion validator --------------------------------------------


def mixed_trace(trust_plugin: str):
    """One observer that settled a trade, one that never did."""
    spec = load_bundled("marketplace")
    spec.layers["trust"] = trust_plugin
    engine = Engine(spec)
    for who in ("buyer-real", "slanderer"):
        engine.layers["identity"].create(who)
    engine.emit("town", "payment_settled", "order-x",
                {"from": "buyer-real", "to": "seller-a", "cents": 10,
                 "via": "escrow"})
    TownAPI(engine, "buyer-real").rate("seller-a", "good")
    api = TownAPI(engine, "slanderer")
    for _ in range(5):
        api.rate("seller-a", "bad")
    return engine


def test_capped_check_passes_a_capped_trace():
    engine = mixed_trace(CAPPED)
    stage = reputation_capped(Trace(engine.events))
    assert stage.status == "passed", stage.note
    assert engine.layers["trust"].score("seller-a") == 1


def test_capped_check_names_the_full_movement_it_rejects():
    """The note must carry the magnitude, not just the first point of it."""
    stage = reputation_capped(Trace(mixed_trace("reputation.v1").events))
    assert stage.status == "failed"
    assert "-5" in stage.note, stage.note
    assert "slanderer" in stage.note


def test_empty_capped_check_is_missing_not_success():
    assert reputation_capped(Trace([])).status == "not_enough_evidence"


def test_capped_check_does_not_judge_the_reference_formula():
    """The two checks stay separate: neither validates the other's rules."""
    events = mixed_trace(CAPPED).events
    # A capped trace fails the unbounded arithmetic check by construction,
    # which is exactly why reputation_consistent was left alone.
    assert reputation_consistent(Trace(events)).status == "failed"
    assert reputation_capped(Trace(events)).status == "passed"


# -- the scenario and its negative control ------------------------------


def capped_trace(name="capped_influence"):
    spec = load_bundled(name)
    engine = build_engine(spec)
    engine.run()
    return spec, [event.model_copy(deep=True) for event in engine.events]


def stage_of(spec, events, name="influence_capped"):
    result = evaluate_scenario(spec, events[0].run_id, events)
    return next(s for s in result.stages if s.name == name)


def test_capped_influence_scenario_passes_and_verifies(tmp_path):
    bundle_dir, result = run_lab("capped_influence", str(tmp_path))
    stages = {s.name: s.status for s in result.stages}
    assert result.verdict == "passed", stages
    assert stages["influence_capped"] == "passed"
    assert stages["honest_signal_survives"] == "passed"
    assert verify_bundle(bundle_dir) == []


def test_unbounded_control_breaks_the_town(tmp_path):
    """Identical but for the trust layer, and must fail: one voice with no
    trade history buries a seller the buyer actually paid."""
    bundle_dir, result = run_lab("capped_influence_uncapped_control",
                                 str(tmp_path))
    stages = {s.name: s.status for s in result.stages}
    assert result.verdict == "failed", stages
    assert stages["influence_capped"] == "failed"
    assert stages["honest_signal_survives"] == "failed"
    assert stages["slander_filed"] == "passed", "the attack must have run"
    assert stages["honest_trade_completed"] == "passed", "the trade still closes"
    assert verify_bundle(bundle_dir) == []
    note = next(s for s in result.stages if s.name == "influence_capped").note
    assert "-5" in note, note


def test_the_two_scenarios_differ_only_in_the_trust_layer():
    capped = load_bundled("capped_influence")
    control = load_bundled("capped_influence_uncapped_control")
    assert capped.layers["trust"] == CAPPED
    assert control.layers["trust"] == "reputation.v1"
    assert capped.agents == control.agents
    assert capped.seed == control.seed
    differing = {layer for layer in capped.layers
                 if capped.layers[layer] != control.layers[layer]}
    assert differing == {"trust"}


@pytest.mark.parametrize("case,want", [
    ("clean", "passed"),
    ("missing_receipts", "not_enough_evidence"),
    ("reused_receipt", "failed"),
    ("wrong_observer", "failed"),
    ("self_report", "failed"),
    ("wrong_claim", "failed"),
    ("forged_weight_claim", "failed"),
    ("inflated_delta", "failed"),
    ("inflated_score", "failed"),
    ("string_delta", "failed"),
    ("unknown_outcome", "failed"),
])
def test_capped_check_rejects_tampered_traces(case, want):
    """Removing any of these checks must break one of these regressions."""
    spec, events = capped_trace()
    receipts = [e for e in events if e.kind == "receipt_attested"]
    updates = [e for e in events if e.kind == "reputation_updated"]
    counted = next(e for e in updates if e.detail["delta"] != 0)
    discarded = next(e for e in updates if e.detail["delta"] == 0)

    if case == "missing_receipts":
        events = [e for e in events if e.kind != "receipt_attested"]
    elif case == "reused_receipt":
        updates[1].detail["receipt"] = updates[0].detail["receipt"]
    elif case == "wrong_observer":
        counted.observer = "unrelated-buyer"
    elif case == "self_report":
        receipts[0].observer = counted.observer = counted.subject
    elif case == "wrong_claim":
        receipts[0].detail["claim"] = "endpoint.live"
    elif case == "forged_weight_claim":
        # An observer with no settled trade claiming its report counted.
        discarded.detail.update(delta=-1, score=0, observer_weight=1,
                                reason="counted")
    elif case == "inflated_delta":
        counted.detail["delta"] = 2
    elif case == "inflated_score":
        counted.detail["score"] = 99
    elif case == "string_delta":
        counted.detail["delta"] = "1"
    elif case == "unknown_outcome":
        counted.detail["outcome"] = "uncertain"

    assert stage_of(spec, events).status == want


# -- the enfranchisement lifecycle --------------------------------------


REPUTATION_KINDS = ("reputation_updated", "reputation_reweighted")


def lifecycle_engine():
    """alice and bob, who will settle one cent between them, and a seller."""
    spec = load_bundled("capped_influence")
    engine = Engine(spec)
    for who in ("alice", "bob", "seller"):
        engine.layers["identity"].create(who)
    engine.layers["payments"].open_account("alice", 10)
    engine.layers["payments"].open_account("bob", 0)
    return engine


def recorded_reputation(engine):
    return [event for event in engine.events
            if event.kind in REPUTATION_KINDS]


def assert_three_views_agree(engine, subject, expected, step):
    """In-memory == newest recorded, and the replay accepts every recorded
    score, which together make all three agree."""
    trust = engine.layers["trust"]
    events = [event.model_copy(deep=True) for event in engine.events]
    recorded = [event for event in events if event.kind in REPUTATION_KINDS]
    stage = reputation_capped(Trace(events))

    in_memory = trust.score(subject)
    assert in_memory == expected, (
        f"{step}: plugin returned {in_memory:+d}, expected {expected:+d}")
    assert recorded, f"{step}: the score changed with nothing recorded"
    newest = recorded[-1].detail["score"]
    assert newest == in_memory, (
        f"{step}: newest recorded score {newest:+d} but the plugin holds"
        f" {in_memory:+d}; the move is invisible in the trace")
    assert stage.status == "passed", (
        f"{step}: replay from events alone says {stage.status}: {stage.note}")


def test_a_late_payment_enfranchises_earlier_reports_consistently():
    """The exact sequence from review: report, then settle, then report."""
    engine = lifecycle_engine()

    TownAPI(engine, "alice").rate("seller", "bad")
    assert_three_views_agree(engine, "seller", 0, "alice reports unweighted")

    engine.layers["payments"].transfer("alice", "bob", 1, "one-cent")
    assert_three_views_agree(engine, "seller", -1, "alice settles one cent")

    TownAPI(engine, "bob").rate("seller", "good")
    assert_three_views_agree(engine, "seller", 0, "bob reports weighted")


def test_replay_agrees_after_a_late_payment():
    """The replay must not reconstruct a score the runtime never recorded."""
    engine = lifecycle_engine()
    TownAPI(engine, "alice").rate("seller", "bad")
    engine.layers["payments"].transfer("alice", "bob", 1, "one-cent")
    TownAPI(engine, "bob").rate("seller", "good")
    events = [event.model_copy(deep=True) for event in engine.events]
    stage = reputation_capped(Trace(events))
    assert stage.status == "passed", stage.note


def test_recorded_deltas_sum_to_the_recorded_score():
    """Every move of a score must be attributable to a recorded delta."""
    engine = lifecycle_engine()
    TownAPI(engine, "alice").rate("seller", "bad")
    engine.layers["payments"].transfer("alice", "bob", 1, "one-cent")
    TownAPI(engine, "bob").rate("seller", "good")

    per_pair: dict[tuple[str, str], int] = {}
    for event in recorded_reputation(engine):
        pair = (event.observer, event.subject)
        per_pair[pair] = per_pair.get(pair, 0) + event.detail["delta"]

    assert per_pair == {("alice", "seller"): -1, ("bob", "seller"): 1}
    assert sum(per_pair.values()) == engine.layers["trust"].score("seller")
    for pair, moved in per_pair.items():
        assert abs(moved) <= 1, f"{pair} moved {moved:+d}"


def enfranchised_trace():
    """A trace containing one enfranchisement, for tampering with."""
    engine = lifecycle_engine()
    TownAPI(engine, "alice").rate("seller", "bad")
    engine.layers["payments"].transfer("alice", "bob", 1, "one-cent")
    TownAPI(engine, "bob").rate("seller", "good")
    return [event.model_copy(deep=True) for event in engine.events]


def test_the_enfranchisement_is_recorded_with_its_transition():
    events = enfranchised_trace()
    reweights = [e for e in events if e.kind == "reputation_reweighted"]
    assert len(reweights) == 1
    event = reweights[0]
    assert event.observer == "alice" and event.subject == "seller"
    assert event.detail["observer_weight_before"] == 0
    assert event.detail["observer_weight_after"] == 1
    assert event.detail["score_before"] == 0
    assert event.detail["score"] == -1
    assert event.detail["delta"] == -1
    assert event.detail["reason"] == "observer_weight_gained"
    assert event.detail["formula"] == CAPPED
    # correlated to the payment that caused it
    payment = next(e for e in events if e.kind == "payment_settled")
    assert event.detail["payment"] == payment.event_id


@pytest.mark.parametrize("case,fragment", [
    ("dropped_reweight", "with no reputation_reweighted event"),
    # A second reweight is caught by the cap itself: alice moves -2.
    ("duplicated_reweight", "is capped at +/-1"),
    # Without the payment nothing enfranchised her, so the weight rule fires.
    ("reweight_without_payment", "has no settled trade of its own"),
    ("wrong_delta", "the capped formula gives"),
    ("wrong_score_before", "the capped formula gives"),
    ("wrong_score", "the capped formula gives"),
    ("backwards_weight", "0 to 1 weight transition"),
    ("reweight_of_an_unreported_subject", "was not owed"),
])
def test_capped_check_rejects_tampered_enfranchisements(case, fragment):
    """Each new check must be the only thing standing between these and a pass."""
    events = enfranchised_trace()
    reweight = next(e for e in events if e.kind == "reputation_reweighted")

    if case == "dropped_reweight":
        events.remove(reweight)
    elif case == "duplicated_reweight":
        events.insert(events.index(reweight) + 1,
                      reweight.model_copy(deep=True, update={"event_id": "ev-dup"}))
    elif case == "reweight_without_payment":
        events.remove(next(e for e in events if e.kind == "payment_settled"))
    elif case == "wrong_delta":
        reweight.detail["delta"] = 0
    elif case == "wrong_score_before":
        reweight.detail["score_before"] = -5
    elif case == "wrong_score":
        reweight.detail["score"] = 1
    elif case == "backwards_weight":
        reweight.detail.update(observer_weight_before=1,
                               observer_weight_after=0)
    elif case == "reweight_of_an_unreported_subject":
        # alice filed nothing about this subject, so none was owed.
        reweight.subject = "a-seller-alice-never-rated"

    stage = reputation_capped(Trace(events))
    assert stage.status == "failed", stage.note
    assert fragment in stage.note, stage.note


def test_an_observer_that_settles_before_reporting_needs_no_reweight():
    """No reports on file means nothing to re-weight, so no event is owed."""
    engine = lifecycle_engine()
    engine.layers["payments"].transfer("alice", "bob", 1, "one-cent")
    TownAPI(engine, "alice").rate("seller", "bad")
    events = [event.model_copy(deep=True) for event in engine.events]
    assert not [e for e in events if e.kind == "reputation_reweighted"]
    assert engine.layers["trust"].score("seller") == -1
    assert reputation_capped(Trace(events)).status == "passed"


def test_enfranchisement_still_respects_the_cap():
    """Retroactive weight must not let one observer exceed one point."""
    engine = lifecycle_engine()
    alice = TownAPI(engine, "alice")
    for _ in range(4):
        alice.rate("seller", "bad")
    engine.layers["payments"].transfer("alice", "bob", 1, "one-cent")
    assert engine.layers["trust"].score("seller") == -1
    events = [event.model_copy(deep=True) for event in engine.events]
    moved = sum(e.detail["delta"] for e in events
                if e.kind in REPUTATION_KINDS and e.observer == "alice")
    assert moved == -1, "four reports, enfranchised, still worth one point"
    assert reputation_capped(Trace(events)).status == "passed"


# -- event subscription -------------------------------------------------


def test_the_layer_subscribes_only_to_settled_payments():
    engine = lifecycle_engine()
    assert engine.layers["trust"].subscribes_to == ("payment_settled",)
    assert set(engine._subscribers) == {"payment_settled"}
    assert [name for name, _ in engine._subscribers["payment_settled"]] \
        == ["trust"]


@pytest.mark.parametrize("name", [
    "marketplace", "auction", "voting", "consensus", "supply_chain",
    "capability_spoofing", "capped_influence_uncapped_control",
])
def test_scenarios_without_the_capped_layer_subscribe_to_nothing(name):
    assert Engine(load_bundled(name))._subscribers == {}


def test_only_subscribed_kinds_reach_the_layer():
    """Every other event kind must not reach on_event at all."""
    engine = lifecycle_engine()
    seen = []
    engine.layers["trust"].on_event = seen.append
    engine._subscribers["payment_settled"] = [("trust", seen.append)]
    engine.emit("town", "card_registered", "alice", {})
    engine.emit("town", "receipt_attested", "alice", {})
    assert seen == []
    engine.layers["payments"].transfer("alice", "bob", 1, "one-cent")
    assert [event.kind for event in seen] == ["payment_settled"]


def test_a_layer_that_re_enters_its_own_kind_is_refused():
    """The no-loop rule is enforced, not just documented."""
    engine = lifecycle_engine()

    def loop(event):
        engine.emit("town", "payment_settled", "again",
                    {"from": "alice", "to": "bob", "cents": 1})

    engine._subscribers["payment_settled"] = [("trust", loop)]
    with pytest.raises(SubscriptionLoop, match="re-entered on"):
        engine.emit("town", "payment_settled", "first",
                    {"from": "alice", "to": "bob", "cents": 1})


def test_a_subscriber_may_still_emit_other_kinds():
    """Enfranchisement emits from inside a subscriber and must not trip."""
    engine = lifecycle_engine()
    TownAPI(engine, "alice").rate("seller", "bad")
    engine.layers["payments"].transfer("alice", "bob", 1, "one-cent")
    assert [e.kind for e in engine.events if e.kind == "reputation_reweighted"]
    assert engine._dispatching == set()


# -- review follow-ups on 9dc2113 ---------------------------------------


def test_an_enfranchised_slanderer_fails_honest_signal_survives():
    """A reweight moves a score, so the stage must read reweights too."""
    spec = load_bundled("capped_influence")
    engine = build_engine(spec)
    engine.schedule(10.0, lambda: engine.layers["payments"].transfer(
        "buyer-1", "slanderer", 1, "one-cent-to-slanderer"))
    engine.run()

    assert engine.layers["trust"].score("seller-honest") == 0
    reweights = [e for e in engine.events if e.kind == "reputation_reweighted"]
    assert [(e.observer, e.detail["score_before"], e.detail["score"])
            for e in reweights] == [("slanderer", 1, 0)]

    result = evaluate_scenario(spec, engine.run_id, engine.events)
    stages = {s.name: s.status for s in result.stages}
    assert stages["influence_capped"] == "passed", "the cap itself held"
    assert stages["honest_signal_survives"] == "failed"
    assert result.verdict == "failed"


def paid(engine, payer, payee, cents, memo):
    engine.layers["payments"].transfer(payer, payee, cents, memo)


def three_party_engine():
    spec = load_bundled("capped_influence")
    engine = Engine(spec)
    for who in ("alice", "bob", "carol", "seller"):
        engine.layers["identity"].create(who)
    engine.layers["payments"].open_account("alice", 10)
    engine.layers["payments"].open_account("bob", 10)
    engine.layers["payments"].open_account("carol", 0)
    return engine


@pytest.mark.parametrize("case", ["late_payment", "two_paid_raters"])
def test_a_missing_receipt_is_incomplete_evidence_not_a_broken_cap(case):
    """Absent attribution must not desynchronise the arithmetic beneath it."""
    engine = three_party_engine()
    if case == "late_payment":
        TownAPI(engine, "alice").rate("seller", "bad")
        paid(engine, "alice", "bob", 1, "c1")
        TownAPI(engine, "bob").rate("seller", "good")
    else:
        paid(engine, "alice", "carol", 1, "c2")
        paid(engine, "bob", "carol", 1, "c3")
        TownAPI(engine, "alice").rate("seller", "good")
        TownAPI(engine, "bob").rate("seller", "good")

    events = [event.model_copy(deep=True) for event in engine.events]
    assert reputation_capped(Trace(events)).status == "passed"
    events.remove(next(e for e in events if e.kind == "receipt_attested"
                       and e.observer == "alice"))
    assert reputation_capped(Trace(events)).status == "not_enough_evidence"


def test_a_real_arithmetic_error_survives_a_missing_receipt():
    """Incomplete evidence must not become cover for a genuine mismatch."""
    engine = three_party_engine()
    paid(engine, "alice", "carol", 1, "c2")
    paid(engine, "bob", "carol", 1, "c3")
    TownAPI(engine, "alice").rate("seller", "good")
    TownAPI(engine, "bob").rate("seller", "good")
    events = [event.model_copy(deep=True) for event in engine.events]
    events.remove(next(e for e in events if e.kind == "receipt_attested"
                       and e.observer == "alice"))
    last = [e for e in events if e.kind == "reputation_updated"][-1]
    last.detail["score"] = 99
    assert reputation_capped(Trace(events)).status == "failed"


def test_a_plugin_may_emit_from_its_own_constructor():
    """Dispatch state must exist before any layer is built."""
    from nandatown.layers import register

    @register("memory", "emits_on_init.v1")
    class EmitsOnInit:
        def __init__(self, engine):
            self.engine = engine
            engine.emit("town", "plugin_ready", "emits_on_init.v1", {})

        def remember(self, *args):
            pass

        def recall(self, *args):
            return None

    spec = load_bundled("capped_influence")
    spec.layers["memory"] = "emits_on_init.v1"
    engine = Engine(spec)
    assert [e.kind for e in engine.events] == ["plugin_ready"]
    # subscriptions are still wired afterwards
    assert set(engine._subscribers) == {"payment_settled"}
