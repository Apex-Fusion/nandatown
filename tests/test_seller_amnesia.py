"""crash_amnesia: the seller answers, loses its journal and dies before
acknowledging. Its restart applies the work again; only the town's
message identity keeps that from becoming a second response."""

import os
import time

import httpx

from nandatown.bundle import verify_bundle
from nandatown.evaluator import evaluate
from nandatown.runner import run_town

from test_evaluator import ev, profile, stage


def test_forgotten_work_is_not_answered_twice(tmp_path):
    bundle_dir, result = run_town("quote-amnesia-restart", str(tmp_path))
    detail = [(s.name, s.status, s.note) for s in result.stages]
    assert stage(result, "amnesia_survived").status == "passed", detail
    assert result.verdict == "passed", detail
    assert verify_bundle(bundle_dir) == []
    # The seller recomputed the forgotten work, so the report must not
    # claim one application; what is proved is one accepted response.
    with open(os.path.join(bundle_dir, "report.md"), encoding="utf-8") as f:
        report = f.read()
    assert "applied the task exactly once" not in report
    assert "one accepted response" in report


def test_fresh_response_ids_answer_twice(tmp_path):
    # Negative control: same fault, response identity minted per
    # application. It must fail, and fail on the second response.
    bundle_dir, result = run_town("quote-amnesia-fresh-ids", str(tmp_path))
    detail = [(s.name, s.status, s.note) for s in result.stages]
    assert result.verdict == "failed", detail
    assert stage(result, "response").status == "failed", detail
    assert "2 distinct quote responses" in stage(result, "response").note
    assert stage(result, "amnesia_survived").status == "failed", detail
    assert verify_bundle(bundle_dir) == []


def test_slow_restart_record_still_precedes_the_new_seller(tmp_path,
                                                          monkeypatch):
    # The restart is recorded before the new seller starts, so a slow
    # admin post cannot let it reclaim and replay ahead of that record.
    post = httpx.Client.post

    def slow_restart_post(self, url, *args, **kwargs):
        if (kwargs.get("json") or {}).get("kind") == "participant_restarted":
            time.sleep(3)
        return post(self, url, *args, **kwargs)

    monkeypatch.setattr(httpx.Client, "post", slow_restart_post)
    bundle_dir, result = run_town("quote-amnesia-restart", str(tmp_path))
    detail = [(s.name, s.status, s.note) for s in result.stages]
    assert stage(result, "amnesia_survived").status == "passed", detail
    assert result.verdict == "passed", detail


def amnesia_events(pre_crash_replay, post_claim_replay):
    events = [
        ev(1, "message_accepted", "q-1", kind="quote_request",
           sender="buyer", to="seller"),
        ev(2, "message_claimed", "q-1", claimant="seller", attempt=1),
        ev(3, "message_accepted", "r-1", kind="quote_response",
           sender="seller", to="buyer", request_id="q-1"),
    ]
    if pre_crash_replay:
        events.append(ev(4, "replay_returned", "r-1", sender="seller"))
    events += [
        ev(5, "participant_crashed", "seller", observer="runner"),
        ev(6, "participant_restarted", "seller", observer="runner"),
        ev(7, "message_claimed", "q-1", claimant="seller", attempt=2),
    ]
    if post_claim_replay:
        events.append(ev(8, "replay_returned", "r-1", sender="seller"))
    return events


def test_replay_after_redelivery_proves_amnesia_survived():
    result = evaluate(profile("crash_amnesia"), "run-1",
                      amnesia_events(False, True))
    s = stage(result, "amnesia_survived")
    assert s.status == "passed"
    assert s.evidence == ["ev-3", "ev-5", "ev-6", "ev-7", "ev-8"]


def test_pre_crash_replay_does_not_prove_amnesia_survived():
    # A seller that sent its first answer twice, crashed, and after the
    # restart only acknowledged the redelivery never answered again.
    result = evaluate(profile("crash_amnesia"), "run-1",
                      amnesia_events(True, False))
    assert stage(result, "amnesia_survived").status == "not_enough_evidence"


def test_crash_before_any_response_does_not_prove_amnesia_survived():
    # The seller crashed before answering, so there was no accepted
    # response to forget. Its restart answering, then sending that answer
    # again, is a duplicate send, not a survived amnesia.
    events = [
        ev(1, "message_accepted", "q-1", kind="quote_request",
           sender="buyer", to="seller"),
        ev(2, "message_claimed", "q-1", claimant="seller", attempt=1),
        ev(3, "participant_crashed", "seller", observer="runner"),
        ev(4, "participant_restarted", "seller", observer="runner"),
        ev(5, "message_claimed", "q-1", claimant="seller", attempt=2),
        ev(6, "message_accepted", "r-1", kind="quote_response",
           sender="seller", to="buyer", request_id="q-1"),
        ev(7, "replay_returned", "r-1", sender="seller"),
    ]
    result = evaluate(profile("crash_amnesia"), "run-1", events)
    assert stage(result, "amnesia_survived").status == "not_enough_evidence"
