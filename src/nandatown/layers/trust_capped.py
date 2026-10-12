"""Trust layer: reputation with a per-observer influence cap.

The formula, over the reports and weights held at the time of the read:

    score(subject) = sum over distinct observers of
                     weight(observer) * clamp(net(observer, subject), -1, +1)

    net    = goods minus bads that observer reported about subject
    weight = 1 if a settled payment has named the observer, else 0

One observer moves a score by at most 1 however many receipts it files,
an observer with no settled trade of its own moves nothing, and distinct
observers still accumulate.

Eligibility is evaluated at current state, not at report time. A settled
payment therefore retroactively enfranchises that observer's earlier
reports: reports filed while unweighted begin to count the moment the
observer first settles a payment. That moment is recorded as a
reputation_reweighted event, one per subject the observer had already
reported on, carrying the weight transition and the score either side of
it, so a replay reconstructs the same score from the trace alone and
every move of a score is attributable to a recorded delta.

The trade-off: a late payment changes what a past report contributes.
Report-time eligibility would freeze weight when the report is filed and
be cheaper to verify, needing no transition events at all, but it would
let an agent file its reports before paying and never earn the weight
those reports needed.

Judged by the reputation_capped validator, not reputation_consistent,
which replays the unbounded sum.
"""

from __future__ import annotations

from . import register


def clamp(value: int, low: int = -1, high: int = 1) -> int:
    return max(low, min(high, value))


@register("trust", "reputation.capped.v1")
class CappedReputation:
    """Reputation capped at +/-1 per observer, zero without trade history."""

    subscribes_to = ("payment_settled",)

    def __init__(self, engine):
        self.engine = engine
        # observer -> subject -> net goods minus bads, unclamped
        self.reports: dict[str, dict[str, int]] = {}
        # observer -> 1 once a settled payment has named it
        self.weights: dict[str, int] = {}

    def weight(self, observer: str) -> int:
        return self.weights.get(observer, 0)

    def score(self, name: str) -> int:
        """Pure over the reports and weights held now; reads no events."""
        total = 0
        for observer, subjects in self.reports.items():
            if name in subjects:
                total += self.weight(observer) * clamp(subjects[name])
        return total

    def on_event(self, event) -> None:
        """Enfranchise an observer the first time a payment names it.

        Reports already on file from that observer start counting here, not
        lazily at the next read, so the score change lands in the trace at
        the moment that caused it.
        """
        if event.kind != "payment_settled":
            return
        detail = event.detail if isinstance(event.detail, dict) else {}
        for side in ("from", "to"):
            party = detail.get(side)
            if (not isinstance(party, str) or not party
                    or self.weight(party) == 1):
                continue
            self.weights[party] = 1
            for subject in sorted(self.reports.get(party, {})):
                delta = clamp(self.reports[party][subject])
                after = self.score(subject)
                self.engine.emit(
                    party, "reputation_reweighted", subject,
                    {"delta": delta, "score": after,
                     "score_before": after - delta,
                     "observer_weight_before": 0,
                     "observer_weight_after": 1,
                     "observer_net": delta,
                     "formula": "reputation.capped.v1",
                     "reason": "observer_weight_gained",
                     "payment": event.event_id})

    def update(self, observer: str, subject: str, outcome: str,
               receipt_id: str) -> int:
        before = self.score(subject)
        net = self.reports.setdefault(observer, {})
        net[subject] = net.get(subject, 0) + (1 if outcome == "good" else -1)
        after = self.score(subject)

        weight = self.weight(observer)
        if weight == 0:
            reason = "observer_has_no_settled_trade"
        elif after == before:
            reason = "observer_cap_reached"
        else:
            reason = "counted"

        # A discarded report is still recorded, with delta 0 and a reason.
        self.engine.emit(observer, "reputation_updated", subject,
                         {"outcome": outcome, "delta": after - before,
                          "score": after, "receipt": receipt_id,
                          "formula": "reputation.capped.v1",
                          "observer_weight": weight,
                          "observer_net": clamp(net[subject]),
                          "reason": reason})
        return after
