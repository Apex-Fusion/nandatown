"""Vector adapter: registry plugins for the captured Vector mainnet snapshot.

    registry  snapshot.vector-mainnet.v1          vector-mainnet.json, pinned
              snapshot.vector-mainnet.sigonly.v1  control: claim signatures
                                                  checked, the record not

Load after registry_snapshot.py (list both in a scenario's plugin_files, the
core first). The core stays free of any source; this file adds one by
subclassing its SnapshotIndex with a source, a pinned fingerprint and a
snapshot path. capture.py writes the snapshot and prints its fingerprint.
"""

from __future__ import annotations

from pathlib import Path

from nandatown.layers import register, resolve

HERE = Path(__file__).resolve().parent
PIN = "sha256:03433d350be8a4f9ca2ea2a1b84e260380af7c5c86ef3bb31eed5100710d493d"


def _snapshot_index():
    core = resolve("registry", "snapshot.mock.v1")
    return next(c for c in core.__mro__ if c.__name__ == "SnapshotIndex")


@register("registry", "snapshot.vector-mainnet.v1")
class VectorMainnetIndex(_snapshot_index()):
    """Registry claims checked against the captured Vector mainnet snapshot."""
    source = "vector-mainnet"
    pinned = PIN
    snapshot_path = HERE / "vector-mainnet.json"
    defined_in = __file__


@register("registry", "snapshot.vector-mainnet.sigonly.v1")
class VectorMainnetSigOnlyIndex(VectorMainnetIndex):
    """Control: claim signatures checked, the Vector mainnet record not."""
    compare_records = False
