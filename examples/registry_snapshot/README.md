# Registry snapshot profile: claims checked against a record that outlives the run

A signature proves that a key signed. It cannot tell you whether that key still speaks for the identity it claims. If an external registry moved control of an identity from key K1 to key K2, K1 still produces perfect signatures. Only the registry's record knows that its authority lapsed.

This profile adds that check to the Lab. A card may carry a **registry claim**: a statement that an identity's controller key signed once, outside any run, naming the town agent that speaks for it. When the card is published, the registry layer checks the claim against a **pinned snapshot of the external registry**. The snapshot holds each identity's current controller and every transaction that moved it. A key the record has since moved away from is refused as a former controller, before anyone talks to it.

The core is neutral: a `registry-snapshot/v1` format, a claim statement and a policy. Vector's agent registry is the first source, under `adapters/vector/`.

## The three runs

```
nandatown run examples/registry_snapshot/scenarios/rotation_mock.yaml
nandatown run examples/registry_snapshot/scenarios/rotation_mock_sigonly_control.yaml
nandatown compare examples/registry_snapshot/scenarios/rotation_mock.yaml --swap registry=snapshot.mock.sigonly.v1
nandatown run examples/registry_snapshot/scenarios/rotation_vector_mainnet.yaml
```

Two providers claim the same identity. The snapshot records that control moved from K1 to K2. The K1 provider prices below K2 and delivers honestly, so a buyer that cannot see the transfer has every reason to pick it.

| Run | Verdict | What happens |
|---|---|---|
| `rotation_mock` | passed | K2's claim resolves to the recorded controller and its card is listed. K1's claim signature is valid and its card is refused on the record, before any traffic. The buyer trades with K2. |
| `rotation_mock_sigonly_control` | failed on purpose | Same agents and seed. The registry still checks every claim signature but does not compare the record. K1 is listed, picked and paid. |
| `compare --swap registry=snapshot.mock.sigonly.v1` | baseline passed, swapped failed | Three stages fail for a reason: `former_controller_refused`, `former_controller_contained` and `current_controller_paid`. `current_controller_verified` is reported `not_tested`, because a control that never compares records cannot verify one. |
| `rotation_vector_mainnet` | passed | The same check against a snapshot captured from Vector mainnet. The claims were signed by the real controller keys. It runs offline and needs no key, so anyone can rerun it. |

The control is the precise one: every signature in it is valid and checked, the town's and the claim's. The only thing missing is the record. That isolates the claim this profile makes: a valid signature under the presented key cannot see a transfer.

## Situations and outcomes

| Situation | Outcome | Event |
|---|---|---|
| Current controller's claim | resolved, card listed | `registry_claim_resolved` |
| Former controller, valid claim signature | refused before any traffic; its own messages are refused too | `registry_claim_refused` reason `controller_mismatch` with `rotation_tx`; `registry_sender_unbound` |
| A key that never controlled the identity | refused, no rotation named | `controller_mismatch`, `rotation_tx: null` |
| Controller's public key presented with another key's signature | refused | `claim_signature_invalid` |
| A claim signed for another agent name | refused | `claim_signature_invalid` |
| A claim the agent was not configured with, even one the controller signed | refused | `claim_not_configured_for_agent` |
| Unknown identity / retired identity | refused | `identity_unknown` / `identity_retired` |
| Snapshot missing, edited (fingerprint not pinned) or inconsistent with its own history | every claim refused as unavailable; the run is `incomplete`, never passed or failed | `registry_snapshot_unavailable`, reason `snapshot_unavailable` |
| A card-shaped message body from any agent | judged as a message under the sender's own key; nothing changes for any other agent | none |
| Another agent republishes a listing under someone else's name, with its own valid claim | refused; the listing stays (#303's invariant) | `controller_mismatch`, publisher recorded |

## How it is wired

- **identity `claims.v1`.** Each agent gets a seeded Ed25519 town key for the run. An agent whose config has a `claim` puts it on its card as `facts.registry_claim`. No controller key, mock or real, ever enters a run.
- **auth `ed25519.v1`.** Every call is judged the same way, whatever the payload looks like: the signature must verify under the town key of the name it claims. A name whose own claim the registry refused is unbound and cannot deliver anything.
- **registry `snapshot.<source>.v1`.** This extends `index.owned.v1`. At publish it checks, in order:
  1. the claim is the one configured for that agent;
  2. the snapshot is available;
  3. the claim statement verifies under the presented controller key;
  4. the identity exists and is active;
  5. blake2b-224 of the controller key equals the recorded controller.

  Only an agent's own failed claim unbinds it. Then `index.owned.v1` applies, so only a name's own town key changes its listing. The `.sigonly` controls run the same checks except step 5's record comparison.
- **The claim statement**, signed by the controller key: `{"statement": "registry-claim/v1", "agent": <name>, "identity": <id>, "registry": <registry id>}`, as canonical JSON. `sign_claim.py` makes one.

## The snapshot

`registry-snapshot/v1` is a JSON file. It holds:
- the source and network;
- the registry id;
- the key-hash function;
- the chain tip at capture;
- for each identity, its status, current controller, registry output reference and full history (`registered`, `controller_rotated`, `updated`, `retired`, each with transaction, slot and block height).

Before a snapshot loads, three checks run:
- its fingerprint must equal the one pinned in `registry_snapshot.py`;
- every identity's history must replay to exactly its recorded status and controller;
- every history slot must be at or before the tip.

A snapshot that fails any check is unavailable: an edited snapshot is never trusted.

The run records the whole snapshot in its `registry_snapshot_loaded` event, together with the validator version and the profile's sha256. Each claim event records the claim, the presented key and its hash, the signature and the card's fingerprint.

## The validator recomputes, it does not trust

`registry_rotation` (version `registry-rotation-0.1`) judges each stage from `events.jsonl` alone. Wherever a decision depends on cryptography or on the record, it recomputes the decision rather than reading the plugin's flags. Every stage is per agent.

- **`snapshot_loaded`:** a loaded snapshot, by this validator version, whose recorded identities replay consistently.
  - No snapshot, or a different validator version: every stage is `not_enough_evidence`, and the run is `incomplete`.
- **`former_controller_refused`:** for every former controller, a `controller_mismatch` refusal before its first traffic, in either direction. The refusal must survive two recomputations:
  - the recorded claim signature verifies, and the recorded hash is the hash of the recorded key;
  - in the recorded history, that key once controlled the identity and was rotated away.

  No former controller in the scenario: `not_enough_evidence`.
- **`former_controller_contained`:** for every former controller, no message sent to it, none accepted from it, no escrow release and no settlement. The counts are in the note.
- **`current_controller_verified`:** for every claiming seller, one recomputable resolution to the recorded controller, then a verified card, and no resolution with any other key. Under a `.sigonly` control this stage is `not_tested`.
- **`current_controller_paid`:** an escrow release to the current controller for an order sent after its claim resolved, correlated by order id.

The standing `ledger_conserved` and `privacy_clean` checks also run.

## Verifying a bundle

`python examples/registry_snapshot/verify_bundle.py <bundle>` reads the validator version and profile sha256 the bundle recorded. It refuses to replay if this checkout differs, so a later change to the rules cannot pass for a good bundle. Only then does it import the profile and run the stock `nandatown verify`.

**Stock `nandatown verify` on these bundles prints "evaluator replay mismatch".** It replays only the validators it already knows, and it rightly never imports plugin files named inside a bundle. Here that message means the out-of-tree validator was not loaded, not that the bundle was tampered with.

Bundles also record the absolute path of `registry_snapshot.py` in `profile.json`. That's how scenario `plugin_files` are resolved upstream. Check before sharing a bundle.

## The Vector adapter

- **`adapters/vector/capture.py --did <did>`** reads Vector's public Koios API and writes `snapshots/vector-mainnet.json`.
  - History is read in chain order (block height, then position in the block) and paginated.
  - Each owner credential is checked to be a key hash, and the token is checked to stay at the registry script.
  - The tip is read after the histories.
  - The network is identified by genesis (system start, network magic, security parameter).
  - It records each identity's depth against that security parameter, and refuses to overwrite the pinned file without `--force`.
- **`adapters/vector/make_scenario.py`** has the operator sign the two claims with the controller keys, once, off-chain, and writes `scenarios/rotation_vector_mainnet.yaml`. Ed25519 is deterministic, so the same keys reproduce the same file.

**Mainnet provenance.** All of it can be re-checked on Vector Koios (`tx_info`, `asset_utxos`).

| Field | Value |
|---|---|
| Registry (policy) | `be1a0a2912da180757ed3cd61b56bb8eab0188c19dc3c0e3912d2c01` |
| Identity | `did:vector:agent:be1a0a29…2c01:acd896b4ed9ed81392f158c245ad322cdea7dcae89b317a61e1e655648832bc2` (`vector-rotation-demo`) |
| Registered under K1 | tx `80ddea05080a48630246161c80456b1db0eaa27ac3b4a776048440c91321b682`, block 9073354, slot 36793345, controller `94e919ef…` |
| Rotated K1 → K2 | tx `91b9f8878ffab2d693e77383c41e2ee1a5af926e835dfb16f3ffa198027296e5`, block 9073392, slot 36793554, controller `08bd66d2…` |
| Tip at capture | block 9074394, slot 36797507; the rotation was 1002 blocks deep, against security parameter k = 2160 |
| Snapshot fingerprint | `sha256:695ed8e3cbe66a4c749bdf3819cb541fbac49a372743b0c2e8ca72b4b33ec2ac` |
| Mock fingerprint | `sha256:77ab614f48fdc852c568e5c1c825c76f1dba7ef4c5a37359d6913ed4bdcb6a4e` |

**Disclosure.** The identity was minted for this demonstration on 2026-10-29, and both claimants are operated by Apex Fusion. It is a first-party fixture, not independent adoption. No run calls a chain.

## Tests

`pytest tests/test_registry_snapshot_profile.py` has 54 tests:
- the three runs and the compare;
- the mainnet claims against the recorded history;
- the wrapper verifying, and refusing a changed profile;
- stock verify's mismatch;
- the drop-in sweep: `claims.v1` and `ed25519.v1` swapped into all 11 bundled scenarios keep their verdicts, except `capability_spoofing_weak_auth`, whose point is the `plain.v1` the swap replaces;
- each refusal reason;
- snapshot edits and inconsistencies;
- the #303 listing invariant;
- the card-shaped-body regressions;
- one hand-built trace per validator rule;
- mock data reproducing byte for byte.

**Mutation check.** 20 deliberate weakenings of the validator, registry and auth were each applied alone; 19 fail at least one test. The survivor drops the check that a refusal belongs to the agent being judged. It is equivalent, because the recomputed claim signature already binds the agent's name.

## What this shows, and what it does not

It shows three things:
- a check against a registry record that outlives the run refuses a key the record moved away from, even when every signature is valid;
- the refusal comes before any traffic or money;
- the same run without the record comparison pays that key.

It does not show any of these:
- **Trustworthiness.** It doesn't show that a resolved identity is trustworthy: a signature shows that a key committed, not that a claim is true.
- **A chain refusing anything.** The refusal is this plugin's decision over a pinned copy of the record.
- **DID-pinned buying.** The buyer trades with any listed seller; it does not seek a particular identity.
- **Third-party revocation.** Vector retirement is initiated by the owner.
- **Finality.** Nothing beyond the depth recorded at capture.
- **Independent adoption.** This is a first-party fixture.
- **Generality.** One seeded run is one observation.

## Next

- Bind claims to deployed NANDA Index records instead of a profile-local snapshot.
- `verify --plugin`, as a separate core proposal with its own trust discussion.
- Mutual verification, where the provider checks the buyer's claim.
- Retirement as a scenario.
- A buyer that seeks one identity.
