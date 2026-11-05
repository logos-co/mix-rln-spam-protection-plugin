# Shared RLN backend adapter

`mix_rln_spam_protection/module_api` implements core Mix's asynchronous
`SpamProtection` interface using a caller-supplied `RlnModuleCall`. It does
not open a zerokit context, hold credentials, or allocate membership indices.
The shared backend owns these operations and durable message-id allocation.

Configure the same `registryId`, 32-byte `rlnIdentifierHex`, epoch duration,
accepted epoch gap, and metadata topic on every participant. The Logos Mixnet
profile uses 10-second epochs, gap 3, and message limit 100. The host starts
the backend with matching registry parameters before starting this adapter.
Mix and Relay RLN use separate scopes. Startup requires `get_registry_parameters`
to return integer `epoch_size_sec` and `max_epoch_gap` matching the adapter.
Older backends without `max_epoch_gap` must be upgraded before using this adapter.
`messageLimit` has been removed from `ModuleRlnConfig`; quota belongs to the
backend membership. Hosts must remove that field from adapter construction.

The callback receives a method name and an ordered JSON argument array.
`generate_proof` and `validate_proof` are scoped by the registry and application
identifier. They bind the proof to the exact serialized Sphinx packet for
that hop. No proof request blocks the Nim event loop.

The adapter preserves Mix's 301-byte protobuf proof representation. Because
that representation omits `external_nullifier`, verification asks the backend
to reconstruct it from the scope and epoch. The backend must support this
form and return the derived field with its verdict. A wrong scope, signal,
malformed proof, failed request, or missing field fails closed.

A successful validation appends one entry to the current batch and returns.
The batch publishes when it reaches `maxMetadataBatchEntries` or the Mix
epoch changes, whichever comes first, then clears. Zero means 500. One entry
is about 173 bytes, and 500 stays under Waku's 150 KiB default. A host whose
relay limit differs sets the entry count to match. An empty epoch publishes
nothing. `disableMetadataBatch` defaults to false, so a host
that leaves the field unset keeps batching. Setting it publishes each verified
proof immediately as a one-entry `MessagingMetadata`. Shutdown publishes
whatever is still buffered, waits up to `publishStopTimeoutMs` for in-flight
publishes, and cancels what is still running. Zero means 2 seconds.
Publication errors do not reject an otherwise valid packet; local duplicate
detection remains active. `handleProofMetadata` accepts a `MessagingMetadata` of
`ProofMetadataBroadcast` entries. It checks `maxEpochGap` per entry. A
malformed entry is counted and skipped, and the rest of the payload is still
applied. A bare single entry is rejected. The deployment must protect this
coordination channel; Logos Mixnet requires RLN-protected Relay. Registry membership
synchronization belongs to the backend, so this mode does not gossip membership
announcements.

Cover precomputation prepares Sphinx packets without spending backend quota.
A proof is generated when a cover packet is sent. A spent backend allocation
is never reclaimed or reused, including after cancellation or a failed send.

`module_transport` supplies the standalone FFI's request correlation: at most
64 pending requests, bounded waits, first response wins, and rejection of
late responses. `cancel()` wakes pending callers during shutdown. Native
Delivery uses its existing C callback transport for the same API.

The legacy embedded provider remains available during migration. Its zerokit
version and nullifier construction differ from the shared backend; the two
modes must not be mixed in one routing network.

Adapter/transport tests use canned backend responses to exercise the boundary.
Real proof reconstruction and wrong-scope/signal rejection are tested in the
shared RLN backend. Full Delivery/standalone interoperability is tracked in the
Logos Mix module's `WORK_SUMMARY.md`.

## Metrics and latency measurements

Build the host with `-d:metrics` and expose its metrics registry:

- `mix_rln_metadata_publication_failures`: failed batch publishes, labelled
  `reason=publish|cancelled`.
- `mix_rln_metadata_batch_entries`: histogram of how many entries a published
  batch carried.
- `mix_rln_metadata_entries_skipped`: entries not applied, labelled
  `reason=malformed|epoch_gap`.
- `mix_rln_metadata_conflicts_total`: received entries whose nullifier was
  already in the local log with different shares.
- `mix_rln_module_request_limit_rejections`: requests rejected by the standalone
  transport's shared 64-request cap. Delivery's separate transport is not covered.
- `mix_rln_module_proof_seconds`: histogram labelled
  `operation=generate_proof|validate_proof` and `outcome=success|error|cancelled`.
  Uses a monotonic clock around the module call and response parsing, including
  transport, backend queueing, and cold-path work. A successful call can still
  return an invalid-proof verdict; this metric does not measure packet acceptance.

Measure real module calls on the target hardware with real memberships and
protected coordination. Record cold-start calls separately, then collect warm
p50/p95/p99 generation and verification latency at idle and at expected incoming
traffic rates, including cover and simultaneous Relay activity. Include request
rejections and error/cancellation counts; successful-call latency alone can hide
overload. Compare generation latency with the configured Mix delay distribution
and the 10-second epoch, and record CPU, concurrency, sample count, and backend
revision with the results. For example, warm successful generation p95:

```promql
histogram_quantile(0.95, sum by (le) (
  rate(mix_rln_module_proof_seconds_bucket{
    operation="generate_proof",outcome="success"
  }[5m])
))
```

Proof validation has a 10-second failure deadline. Proof generation and
registry-backed membership state, parameter, and registration calls have a
100-second deadline because the backend may use a 90-second budget. Canned-response
tests verify instrumentation, not real proof performance.

Each Mix epoch that verified at least one proof publishes one Relay message.
Other nodes learn a nullifier up to one epoch later. The local log still
catches a double-signal this node sees itself, at once. A batch of 100 entries
is about 17 KB.
