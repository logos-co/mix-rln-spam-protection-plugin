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

A successful validation schedules a best-effort `ProofMetadataBroadcast` through
the supplied publish callback and returns without waiting for publication.
At most 64 broadcasts may be pending; excess broadcasts are dropped and counted.
Shutdown cancels and waits for pending broadcasts. Publication errors do not
reject an otherwise valid packet; local duplicate detection remains active. Incoming coordination frames enter through
`handleProofMetadata`. The deployment must protect this coordination channel;
Logos Mixnet requires RLN-protected Relay. Registry membership synchronization
belongs to the backend, so this mode does not gossip membership announcements.

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

- `mix_rln_metadata_publication_failures`: failed/dropped broadcasts, labelled
  `reason=publish|capacity|cancelled`.
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

The existing 80-second generation timeout is a failure deadline, not a latency
measurement. Keep it until representative module measurements justify changing
it. Canned-response tests verify instrumentation, not real proof performance.

Per-packet coordination still consumes Relay quota and reveals reception timing.
Provision Relay quota for incoming verified traffic plus normal Relay activity.
Batching is a follow-up: it reduces publication volume and timing correlation,
but delays network-wide reuse detection and can still reveal batch size/timing.
