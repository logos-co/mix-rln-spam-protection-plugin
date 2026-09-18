# Shared RLN backend adapter

`mix_rln_spam_protection/module_api` implements core Mix's asynchronous
`SpamProtection` interface using a caller-supplied `RlnModuleCall`. It does
not open a zerokit context, hold credentials, or allocate membership indices.
The shared backend owns these operations and durable message-id allocation.

Configure the same `registryId`, 32-byte `rlnIdentifierHex`, epoch duration,
accepted epoch gap, and metadata topic on every participant. The Logos Mixnet
profile uses 10-second epochs, gap 3, and message limit 100. The host starts
the backend with matching registry parameters before starting this adapter.
Mix and Relay RLN use separate scopes.

The callback receives a method name and an ordered JSON argument array.
`generate_proof` and `validate_proof` are scoped by the registry and application
identifier. They bind the proof to the exact serialized Sphinx packet for
that hop. No proof request blocks the Nim event loop.

The adapter preserves Mix's 301-byte protobuf proof representation. Because
that representation omits `external_nullifier`, verification asks the backend
to reconstruct it from the scope and epoch. The backend must support this
form and return the derived field with its verdict. A wrong scope, signal,
malformed proof, failed request, or missing field fails closed.

A successful validation publishes a `ProofMetadataBroadcast` through the
supplied publish callback. Incoming coordination frames enter through
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
