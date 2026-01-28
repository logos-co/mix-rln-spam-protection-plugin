# Mix RLN Spam Protection Plugin

RLN-based spam protection plugin for libp2p mix networks. This plugin implements [Rate Limiting Nullifiers (RLN)](https://rate-limiting-nullifier.github.io/rln-docs/) to provide proof generation and verification primitives.

## Overview

This plugin provides:

- **RLN proof primitives**: `generateProof(bindingData)` and `verifyProof(proof, bindingData)` methods
- **Spam detection**: Detects double-signaling (sending more than allowed messages per epoch)
- **Offchain membership**: Membership managed via logos-messaging content topics (no blockchain required)
- **Pluggable architecture**: Implements nim-libp2p's `SpamProtection` interface for easy integration

## Architecture

```
┌─────────────────────────────────────────────────────────────────┐
│                    MixRlnSpamProtection                          │
├─────────────────────────────────────────────────────────────────┤
│  SpamProtection (nim-libp2p compatible)                         │
│    - generateProof(bindingData) → EncodedProofData              │
│    - verifyProof(proof, bindingData) → bool                     │
│    - proofSize() → 301 bytes (protobuf-encoded)                 │
├─────────────────────────────────────────────────────────────────┤
│  RLN Core (zerokit v0.9.0 FFI)                                  │
│    - Proof generation/verification (RLN-v2 format)              │
│    - Merkle tree operations                                      │
│    - Poseidon hash, secret recovery                              │
├─────────────────────────────────────────────────────────────────┤
│  OffchainGroupManager                                            │
│    - Membership tree (depth 20, ~1M members)                     │
│    - Credential management                                       │
│    - Root validation (window of 5 roots)                         │
├─────────────────────────────────────────────────────────────────┤
│  NullifierLog                                                    │
│    - Per-epoch nullifier tracking                                │
│    - Double-signaling detection                                  │
│    - Secret key recovery on spam                                 │
├─────────────────────────────────────────────────────────────────┤
│  Coordination Layer (via logos-messaging)                        │
│    - /mix/rln/membership/v1 → membership broadcasts              │
│    - /mix/rln/metadata/v1 → proof metadata broadcasts            │
└─────────────────────────────────────────────────────────────────┘
```

## Prerequisites

### Zerokit Library (librln)

This plugin requires the zerokit RLN library (v0.9.0) for proof generation and verification.

```bash
# Option 1: Build from source
git clone https://github.com/vacp2p/zerokit
cd zerokit
git checkout v0.9.0
cargo build --release -p rln
cp target/release/librln.a /path/to/your/project/

# Option 2: Download prebuilt
# https://github.com/vacp2p/zerokit/releases/tag/v0.9.0
```

## Installation

Add to your `.nimble` file:

```nim
requires "mix_rln_spam_protection >= 0.1.0"
```

### Dependencies

- [zerokit-rln](https://github.com/vacp2p/zerokit) v0.9.0 - RLN proving library (static linking)
- nim >= 2.0.0
- chronos, results, chronicles, nimcrypto

## Quick Start

```nim
import mix_rln_spam_protection

# Create configuration
var config = defaultConfig()
config.keystorePassword = "my-secure-password"

# Optionally customize content topics for your network
# config.membershipContentTopic = "/my-app/rln/membership/v1"
# config.proofMetadataContentTopic = "/my-app/rln/metadata/v1"

# Create plugin
let plugin = newMixRlnSpamProtection(config).valueOr:
  echo "Failed to create plugin: ", error
  return

# Initialize (loads/generates credentials)
await plugin.init()

# Set up coordination layer e.g via logos-messaging
plugin.setPublishCallback(proc(topic: string, data: seq[byte]) {.async.} =
  await logosMessaging.publish(topic, data)
)

# Subscribe to coordination topics (uses configured content topics)
let coordination = newCoordinationLayer(plugin)
for topic in coordination.getContentTopics():
  logosMessaging.subscribe(topic, proc(data: seq[byte]) {.async.} =
    discard await coordination.handleIncomingMessage(topic, data)
  )

# Start the plugin
await plugin.start()

# Register this node in the membership
let index = await plugin.registerSelf()
echo "Registered at index: ", index.get()

# Use with mix protocol
let mixProto = MixProtocol.new(
  mixNodeInfo,
  pubNodeInfo,
  switch,
  spamProtection = Opt.some(SpamProtection(plugin))
)
```

## Building

```bash
# Compile with static linking (requires librln.a)
nim c --passL:librln.a --passL:-lm src/mix_rln_spam_protection.nim

# Run tests
nim c -r --passL:librln.a --passL:-lm tests/test_all.nim
```

## Configuration

| Parameter                   | Default                        | Description                                          |
| --------------------------- | ------------------------------ | ---------------------------------------------------- |
| `rlnIdentifier`             | `"mix-rln-spam-protection/v1"` | Application identifier (must be same across network) |
| `epochDurationSeconds`      | `10.0`                         | Duration of each epoch                               |
| `maxEpochGap`               | `5`                            | Maximum epoch difference for valid proofs            |
| `userMessageLimit`          | `100`                          | Max messages per member per epoch                    |
| `keystorePath`              | `"rln_keystore.json"`          | Path to credentials file                             |
| `keystorePassword`          | `""`                           | Password for keystore (empty = no persistence)       |
| `treePath`                  | `"rln_tree.db"`                | Path for Merkle tree persistence                     |
| `membershipContentTopic`    | `"/mix/rln/membership/v1"`     | Content topic for membership broadcasts              |
| `proofMetadataContentTopic` | `"/mix/rln/metadata/v1"`       | Content topic for proof metadata broadcasts          |

## Content Topics

The plugin uses two configurable content topics for coordination. You can customize these during initialization to use different topics for your network:

```nim
var config = defaultConfig()
config.membershipContentTopic = "/my-app/rln/membership/v1"
config.proofMetadataContentTopic = "/my-app/rln/metadata/v1"
```

### Membership Updates (default: `/mix/rln/membership/v1`)

Broadcasts when members join or leave:

```
┌─────────────┬────────────────┬─────────────┐
│ action (1B) │ commitment(32B)│ index (8B)  │
└─────────────┴────────────────┴─────────────┘
```

### Proof Metadata (default: `/mix/rln/metadata/v1`)

Broadcasts proof metadata for network-wide spam detection:

```
┌───────────────┬──────────────┬──────────────┬─────────────────────┬────────────┐
│ nullifier(32B)│ shareX (32B) │ shareY (32B) │ extNullifier (32B)  │ epoch(32B) │
└───────────────┴──────────────┴──────────────┴─────────────────────┴────────────┘
```

## Spam Detection

When a member sends more than `userMessageLimit` messages in an epoch:

1. The nullifier log detects different Shamir shares for the same nullifier
2. The member's secret key is recovered and logged
3. The member is removed from the local tree
4. A removal broadcast is sent to all nodes

```nim
# Set custom spam handler
plugin.setSpamHandler(proc(proof: RateLimitProof, secret: IDSecretHash, index: MembershipIndex) {.async.} =
  echo "Spam detected! Secret: ", secret.toHex()
  echo "Member index: ", index
  # Custom handling...
)
```

## Tree Bootstrap

For new nodes joining the network:

```nim
# Save current tree state
plugin.saveTree()

# Load tree from file (on another node)
plugin.loadTree()

# Or use the group manager directly for binary snapshots
let snapshot = plugin.groupManager.serializeTreeSnapshot()
writeFile("tree_snapshot.bin", snapshot)

# Load on another node
let data = readFile("tree_snapshot.bin")
plugin.groupManager.loadTreeSnapshot(cast[seq[byte]](data))
```

## Testing

Run following command to execute all tests

```bash
# Run tests (requires librln.a)
nim c -r --passL:/path/to/librln.a --passL:-lm tests/test_all.nim

```

## References

- [RLN Spam Protection for Mix Networks RFC](https://github.com/vacp2p/rfc-index/pull/252)
- [nim-libp2p Spam Protection Interface](https://github.com/vacp2p/nim-libp2p/pull/2037)
- [RLN Documentation](https://rate-limiting-nullifier.github.io/rln-docs/)
- [Zerokit](https://github.com/vacp2p/zerokit) (v0.9.0)
- [logos-messaging-nim](https://github.com/logos-messaging/logos-messaging-nim)

## License

Licensed under either of:

- Apache License, Version 2.0
- MIT license
