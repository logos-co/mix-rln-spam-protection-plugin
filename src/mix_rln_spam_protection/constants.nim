# Mix RLN Spam Protection Plugin
# Copyright (c) 2025 vacp2p
# Licensed under either of Apache License 2.0 or MIT license.

## Constants for the RLN spam protection plugin.

import std/math

const
  # Merkle tree configuration
  MerkleTreeDepth* = 20
    ## Depth of the Merkle tree for membership. Supports 2^20 (~1M) members.

  MerkleTreeCapacity* = 1'u64 shl MerkleTreeDepth
    ## Number of leaves the Merkle tree can hold. Valid indices are 0 ..< this.

  # Cryptographic sizes
  HashByteSize* = 32 ## Size of hash outputs (Poseidon, Keccak256) in bytes.

  ZksnarkProofByteSize* = 128 ## Size of compressed zkSNARK proof in bytes.

  RateLimitProofByteSize* = 301
    ## Total size of protobuf-encoded RateLimitProof.
    ## Raw data: proof(128) + root(32) + epoch(32) + shareX(32) + shareY(32) + nullifier(32) = 288 bytes
    ## Protobuf overhead: 6 field tags (6 bytes) + length prefixes (1 byte for 32B fields, 2 bytes for 128B field) = 13 bytes
    ## Total: 288 + 13 = 301 bytes
    ## Note: rlnIdentifier is NOT included as it's a network-wide constant

  # Rate limiting parameters
  EpochDurationSeconds* = 10.0
    ## Duration of each epoch in seconds. Nodes can send up to
    ## their stake-derived userMessageLimit messages per epoch.

  MaxEpochGap* = 3
    ## Maximum allowed epoch gap between message epoch and current epoch.
    ## Messages outside this window are rejected.
    ##
    ## Derived as ceil((S + A + D) / EpochDurationSeconds), where S is the max
    ## clock skew between minter and verifier (20 s assumed, 2 epochs), A is
    ## the proof age at emission (1 epoch: precomputed cover packets sit queued
    ## up to a full epoch before the boundary purge), and D is path latency
    ## (proof generation plus upstream forwarding delays; sub-second at the
    ## default mean per-hop delay, absorbed in the skew slack). Revisit if the
    ## epoch duration shrinks or per-hop delays grow to a meaningful fraction
    ## of an epoch. Each accepted epoch carries a full per-node rate-limit
    ## allowance, so the window multiplies burst capacity by 2*MaxEpochGap + 1
    ## (see issue #14).

  # Stake-weighted rate limiting parameters
  DefaultRateBase* = 100'u64
    ## Default flat per-node rate limit per epoch (spec: R_base).

  DefaultStakeUnit* = 1'u64
    ## Default stake required per message per epoch (spec: S_unit).

  DefaultStakeTierSize* = 100'u64
    ## Default stake tier size (spec: T); T >= 10 for registered-stake privacy.

  DefaultRateMax* = 1000'u64
    ## Default maximum rate (spec: R_max); 10 * DefaultRateBase, the spec's
    ## suggested starting point.

  # Root validation
  AcceptableRootWindowSize* = 5
    ## Number of past Merkle roots to keep for validation.
    ## Allows verification against slightly stale roots due to propagation delay.

  # Content topics for coordination layer
  MembershipContentTopic* = "/mix/rln/membership/v1"
    ## Content topic for broadcasting membership additions and removals.

  ProofMetadataContentTopic* = "/mix/rln/metadata/v1"
    ## Content topic for broadcasting proof metadata for network-wide spam detection.

  # RLN identifier for this application
  MixRlnIdentifier* = "mix-rln-spam-protection/v1"
    ## Application-specific RLN identifier to prevent proof reuse across applications.

  # File paths (defaults)
  DefaultTreePath* = "rln_tree.db" ## Default path for persisting the Merkle tree.

  DefaultKeystorePath* = "rln_keystore.json"
    ## Default path for the credentials keystore.

static:
  # Validate the stake-weighted inputs
  doAssert DefaultStakeUnit > 0,
    "DefaultStakeUnit (" & $DefaultStakeUnit & ") must be > 0"
  doAssert DefaultRateBase >= 1,
    "DefaultRateBase (" & $DefaultRateBase & ") must be >= 1"
  doAssert DefaultStakeTierSize >= 1,
    "DefaultStakeTierSize (" & $DefaultStakeTierSize & ") must be >= 1"

const
  DefaultRateMin* =
    ceilDiv(DefaultRateBase, DefaultStakeTierSize) * DefaultStakeTierSize
    ## Default minimum rate (spec: R_min).

  FloorStakeAmount* = DefaultRateMin * DefaultStakeUnit
    ## Minimum stake required to register (spec: floor-stake).

static:
  doAssert DefaultRateMax >= DefaultRateMin,
    "DefaultRateMax (" & $DefaultRateMax & ") must be >= DefaultRateMin (" &
      $DefaultRateMin & ")"
  doAssert DefaultRateMax mod DefaultStakeTierSize == 0,
    "DefaultRateMax (" & $DefaultRateMax &
      ") must be a multiple of DefaultStakeTierSize (" & $DefaultStakeTierSize & ")"
  doAssert DefaultRateMax <= uint64(high(int)),
    "DefaultRateMax (" & $DefaultRateMax & ") must be <= high(int) (" & $high(int) & ")"
