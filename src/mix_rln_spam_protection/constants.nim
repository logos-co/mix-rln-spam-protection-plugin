# Mix RLN Spam Protection Plugin
# Copyright (c) 2025 vacp2p
# Licensed under either of Apache License 2.0 or MIT license.

## Constants for the RLN spam protection plugin.

const
  # Merkle tree configuration
  MerkleTreeDepth* = 20
    ## Depth of the Merkle tree for membership. Supports 2^20 (~1M) members.

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
    ## UserMessageLimit messages per epoch.

  MaxEpochGap* = 5
    ## Maximum allowed epoch gap between message epoch and current epoch.
    ## Messages outside this window are rejected.

  UserMessageLimit* = 100 ## Maximum number of messages a member can send per epoch.

  # Root validation
  AcceptableRootWindowSize* = 50
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

  # Cleanup intervals
  NullifierLogCleanupIntervalSeconds* = 60
    ## How often to clean up expired entries from the nullifier log.

  # File paths (defaults)
  DefaultTreePath* = "rln_tree.db" ## Default path for persisting the Merkle tree.

  DefaultKeystorePath* = "rln_keystore.json"
    ## Default path for the credentials keystore.
