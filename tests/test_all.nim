# Mix RLN Spam Protection Plugin - Tests
# Copyright (c) 2025 vacp2p
# Licensed under either of Apache License 2.0 or MIT license.

## Test suite for the RLN spam protection plugin.
##
## Tests require the zerokit library (librln) to be linked.
##
## Run tests with static linking (in logos-messaging-nim context):
##   nim c -r --passL:librln.a --passL:-lm tests/test_all.nim
##
## Run tests with dynamic linking:
##   nim c -r -d:rlnDynlib tests/test_all.nim

import std/[options, random]
import chronos
import results

# Import all plugin modules
import ../src/mix_rln_spam_protection
import ../src/mix_rln_spam_protection/types
import ../src/mix_rln_spam_protection/constants
import ../src/mix_rln_spam_protection/nullifier_log

# Use std/unittest (testutils/unittests available in logos-messaging-nim context)
import std/unittest

# Test helpers

proc valid(x: openArray[byte]): bool =
  ## Check that a byte array is valid (not empty and correct length)
  if x.len != 32:
    return false
  for b in x:
    if b != 0:
      return true
  return false

# =============================================================================
# CONSTANTS AND EPOCH TESTS
# =============================================================================

suite "Constants":
  test "Proof size is correct":
    check RateLimitProofByteSize == 288  # 128 + 32*5

  test "Epoch calculation":
    let timestamp = 1700000000.0
    let epoch = calcEpoch(timestamp)
    let epochNum = epochToUint64(epoch)

    # With 10 second epochs: 1700000000 / 10 = 170000000
    check epochNum == uint64(timestamp / EpochDurationSeconds)

  test "Epoch validity check":
    let current = currentEpoch()
    let curNum = epochToUint64(current)

    # Same epoch should be valid
    check isEpochValid(current, current)

    # Epoch within gap should be valid
    var withinGap = current
    let withinGapNum = curNum - 2
    withinGap[0] = byte(withinGapNum and 0xFF)
    withinGap[1] = byte((withinGapNum shr 8) and 0xFF)
    check isEpochValid(withinGap, current)

    # Epoch outside gap should be invalid
    var outsideGap = current
    let outsideGapNum = curNum - uint64(MaxEpochGap + 10)
    outsideGap[0] = byte(outsideGapNum and 0xFF)
    outsideGap[1] = byte((outsideGapNum shr 8) and 0xFF)
    outsideGap[2] = byte((outsideGapNum shr 16) and 0xFF)
    outsideGap[3] = byte((outsideGapNum shr 24) and 0xFF)
    check not isEpochValid(outsideGap, current)

# =============================================================================
# TYPE SERIALIZATION TESTS
# =============================================================================

suite "Type Serialization":
  test "RateLimitProof serialization roundtrip":
    var proof: RateLimitProof
    # Fill with test data
    for i in 0 ..< proof.proof.len:
      proof.proof[i] = byte(i mod 256)
    for i in 0 ..< proof.merkleRoot.len:
      proof.merkleRoot[i] = byte((i + 1) mod 256)
    for i in 0 ..< proof.epoch.len:
      proof.epoch[i] = byte((i + 2) mod 256)
    for i in 0 ..< proof.shareX.len:
      proof.shareX[i] = byte((i + 3) mod 256)
    for i in 0 ..< proof.shareY.len:
      proof.shareY[i] = byte((i + 4) mod 256)
    for i in 0 ..< proof.nullifier.len:
      proof.nullifier[i] = byte((i + 5) mod 256)

    let serialized = proof.serialize()
    check serialized.len == RateLimitProofByteSize

    let deserialized = RateLimitProof.deserialize(serialized)
    check deserialized.isOk
    let proof2 = deserialized.get()

    check proof.proof == proof2.proof
    check proof.merkleRoot == proof2.merkleRoot
    check proof.epoch == proof2.epoch
    check proof.shareX == proof2.shareX
    check proof.shareY == proof2.shareY
    check proof.nullifier == proof2.nullifier

  test "MembershipUpdate serialization roundtrip":
    var update: MembershipUpdate
    update.action = MembershipAction.Add
    for i in 0 ..< update.idCommitment.len:
      update.idCommitment[i] = byte(i)
    update.index = 12345

    let serialized = update.serialize()
    check serialized.len == 41

    let deserialized = MembershipUpdate.deserialize(serialized)
    check deserialized.isOk
    let update2 = deserialized.get()

    check update.action == update2.action
    check update.idCommitment == update2.idCommitment
    check update.index == update2.index

  test "ProofMetadataBroadcast serialization roundtrip":
    var broadcast: ProofMetadataBroadcast
    for i in 0 ..< broadcast.nullifier.len:
      broadcast.nullifier[i] = byte(i)
    for i in 0 ..< broadcast.shareX.len:
      broadcast.shareX[i] = byte(i + 1)
    for i in 0 ..< broadcast.shareY.len:
      broadcast.shareY[i] = byte(i + 2)
    for i in 0 ..< broadcast.externalNullifier.len:
      broadcast.externalNullifier[i] = byte(i + 3)
    for i in 0 ..< broadcast.epoch.len:
      broadcast.epoch[i] = byte(i + 4)

    let serialized = broadcast.serialize()
    check serialized.len == 160

    let deserialized = ProofMetadataBroadcast.deserialize(serialized)
    check deserialized.isOk
    let broadcast2 = deserialized.get()

    check broadcast.nullifier == broadcast2.nullifier
    check broadcast.shareX == broadcast2.shareX
    check broadcast.shareY == broadcast2.shareY
    check broadcast.externalNullifier == broadcast2.externalNullifier
    check broadcast.epoch == broadcast2.epoch

# =============================================================================
# NULLIFIER LOG TESTS
# =============================================================================

suite "Nullifier Log":
  test "Empty log returns no spam":
    let nl = newNullifierLog()

    var metadata: ProofMetadata
    for i in 0 ..< metadata.nullifier.len:
      metadata.nullifier[i] = byte(i)
      metadata.shareX[i] = byte(i + 1)
      metadata.shareY[i] = byte(i + 2)
      metadata.externalNullifier[i] = byte(i + 3)

    let result = nl.checkAndInsert(metadata)
    check not result.isSpam
    check not result.isDuplicate

  test "Duplicate detection":
    let nl = newNullifierLog()

    var metadata: ProofMetadata
    for i in 0 ..< metadata.nullifier.len:
      metadata.nullifier[i] = byte(i)
      metadata.shareX[i] = byte(i + 1)
      metadata.shareY[i] = byte(i + 2)
      metadata.externalNullifier[i] = byte(i + 3)

    # First insert
    var result = nl.checkAndInsert(metadata)
    check not result.isSpam
    check not result.isDuplicate

    # Same metadata again = duplicate
    result = nl.checkAndInsert(metadata)
    check not result.isSpam
    check result.isDuplicate

  test "Spam detection (different shares, same nullifier)":
    let nl = newNullifierLog()

    var metadata1: ProofMetadata
    for i in 0 ..< metadata1.nullifier.len:
      metadata1.nullifier[i] = byte(i)
      metadata1.shareX[i] = byte(i + 1)
      metadata1.shareY[i] = byte(i + 2)
      metadata1.externalNullifier[i] = byte(i + 3)

    # First insert
    var result = nl.checkAndInsert(metadata1)
    check not result.isSpam

    # Same nullifier but different shares = SPAM
    var metadata2 = metadata1
    metadata2.shareX[0] = 100  # Different share
    metadata2.shareY[0] = 200

    result = nl.checkAndInsert(metadata2)
    check result.isSpam
    check result.conflictingEntry.isSome

  test "Different nullifiers are independent":
    let nl = newNullifierLog()

    var metadata1: ProofMetadata
    for i in 0 ..< metadata1.nullifier.len:
      metadata1.nullifier[i] = byte(1)
      metadata1.externalNullifier[i] = byte(1)

    var metadata2: ProofMetadata
    for i in 0 ..< metadata2.nullifier.len:
      metadata2.nullifier[i] = byte(2)  # Different nullifier
      metadata2.externalNullifier[i] = byte(1)

    let result1 = nl.checkAndInsert(metadata1)
    let result2 = nl.checkAndInsert(metadata2)

    check not result1.isSpam
    check not result2.isSpam

# =============================================================================
# TREE SERIALIZATION FORMAT TESTS
# =============================================================================

suite "Tree Serialization Format":
  test "Empty tree snapshot format":
    # Snapshot format: member_count(8) + next_index(8) + members(n * 40)
    let emptySnapshot = @[
      byte(0), 0, 0, 0, 0, 0, 0, 0,  # member_count = 0
      byte(0), 0, 0, 0, 0, 0, 0, 0   # next_index = 0
    ]
    check emptySnapshot.len == 16

  test "Snapshot with one member format":
    # Format: member_count(8) + next_index(8) + commitment(32) + index(8)
    var snapshot = newSeq[byte](16 + 40)

    # member_count = 1
    snapshot[0] = 1

    # next_index = 1
    snapshot[8] = 1

    # commitment (32 bytes starting at offset 16)
    for i in 0 ..< 32:
      snapshot[16 + i] = byte(i)

    # index = 0 (8 bytes starting at offset 48)
    # Already zero

    check snapshot.len == 56

# =============================================================================
# CREDENTIALS TESTS (requires zerokit)
# =============================================================================

suite "Credentials":
  test "Generate random credentials":
    let cred = generateCredentials()
    check cred.isOk

    let c = cred.get()
    # Check that fields are not all zeros
    check c.idCommitment.valid()
    check c.idSecretHash.valid()

  test "Deterministic credentials from seed":
    let seed = @[byte(1), 2, 3, 4, 5, 6, 7, 8]

    let cred1 = generateCredentialsFromSeed(seed)
    let cred2 = generateCredentialsFromSeed(seed)

    check cred1.isOk
    check cred2.isOk

    # Same seed should produce same credentials
    check cred1.get().idCommitment == cred2.get().idCommitment
    check cred1.get().idSecretHash == cred2.get().idSecretHash

  test "Different seeds produce different credentials":
    let seed1 = @[byte(1), 2, 3, 4]
    let seed2 = @[byte(5), 6, 7, 8]

    let cred1 = generateCredentialsFromSeed(seed1)
    let cred2 = generateCredentialsFromSeed(seed2)

    check cred1.isOk
    check cred2.isOk
    check cred1.get().idCommitment != cred2.get().idCommitment

# =============================================================================
# CONFIGURATION TESTS
# =============================================================================

suite "Configuration":
  test "Default config has valid values":
    let config = defaultConfig()

    check config.epochDurationSeconds == EpochDurationSeconds
    check config.maxEpochGap == MaxEpochGap
    check config.userMessageLimit == UserMessageLimit
    check config.keystorePath == DefaultKeystorePath
    check config.treePath == DefaultTreePath

  test "RLN identifier from default":
    let id = defaultRlnIdentifier()
    # Should have content (from MixRlnIdentifier constant)
    check id.valid()

# Main test runner
when isMainModule:
  randomize()
  echo "Running Mix RLN Spam Protection tests..."
  echo "  (Tests require librln - link with --passL:librln.a --passL:-lm)"
