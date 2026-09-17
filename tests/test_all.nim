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

import std/[options, os, random]
import chronos
import results

# Import all plugin modules
import ../src/mix_rln_spam_protection
import ../src/mix_rln_spam_protection/types
import ../src/mix_rln_spam_protection/constants
import ../src/mix_rln_spam_protection/codec
import ../src/mix_rln_spam_protection/nullifier_log
import ../src/mix_rln_spam_protection/rln_interface
import libp2p_mix/spam_protection as libp2p_spam

# Use std/unittest (testutils/unittests available in logos-messaging-nim context)
import std/unittest

# =============================================================================
# TEST CONSTANTS
# =============================================================================

const
  # Two stake amounts so multi-member tests can register at different rates
  TestStakeAmount1* = 100'u64 * DefaultStakeUnit
  TestStakeAmount2* = 200'u64 * DefaultStakeUnit

  TestRate1* = computeUserMessageLimit(TestStakeAmount1).get()
  TestRate2* = computeUserMessageLimit(TestStakeAmount2).get()

  # Membership index - used across multiple tests
  TestMemberIndex* = 0'u64 ## Default membership index for single-member tests

# Test helpers

proc tempKeystorePath(): string =
  ## Unique keystore path for tests that persist credentials.
  getTempDir() / ("mix_rln_test_" & $rand(high(int32)) & ".json")

proc mkEpoch(v: uint64): Epoch =
  ## Build an epoch holding `v` in the first 8 bytes, little-endian.
  result = default(Epoch)
  for i in 0 ..< 8:
    result[i] = byte((v shr (8 * i)) and 0xFF)

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
    check RateLimitProofByteSize == 301 # 288 raw + 13 protobuf overhead

  test "Epoch calculation":
    let timestamp = 1700000000.0
    let epoch = calcEpoch(timestamp)
    let epochNum = epochToUint64(epoch)
    let expectedEpochNum = uint64(timestamp / float64(EpochDurationSeconds))

    # With RFC ceil semantics, integer-aligned timestamps keep the same epoch number.
    check epochNum == expectedEpochNum

  test "Epoch calculation uses RFC ceil semantics":
    let timestamp = 10.1

    let epoch = calcEpoch(timestamp)
    check epochToUint64(epoch) == 2'u64

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

  test "Epoch validity rejects out-of-int64-range epochs without raising":
    # Epochs are attacker-controlled and span the full uint64 range. Anything
    # with the eighth byte >= 0x80 used to raise RangeDefect on conversion.
    let current = mkEpoch(175_000_000'u64)

    # Honest nearby epoch still validates.
    check isEpochValid(mkEpoch(174_999_998'u64), current)

    var topByteSet: Epoch
    topByteSet[7] = 0xFF
    check not isEpochValid(topByteSet, current)

    check not isEpochValid(mkEpoch(0xFFFFFFFFFFFFFFFF'u64), current)
    check not isEpochValid(mkEpoch(0x8000000000000000'u64), current)

    # Current epoch itself out of int64 range, message epoch small.
    check not isEpochValid(current, mkEpoch(0x8000000000000000'u64))

  test "Epoch validity gap boundary":
    let curNum = 175_000_000'u64
    let current = mkEpoch(curNum)

    # Just inside the gap, on both sides.
    check isEpochValid(mkEpoch(curNum - uint64(MaxEpochGap)), current)
    check isEpochValid(mkEpoch(curNum + uint64(MaxEpochGap)), current)

    # Just outside the gap, on both sides.
    check not isEpochValid(mkEpoch(curNum - uint64(MaxEpochGap) - 1), current)
    check not isEpochValid(mkEpoch(curNum + uint64(MaxEpochGap) + 1), current)

    # A negative gap accepts nothing, not even an exact match.
    check not isEpochValid(current, current, -1)

# =============================================================================
# BYTE UTILITY TESTS
# =============================================================================

suite "Byte Utilities":
  test "readUint64LE rejects reads that would run past the buffer":
    var buf = newSeq[byte](12)
    for i in 0 ..< buf.len:
      buf[i] = byte(i + 1)

    let first = buf.readUint64LE(0)
    check first.isOk
    check first.get() == 0x0807060504030201'u64

    # Last offset that still leaves 8 bytes.
    check buf.readUint64LE(4).isOk
    check buf.readUint64LE(5).isErr

    check buf.readUint64LE(-1).isErr

    let short4 = newSeq[byte](4)
    check short4.readUint64LE(0).isErr

    let empty: seq[byte] = @[]
    check empty.readUint64LE(0).isErr

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
    # Epoch number lives in the low 8 bytes; the tail stays zero-padded.
    for i in 0 ..< Uint64ByteSize:
      proof.epoch[i] = byte((i + 2) mod 256)
    for i in 0 ..< proof.shareX.len:
      proof.shareX[i] = byte((i + 3) mod 256)
    for i in 0 ..< proof.shareY.len:
      proof.shareY[i] = byte((i + 4) mod 256)
    for i in 0 ..< proof.nullifier.len:
      proof.nullifier[i] = byte((i + 5) mod 256)

    # Serialize using protobuf
    let serialized = proof.toBytes()
    check serialized.len > 0 # Protobuf has variable length

    # Deserialize using protobuf
    let deserialized = RateLimitProof.decode(serialized)
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
    update.userMessageLimit = TestRate1
    update.index = 12345

    # Serialize using protobuf
    let serialized = update.toBytes()
    check serialized.len > 0 # Protobuf has variable length

    # Deserialize using protobuf
    let deserialized = MembershipUpdate.decode(serialized)
    check deserialized.isOk
    let update2 = deserialized.get()

    check update.action == update2.action
    check update.idCommitment == update2.idCommitment
    check update.userMessageLimit == update2.userMessageLimit
    check update.index == update2.index

  test "decode rejects a MembershipUpdate without a rate limit":
    # Under stake-weighted registration there is no network-wide default
    # rate, so user_message_limit is a required field. Build the buffer by
    # hand with field 3 left out.
    var commitment: IDCommitment
    var buf = initProtoBuffer()
    buf.write3(1, uint32(ord(MembershipAction.Add)))
    buf.write3(2, @(commitment))
    buf.write3(4, 1'u64)
    buf.finish3()
    check MembershipUpdate.decode(buf.buffer).isErr

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
    # Epoch number lives in the low 8 bytes; the tail stays zero-padded.
    for i in 0 ..< Uint64ByteSize:
      broadcast.epoch[i] = byte(i + 4)

    # Serialize using protobuf
    let serialized = broadcast.toBytes()
    check serialized.len > 0 # Protobuf has variable length

    # Deserialize using protobuf
    let deserialized = ProofMetadataBroadcast.decode(serialized)
    check deserialized.isOk
    let broadcast2 = deserialized.get()

    check broadcast.nullifier == broadcast2.nullifier
    check broadcast.shareX == broadcast2.shareX
    check broadcast.shareY == broadcast2.shareY
    check broadcast.externalNullifier == broadcast2.externalNullifier
    check broadcast.epoch == broadcast2.epoch

  test "decode rejects a non-canonical epoch":
    # calcEpoch zero-pads bytes 8..31, so a non-zero tail is a second encoding
    # of the same epoch number and must not be accepted.
    var proof: RateLimitProof
    proof.epoch[HashByteSize - 1] = 1
    check RateLimitProof.decode(proof.toBytes()).isErr

    var broadcast: ProofMetadataBroadcast
    broadcast.epoch[Uint64ByteSize] = 1
    check ProofMetadataBroadcast.decode(broadcast.toBytes()).isErr

  test "decode rejects a membership index beyond tree capacity":
    var update: MembershipUpdate
    update.action = MembershipAction.Add
    update.userMessageLimit = TestRate1
    update.index = MerkleTreeCapacity
    check MembershipUpdate.decode(update.toBytes()).isErr

    update.index = high(uint64)
    check MembershipUpdate.decode(update.toBytes()).isErr

    update.index = MerkleTreeCapacity - 1
    check MembershipUpdate.decode(update.toBytes()).isOk

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
    metadata2.shareX[0] = 100 # Different share
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
      metadata2.nullifier[i] = byte(2) # Different nullifier
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
      byte(0),
      0,
      0,
      0,
      0,
      0,
      0,
      0, # member_count = 0
      byte(0),
      0,
      0,
      0,
      0,
      0,
      0,
      0, # next_index = 0
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
    check config.stakeAmount == 0 # operator must set before registerSelf
    check config.keystorePath == DefaultKeystorePath
    check config.treePath == DefaultTreePath

  test "RLN identifier from default":
    let id = defaultRlnIdentifier()
    # Should have content (from MixRlnIdentifier constant)
    check id.valid()

# =============================================================================
# RATE LIMIT COMPUTATION TESTS
# =============================================================================

suite "Rate Limit Computation":
  const TierStake = DefaultStakeTierSize * DefaultStakeUnit
    ## Stake per tier (spec: T * S_unit)

  test "Mid-range stake yields proportional rate":
    # stakeAmount = exact multiple of TierStake between floor and cap
    # -> rate = matching multiple of DefaultStakeTierSize
    let tiers = (DefaultRateMin div DefaultStakeTierSize) + 3
    let result = computeUserMessageLimit(tiers * TierStake)
    check result.isOk
    check result.get() == tiers * DefaultStakeTierSize

  test "Floor-stake yields DefaultRateMin":
    # stakeAmount = FloorStakeAmount -> rate = DefaultRateMin
    let result = computeUserMessageLimit(FloorStakeAmount)
    check result.isOk
    check result.get() == DefaultRateMin

  test "Stake just below floor errors":
    # stakeAmount < FloorStakeAmount -> reject
    let result = computeUserMessageLimit(FloorStakeAmount - 1'u64)
    check result.isErr

  test "Zero stake errors":
    # stakeAmount = 0 -> reject
    let result = computeUserMessageLimit(0'u64)
    check result.isErr

  test "Stake above cap yields DefaultRateMax":
    # stakeAmount > DefaultRateMax * DefaultStakeUnit -> rate = DefaultRateMax
    let bigStake = (DefaultRateMax + 100'u64) * DefaultStakeUnit
    let result = computeUserMessageLimit(bigStake)
    check result.isOk
    check result.get() == DefaultRateMax

  test "Fractional stake floors correctly":
    # stakeAmount mod TierStake != 0
    # -> fractional tier ignored, rate stays at the lower tier boundary
    let result = computeUserMessageLimit(FloorStakeAmount + TierStake - 1'u64)
    check result.isOk
    check result.get() == DefaultRateMin

  test "Computed rates pass registry-side validation":
    # Every mapping output must be admissible by validateRate
    var stake = FloorStakeAmount
    while stake <= (DefaultRateMax + DefaultStakeTierSize) * DefaultStakeUnit:
      let rate = computeUserMessageLimit(stake)
      check rate.isOk
      check validateRate(rate.get()).isOk
      stake += TierStake div 2

  test "Splitting stake never yields more aggregate rate (Sybil-resistance)":
    # For any split S = S1 + S2, rate(S1) + rate(S2) <= rate(S), with
    # equality when both parts are exact multiples of TierStake
    let whole = 7'u64 * FloorStakeAmount
    let wholeRate = computeUserMessageLimit(whole).get()

    # exact tier multiples -> additive
    let evenSplit =
      computeUserMessageLimit(3'u64 * FloorStakeAmount).get() +
      computeUserMessageLimit(4'u64 * FloorStakeAmount).get()
    check evenSplit == wholeRate

    # off-boundary split -> loses the fractional tiers
    let part1 = 3'u64 * FloorStakeAmount + TierStake div 2
    let part2 = whole - part1
    let unevenSplit =
      computeUserMessageLimit(part1).get() + computeUserMessageLimit(part2).get()
    check unevenSplit <= wholeRate

# =============================================================================
# SPAM DETECTION AND SECRET RECOVERY TESTS (requires zerokit)
# =============================================================================

suite "Spam Detection and Secret Recovery":
  ## These tests verify the core spam protection functionality:
  ## 1. Duplicate proof detection via nullifier log
  ## 2. Spam detection when same identity sends different messages in same epoch
  ## 3. Secret key recovery from spam proofs (for slashing)

  test "Detect spam from duplicate nullifiers and recover secret":
    ## This test simulates a spammer sending two messages in the same epoch
    ## with the same messageId, which produces the same nullifier.
    ## The verifier should detect this as spam and be able to recover the secret.

    # Create RLN instance
    let rlnInstance = newRLNInstance()
    check rlnInstance.isOk
    let rln = rlnInstance.get()

    # Generate credentials for a member (the spammer)
    let credResult = generateCredentials()
    check credResult.isOk
    let spammerCreds = credResult.get()

    # Register spammer in the tree with rate commitment
    let rateCommitment = computeRateCommitment(spammerCreds.idCommitment, TestRate1)
    check rateCommitment.isOk

    let insertResult = rln.insertMemberAt(TestMemberIndex, rateCommitment.get())
    check insertResult.isOk

    # Flush tree to ensure it's synced
    discard flush(rln.ctx)

    # Current epoch
    let epoch = currentEpoch()
    let rlnId = defaultRlnIdentifier()

    # Generate two proofs with SAME messageId (0) but DIFFERENT signals
    # This simulates the spammer sending two different messages in the same epoch
    let signal1 = @[byte(1), 2, 3, 4] # First message
    let signal2 = @[byte(5), 6, 7, 8] # Second message (spam)

    let proof1Result = rln.generateRlnProofWithWitness(
      spammerCreds,
      TestMemberIndex,
      epoch,
      rlnId,
      signal1,
      messageId = 0,
      userMessageLimit = TestRate1,
    )
    check proof1Result.isOk
    let proof1 = proof1Result.get()

    let proof2Result = rln.generateRlnProofWithWitness(
      spammerCreds,
      TestMemberIndex,
      epoch,
      rlnId,
      signal2,
      messageId = 0,
      userMessageLimit = TestRate1,
    )
    check proof2Result.isOk
    let proof2 = proof2Result.get()

    # Both proofs should have the SAME nullifier (since same identity, same epoch, same messageId)
    check proof1.nullifier == proof2.nullifier

    # But different share values (since different signals produce different x values)
    # The shares are derived from Shamir secret sharing where x = signal_hash
    # So different signals produce different shareX and shareY

    # Create nullifier log and check for spam
    let nullifierLog = newNullifierLog()

    # Compute external nullifier for the log
    let extNullifier = computeExternalNullifier(epoch, rlnId)
    check extNullifier.isOk

    # First proof - should be valid (not spam)
    let metadata1 = ProofMetadata(
      nullifier: proof1.nullifier,
      shareX: proof1.shareX,
      shareY: proof1.shareY,
      externalNullifier: extNullifier.get(),
    )
    let result1 = nullifierLog.checkAndInsert(metadata1)
    check not result1.isSpam
    check not result1.isDuplicate

    # Second proof with SAME nullifier but DIFFERENT shares - should be detected as SPAM
    let metadata2 = ProofMetadata(
      nullifier: proof2.nullifier,
      shareX: proof2.shareX,
      shareY: proof2.shareY,
      externalNullifier: extNullifier.get(),
    )
    let result2 = nullifierLog.checkAndInsert(metadata2)

    # This should be spam (same nullifier, different shares)
    check result2.isSpam
    check result2.conflictingEntry.isSome

    # Now recover the secret from the two spam proofs
    let recoveredSecret = rln.recoverSecret(proof1, proof2)
    check recoveredSecret.isOk

    # The recovered secret should match the spammer's idSecretHash
    check recoveredSecret.get() == spammerCreds.idSecretHash

    echo "  ✓ Spam detected and secret recovered successfully!"
    echo "    Spammer's idSecretHash: ",
      spammerCreds.idSecretHash.toHex()[0 .. 15], "..."
    echo "    Recovered secret:       ", recoveredSecret.get().toHex()[0 .. 15], "..."

  test "Different messageIds produce different nullifiers (no spam)":
    ## This test verifies that using different messageIds within the rate limit
    ## produces different nullifiers and is NOT detected as spam.

    # Create RLN instance
    let rlnInstance = newRLNInstance()
    check rlnInstance.isOk
    let rln = rlnInstance.get()

    # Generate credentials
    let credResult = generateCredentials()
    check credResult.isOk
    let creds = credResult.get()

    # Register member
    let rateCommitment = computeRateCommitment(creds.idCommitment, TestRate1)
    check rateCommitment.isOk
    let insertResult = rln.insertMemberAt(TestMemberIndex, rateCommitment.get())
    check insertResult.isOk

    # Flush tree
    discard flush(rln.ctx)

    # Current epoch
    let epoch = currentEpoch()
    let rlnId = defaultRlnIdentifier()

    # Generate two proofs with DIFFERENT messageIds (legitimate usage)
    let signal1 = @[byte(1), 2, 3, 4]
    let signal2 = @[byte(5), 6, 7, 8]

    let proof1Result = rln.generateRlnProofWithWitness(
      creds,
      TestMemberIndex,
      epoch,
      rlnId,
      signal1,
      messageId = 0,
      userMessageLimit = TestRate1,
    )
    check proof1Result.isOk
    let proof1 = proof1Result.get()

    let proof2Result = rln.generateRlnProofWithWitness(
      creds,
      TestMemberIndex,
      epoch,
      rlnId,
      signal2,
      messageId = 1,
      userMessageLimit = TestRate1,
    )
    check proof2Result.isOk
    let proof2 = proof2Result.get()

    # Different messageIds should produce DIFFERENT nullifiers
    check proof1.nullifier != proof2.nullifier

    # Neither should be detected as spam
    let nullifierLog = newNullifierLog()
    let extNullifier = computeExternalNullifier(epoch, rlnId)
    check extNullifier.isOk

    let metadata1 = ProofMetadata(
      nullifier: proof1.nullifier,
      shareX: proof1.shareX,
      shareY: proof1.shareY,
      externalNullifier: extNullifier.get(),
    )
    let result1 = nullifierLog.checkAndInsert(metadata1)
    check not result1.isSpam
    check not result1.isDuplicate

    let metadata2 = ProofMetadata(
      nullifier: proof2.nullifier,
      shareX: proof2.shareX,
      shareY: proof2.shareY,
      externalNullifier: extNullifier.get(),
    )
    let result2 = nullifierLog.checkAndInsert(metadata2)
    check not result2.isSpam
    check not result2.isDuplicate

    echo "  ✓ Different messageIds correctly produce different nullifiers (no spam)"

  test "Verify proofs are valid before spam detection":
    ## This test ensures the generated proofs are cryptographically valid.

    # Create RLN instance
    let rlnInstance = newRLNInstance()
    check rlnInstance.isOk
    let rln = rlnInstance.get()

    # Generate credentials
    let credResult = generateCredentials()
    check credResult.isOk
    let creds = credResult.get()

    # Register member
    let rateCommitment = computeRateCommitment(creds.idCommitment, TestRate1)
    check rateCommitment.isOk
    let insertResult = rln.insertMemberAt(TestMemberIndex, rateCommitment.get())
    check insertResult.isOk

    # Flush tree
    discard flush(rln.ctx)

    let epoch = currentEpoch()
    let rlnId = defaultRlnIdentifier()
    let signal = @[byte(1), 2, 3, 4, 5]

    # Generate proof
    let proofResult = rln.generateRlnProofWithWitness(
      creds,
      TestMemberIndex,
      epoch,
      rlnId,
      signal,
      messageId = 0,
      userMessageLimit = TestRate1,
    )
    check proofResult.isOk
    let proof = proofResult.get()

    # Get current root for verification
    let currentRoot = rln.getMerkleRoot()
    check currentRoot.isOk

    # Verify the proof is cryptographically valid
    let verifyResult =
      rln.verifyRlnProof(proof, rlnId, signal, validRoots = @[currentRoot.get()])
    check verifyResult.isOk
    check verifyResult.get() == true

    echo "  ✓ Proof verification successful"

  test "Full spam protection flow with MixRlnSpamProtection":
    ## Integration test using the full MixRlnSpamProtection interface.

    # Create config
    var config = defaultConfig()
    config.stakeAmount = TestStakeAmount1

    # Create spam protection instance
    let spResult = MixRlnSpamProtection.new(config)
    check spResult.isOk
    let sp = spResult.get()

    # Initialize
    let initResult = waitFor sp.init()
    check initResult.isOk

    # Register self
    let registerResult = waitFor sp.registerSelf()
    check registerResult.isOk
    discard registerResult.get()

    # Start the plugin
    let startResult = waitFor sp.start()
    check startResult.isOk

    check sp.isReady()

    # Generate a proof using the high-level interface
    let bindingData = @[byte(10), 20, 30, 40, 50]
    let proofResult = sp.generateProof(bindingData)
    check proofResult.isOk
    let proofBytes = proofResult.get().proof

    # Verify the proof
    let verifyResult = sp.verifyProof(proofBytes, bindingData)
    check verifyResult.isOk
    check verifyResult.get() == true

    # Same proof verified again should be detected as duplicate
    let verifyResult2 = sp.verifyProof(proofBytes, bindingData)
    check verifyResult2.isOk
    check verifyResult2.get() == false # Duplicate should return false

    # Cleanup
    waitFor sp.stop()

    echo "  ✓ Full spam protection flow completed successfully"

  test "Proof metadata with out-of-window epoch is rejected at ingest":
    let spResult = MixRlnSpamProtection.new(defaultConfig())
    check spResult.isOk
    let sp = spResult.get()

    var broadcast: ProofMetadataBroadcast
    for i in 0 ..< HashByteSize:
      broadcast.nullifier[i] = byte(i)
      broadcast.shareX[i] = byte(i + 1)
      broadcast.shareY[i] = byte(i + 2)
      broadcast.externalNullifier[i] = byte(i + 3)

    let curEpochNum = int64(epochToUint64(currentEpoch()))

    # Current epoch is accepted. An epoch tick between here and the internal
    # currentEpoch() call moves the offset to -1, which is still in-window.
    broadcast.epoch = calcEpoch(float64(curEpochNum) * EpochDurationSeconds)
    check sp.handleProofMetadata(broadcast.toBytes()).isOk

    # Two epochs past either window edge stays out-of-window across a tick.
    broadcast.epoch =
      calcEpoch(float64(curEpochNum - int64(MaxEpochGap) - 2) * EpochDurationSeconds)
    check sp.handleProofMetadata(broadcast.toBytes()).isErr

    broadcast.epoch =
      calcEpoch(float64(curEpochNum + int64(MaxEpochGap) + 2) * EpochDurationSeconds)
    check sp.handleProofMetadata(broadcast.toBytes()).isErr

# =============================================================================
# KEYSTORE PERSISTENCE TESTS (requires zerokit)
# =============================================================================

suite "Keystore Persistence":
  test "Restart from keystore rebuilds the registered leaf":
    var config = defaultConfig()
    config.stakeAmount = TestStakeAmount2
    config.keystorePassword = "test-password"
    config.keystorePath = tempKeystorePath()
    defer:
      removeFile(config.keystorePath)

    # First run: register with stake, which writes index and rate to keystore.
    let first = MixRlnSpamProtection.new(config).get()
    check (waitFor first.init()).isOk
    let index = waitFor first.registerSelf()
    check index.isOk
    check (waitFor first.start()).isOk
    let firstRate = first.rateLimitBudget()

    # Second run with no tree file: init loads the keystore, the restore
    # re-inserts the leaf, and registerSelf returns the stored index.
    let second = MixRlnSpamProtection.new(config).get()
    check (waitFor second.init()).isOk
    check second.restoreCredentialsToTree().isOk
    check (waitFor second.start()).isOk
    check (waitFor second.registerSelf()).get() == index.get()
    check second.rateLimitBudget() == firstRate

    # A proof from the restarted node verifies against the first node's
    # tree, so both hold the same leaf and root.
    let bindingData = @[byte(1), 2, 3]
    let proof = second.generateProof(bindingData)
    check proof.isOk
    check first.verifyProof(proof.get().proof, bindingData).get() == true

    waitFor first.stop()
    waitFor second.stop()

  test "Keystore with an index but no rate limit is rejected at init":
    var config = defaultConfig()
    config.keystorePassword = "test-password"
    config.keystorePath = tempKeystorePath()
    defer:
      removeFile(config.keystorePath)

    # A flat-rate build persisted the index without a rate.
    let creds = generateCredentials().get()
    check saveKeystore(
      creds, config.keystorePassword, config.keystorePath, some(TestMemberIndex)
    ).isOk

    let sp = MixRlnSpamProtection.new(config).get()
    check (waitFor sp.init()).isErr

suite "Partial Proof Cache and Root Tracking":
  test "Partial proof cache stores Merkle path and finishes valid proofs":
    let rlnInstance = newRLNInstance()
    check rlnInstance.isOk

    let gm = newOffchainGroupManager(rlnInstance.get())
    let initResult = waitFor gm.init()
    check initResult.isOk
    let startResult = waitFor gm.start()
    check startResult.isOk

    let credResult = generateCredentials()
    check credResult.isOk
    let creds = credResult.get()

    check (waitFor gm.register(creds, FloorStakeAmount - 1'u64)).isErr
    let registerResult = waitFor gm.register(creds, TestStakeAmount1)
    check registerResult.isOk
    let memberIndex = registerResult.get()

    check gm.partialProofCache.isSome
    let cache = gm.partialProofCache.get()
    check cache.memberIndex == memberIndex
    check cache.partialProofBytes.len > 0
    check cache.pathIndex.len > 0
    check cache.pathElements.len == cache.pathIndex.len * HashByteSize

    let epoch = currentEpoch()
    let rlnId = defaultRlnIdentifier()
    let signal = @[byte(7), 8, 9, 10]

    let proofResult = gm.rlnInstance.finishRlnProofWithCache(
      cache,
      creds,
      memberIndex,
      epoch,
      rlnId,
      signal,
      messageId = 0,
      userMessageLimit = TestRate1,
    )
    check proofResult.isOk

    let wrongIndexResult = gm.rlnInstance.finishRlnProofWithCache(
      cache,
      creds,
      memberIndex + 1,
      epoch,
      rlnId,
      signal,
      messageId = 0,
      userMessageLimit = TestRate1,
    )
    check wrongIndexResult.isErr

    let verifyResult = gm.verifyProof(proofResult.get(), signal, rlnId)
    check verifyResult.isOk
    check verifyResult.get()

  test "Removing a member resets the valid root window":
    let rlnInstance = newRLNInstance()
    check rlnInstance.isOk

    let gm = newOffchainGroupManager(rlnInstance.get())
    check (waitFor gm.init()).isOk
    check (waitFor gm.start()).isOk

    let selfCreds = generateCredentials()
    check selfCreds.isOk
    let selfRegister = waitFor gm.register(selfCreds.get(), TestStakeAmount1)
    check selfRegister.isOk

    let rootBeforeSecondMember = gm.rlnInstance.getMerkleRoot()
    check rootBeforeSecondMember.isOk

    # Register the peer at a different rate than this node.
    let peerCreds = generateCredentials()
    check peerCreds.isOk
    check (
      waitFor gm.registerWithStake(
        peerCreds.get().idCommitment, FloorStakeAmount - 1'u64
      )
    ).isErr
    let peerRegister =
      waitFor gm.registerWithStake(peerCreds.get().idCommitment, TestStakeAmount2)
    check peerRegister.isOk
    let peerIndex = peerRegister.get()

    check gm.getMemberRateLimit(selfCreds.get().idCommitment) == some(TestRate1)
    check gm.getMemberRateLimit(peerCreds.get().idCommitment) == some(TestRate2)

    let rootBeforeRemoval = gm.rlnInstance.getMerkleRoot()
    check rootBeforeRemoval.isOk
    check gm.validateRoot(rootBeforeSecondMember.get())
    check gm.validateRoot(rootBeforeRemoval.get())

    let withdrawResult = waitFor gm.withdraw(peerIndex)
    check withdrawResult.isOk

    check gm.getMemberRateLimit(peerCreds.get().idCommitment) == none(uint64)

    let currentRoot = gm.rlnInstance.getMerkleRoot()
    check currentRoot.isOk
    check currentRoot.get() == rootBeforeSecondMember.get()
    check not gm.validateRoot(rootBeforeRemoval.get())
    check gm.validateRoot(currentRoot.get())

  test "Loading a snapshot replaces previously accepted roots":
    let sourceRln = newRLNInstance()
    check sourceRln.isOk
    let sourceGm = newOffchainGroupManager(sourceRln.get())
    check (waitFor sourceGm.init()).isOk
    check (waitFor sourceGm.start()).isOk

    # Register the member at a different rate than the node loading the snapshot.
    let memberCreds = generateCredentials()
    check memberCreds.isOk
    let sourceRegister = waitFor sourceGm.registerWithStake(
      memberCreds.get().idCommitment, TestStakeAmount2
    )
    check sourceRegister.isOk

    let snapshot = sourceGm.serializeTreeSnapshot()
    let snapshotRoot = sourceGm.rlnInstance.getMerkleRoot()
    check snapshotRoot.isOk

    let targetRln = newRLNInstance()
    check targetRln.isOk
    let targetGm = newOffchainGroupManager(targetRln.get())
    check (waitFor targetGm.init()).isOk

    let emptyRoot = targetGm.rlnInstance.getMerkleRoot()
    check emptyRoot.isOk
    check targetGm.validateRoot(emptyRoot.get())
    check snapshotRoot.get() != emptyRoot.get()

    let loadResult = targetGm.loadTreeSnapshot(snapshot)
    check loadResult.isOk

    check not targetGm.validateRoot(emptyRoot.get())
    check targetGm.validateRoot(snapshotRoot.get())

    # The snapshot carries each member's own rate, not the loading node's.
    check targetGm.getMemberRateLimit(memberCreds.get().idCommitment) == some(TestRate2)

  test "Snapshot with an out-of-range member count is rejected":
    let rln = newRLNInstance()
    check rln.isOk
    let gm = newOffchainGroupManager(rln.get())
    check (waitFor gm.init()).isOk

    # member_count above high(int64) used to reach int(memberCount) and raise
    # RangeDefect; values above 2^57 overflowed the multiply instead.
    var hostile = newSeq[byte](16)
    for i in 0 ..< 8:
      hostile[i] = 0xFF
    check gm.loadTreeSnapshot(hostile).isErr

    var overflowing = newSeq[byte](16)
    overflowing[7] = 0x02 # 2^57 members
    check gm.loadTreeSnapshot(overflowing).isErr

    # A short buffer is caught by the header-length guard, ahead of any read.
    check gm.loadTreeSnapshot(newSeq[byte](12)).isErr

  test "Rejected snapshot leaves the loaded group untouched":
    let rln = newRLNInstance()
    check rln.isOk
    let gm = newOffchainGroupManager(rln.get())
    check (waitFor gm.init()).isOk
    check (waitFor gm.start()).isOk

    let creds = generateCredentials()
    check creds.isOk
    check (waitFor gm.register(creds.get(), TestStakeAmount1)).isOk
    let rootBefore = gm.rlnInstance.getMerkleRoot()
    check rootBefore.isOk

    # Two entries, the second with a rate the mapping cannot produce. Without
    # validating up front the first entry lands and the root window is emptied.
    var hostile = newSeq[byte](16 + 2 * 48)
    hostile[0] = 2 # member_count = 2
    hostile[8] = 2 # next_index = 2
    for i in 0 ..< 32:
      hostile[16 + i] = byte(i + 1) # first commitment
      hostile[64 + i] = byte(i + 2) # second commitment
    hostile[56] = byte(TestRate1) # first rate, valid
    hostile[72] = 1 # second index = 1
    hostile[80] = 7 # second rate = 7, rejected
    check gm.loadTreeSnapshot(hostile).isErr

    check gm.getMemberCount() == 1
    check gm.getMemberRateLimit(creds.get().idCommitment) == some(TestRate1)
    check gm.validateRoot(rootBefore.get())

    # Same shape with a valid rate but an index beyond the tree capacity.
    hostile[80] = byte(TestRate1)
    hostile[72] = 0
    hostile[74] = 0x10 # second index = 2^20 = MerkleTreeCapacity
    check gm.loadTreeSnapshot(hostile).isErr
    check gm.getMemberCount() == 1
    check gm.validateRoot(rootBefore.get())

  test "Snapshot with an out-of-range member rate is rejected":
    let rln = newRLNInstance()
    check rln.isOk
    let gm = newOffchainGroupManager(rln.get())
    check (waitFor gm.init()).isOk

    # One member at index 0 whose rate the stake-to-rate mapping can never
    # produce (0, below DefaultRateMin, and not a multiple of the tier size).
    var hostile = newSeq[byte](16 + 48)
    hostile[0] = 1 # member_count = 1
    hostile[8] = 1 # next_index = 1
    for i in 0 ..< 32:
      hostile[16 + i] = byte(i + 1) # commitment
    check gm.loadTreeSnapshot(hostile).isErr # rate = 0

    hostile[16 + 40] = 7 # rate = 7, not a multiple of DefaultStakeTierSize
    check gm.loadTreeSnapshot(hostile).isErr

  test "Membership update with an unproducible rate is rejected":
    let rln = newRLNInstance()
    check rln.isOk
    let gm = newOffchainGroupManager(rln.get())
    check (waitFor gm.init()).isOk
    check (waitFor gm.start()).isOk

    let peerCreds = generateCredentials()
    check peerCreds.isOk
    let update = MembershipUpdate(
      action: MembershipAction.Add,
      idCommitment: peerCreds.get().idCommitment,
      userMessageLimit: DefaultRateMax + DefaultStakeTierSize,
      index: 0,
    )
    check (waitFor gm.handleMembershipUpdate(update)).isErr

suite "Epoch Change Notification":
  test "epochDurationSeconds returns configured value":
    var cfg = defaultConfig()
    cfg.epochDurationSeconds = 15.0
    let sp = MixRlnSpamProtection.new(cfg)
    check sp.isOk
    check sp.get().epochDurationSeconds() == 15.0

  test "rateLimitBudget returns computed userMessageLimit":
    var cfg = defaultConfig()
    cfg.stakeAmount = TestStakeAmount2
    let sp = MixRlnSpamProtection.new(cfg)
    check sp.isOk
    let plugin = sp.get()

    # No rate before registration; the limit is computed from stake.
    check plugin.rateLimitBudget() == 0

    check (waitFor plugin.init()).isOk
    check (waitFor plugin.registerSelf()).isOk
    check plugin.rateLimitBudget() == int(TestRate2)

  test "registered epoch change callback fires on generateProof":
    var config = defaultConfig()
    config.stakeAmount = TestStakeAmount1
    let sp = MixRlnSpamProtection.new(config)
    check sp.isOk
    let plugin = sp.get()

    let initResult = waitFor plugin.init()
    check initResult.isOk
    let registerResult = waitFor plugin.registerSelf()
    check registerResult.isOk
    let startResult = waitFor plugin.start()
    check startResult.isOk

    var receivedEpoch: uint64 = 0
    plugin.registerOnEpochChange(
      proc(epoch: uint64) {.gcsafe, raises: [].} =
        receivedEpoch = epoch
    )

    let proofResult = plugin.generateProof(@[byte(1), 2, 3])
    check proofResult.isOk
    # First call sets lastEpoch, callback fires with current epoch
    check receivedEpoch > 0

    waitFor plugin.stop()

  test "epoch change callback fires from background timer while idle":
    # Exercises the background runEpochTimer path: no generateProof calls
    # are made, so the callback can only fire if the timer detected a
    # boundary on its own.
    var cfg = defaultConfig()
    cfg.epochDurationSeconds = 1.0
    cfg.stakeAmount = TestStakeAmount1
    let sp = MixRlnSpamProtection.new(cfg)
    check sp.isOk
    let plugin = sp.get()

    check (waitFor plugin.init()).isOk
    check (waitFor plugin.registerSelf()).isOk
    check (waitFor plugin.start()).isOk

    var fired = false
    plugin.registerOnEpochChange(
      proc(epoch: uint64) {.gcsafe, raises: [].} =
        fired = true
    )

    # Sleep > 1 epoch so at least one boundary must be crossed.
    waitFor sleepAsync(1500.milliseconds)
    check fired

    waitFor plugin.stop()

# Main test runner
when isMainModule:
  randomize()
  echo "Running Mix RLN Spam Protection tests..."
  echo "  (Tests require librln - link with --passL:librln.a --passL:-lm)"
