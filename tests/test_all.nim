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
import ../src/mix_rln_spam_protection/codec
import ../src/mix_rln_spam_protection/nullifier_log
import ../src/mix_rln_spam_protection/rln_interface

# Use std/unittest (testutils/unittests available in logos-messaging-nim context)
import std/unittest

# =============================================================================
# TEST CONSTANTS
# =============================================================================

const
  # Rate limiting - used across multiple spam detection tests
  TestUserMessageLimit* = 100'u64
    ## User message limit used in tests (messages per epoch)

  # Membership index - used across multiple tests
  TestMemberIndex* = 0'u64
    ## Default membership index for single-member tests

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
    check RateLimitProofByteSize == 301  # 288 raw + 13 protobuf overhead

  test "Epoch calculation":
    let timestamp = 1700000000.0
    let epoch = calcEpoch(timestamp)
    let epochNum = epochToUint64(epoch)

    # With RFC ceil semantics, integer-aligned timestamps keep the same epoch number.
    check epochNum == 170000000'u64

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

    # Serialize using protobuf
    let serialized = proof.toBytes()
    check serialized.len > 0  # Protobuf has variable length

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
    update.index = 12345

    # Serialize using protobuf
    let serialized = update.toBytes()
    check serialized.len > 0  # Protobuf has variable length

    # Deserialize using protobuf
    let deserialized = MembershipUpdate.decode(serialized)
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

    # Serialize using protobuf
    let serialized = broadcast.toBytes()
    check serialized.len > 0  # Protobuf has variable length

    # Deserialize using protobuf
    let deserialized = ProofMetadataBroadcast.decode(serialized)
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
    let rateCommitment = computeRateCommitment(spammerCreds.idCommitment, TestUserMessageLimit)
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
    let signal1 = @[byte(1), 2, 3, 4]  # First message
    let signal2 = @[byte(5), 6, 7, 8]  # Second message (spam)

    let proof1Result = rln.generateRlnProofWithWitness(
      spammerCreds, TestMemberIndex, epoch, rlnId, signal1, messageId = 0, userMessageLimit = TestUserMessageLimit
    )
    check proof1Result.isOk
    let proof1 = proof1Result.get()

    let proof2Result = rln.generateRlnProofWithWitness(
      spammerCreds, TestMemberIndex, epoch, rlnId, signal2, messageId = 0, userMessageLimit = TestUserMessageLimit
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
    echo "    Spammer's idSecretHash: ", spammerCreds.idSecretHash.toHex()[0..15], "..."
    echo "    Recovered secret:       ", recoveredSecret.get().toHex()[0..15], "..."

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
    let rateCommitment = computeRateCommitment(creds.idCommitment, TestUserMessageLimit)
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
      creds, TestMemberIndex, epoch, rlnId, signal1, messageId = 0, userMessageLimit = TestUserMessageLimit
    )
    check proof1Result.isOk
    let proof1 = proof1Result.get()

    let proof2Result = rln.generateRlnProofWithWitness(
      creds, TestMemberIndex, epoch, rlnId, signal2, messageId = 1, userMessageLimit = TestUserMessageLimit
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
    let rateCommitment = computeRateCommitment(creds.idCommitment, TestUserMessageLimit)
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
      creds, TestMemberIndex, epoch, rlnId, signal, messageId = 0, userMessageLimit = TestUserMessageLimit
    )
    check proofResult.isOk
    let proof = proofResult.get()

    # Get current root for verification
    let currentRoot = rln.getMerkleRoot()
    check currentRoot.isOk

    # Verify the proof is cryptographically valid
    let verifyResult = rln.verifyRlnProof(
      proof, rlnId, signal, validRoots = @[currentRoot.get()]
    )
    check verifyResult.isOk
    check verifyResult.get() == true

    echo "  ✓ Proof verification successful"

  test "Full spam protection flow with MixRlnSpamProtection":
    ## Integration test using the full MixRlnSpamProtection interface.

    # Create config
    var config = defaultConfig()
    config.userMessageLimit = int(TestUserMessageLimit)

    # Create spam protection instance
    let spResult = newMixRlnSpamProtection(config)
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
    let proofBytes = proofResult.get()

    # Verify the proof
    let verifyResult = sp.verifyProof(proofBytes, bindingData)
    check verifyResult.isOk
    check verifyResult.get() == true

    # Same proof verified again should be detected as duplicate
    let verifyResult2 = sp.verifyProof(proofBytes, bindingData)
    check verifyResult2.isOk
    check verifyResult2.get() == false  # Duplicate should return false

    # Cleanup
    waitFor sp.stop()

    echo "  ✓ Full spam protection flow completed successfully"

suite "Partial Proof Cache and Root Tracking":
  test "Partial proof cache stores Merkle path and finishes valid proofs":
    let rlnInstance = newRLNInstance()
    check rlnInstance.isOk

    let gm = newOffchainGroupManager(rlnInstance.get(), userMessageLimit = TestUserMessageLimit)
    let initResult = waitFor gm.init()
    check initResult.isOk
    let startResult = waitFor gm.start()
    check startResult.isOk

    let credResult = generateCredentials()
    check credResult.isOk
    let creds = credResult.get()

    let registerResult = waitFor gm.register(creds)
    check registerResult.isOk
    let memberIndex = registerResult.get()

    check gm.partialProofCache.isSome
    let cache = gm.partialProofCache.get()
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
      userMessageLimit = TestUserMessageLimit,
    )
    check proofResult.isOk

    let verifyResult = gm.verifyProof(proofResult.get(), signal, rlnId)
    check verifyResult.isOk
    check verifyResult.get()

  test "Removing a member resets the valid root window":
    let rlnInstance = newRLNInstance()
    check rlnInstance.isOk

    let gm = newOffchainGroupManager(rlnInstance.get(), userMessageLimit = TestUserMessageLimit)
    check (waitFor gm.init()).isOk
    check (waitFor gm.start()).isOk

    let selfCreds = generateCredentials()
    check selfCreds.isOk
    let selfRegister = waitFor gm.register(selfCreds.get())
    check selfRegister.isOk

    let rootBeforeSecondMember = gm.rlnInstance.getMerkleRoot()
    check rootBeforeSecondMember.isOk

    let peerCreds = generateCredentials()
    check peerCreds.isOk
    let peerRegister = waitFor gm.register(peerCreds.get().idCommitment)
    check peerRegister.isOk
    let peerIndex = peerRegister.get()

    let rootBeforeRemoval = gm.rlnInstance.getMerkleRoot()
    check rootBeforeRemoval.isOk
    check gm.validateRoot(rootBeforeSecondMember.get())
    check gm.validateRoot(rootBeforeRemoval.get())

    let withdrawResult = waitFor gm.withdraw(peerIndex)
    check withdrawResult.isOk

    let currentRoot = gm.rlnInstance.getMerkleRoot()
    check currentRoot.isOk
    check currentRoot.get() == rootBeforeSecondMember.get()
    check not gm.validateRoot(rootBeforeRemoval.get())
    check gm.validateRoot(currentRoot.get())

  test "Loading a snapshot replaces previously accepted roots":
    let sourceRln = newRLNInstance()
    check sourceRln.isOk
    let sourceGm = newOffchainGroupManager(sourceRln.get(), userMessageLimit = TestUserMessageLimit)
    check (waitFor sourceGm.init()).isOk
    check (waitFor sourceGm.start()).isOk

    let memberCreds = generateCredentials()
    check memberCreds.isOk
    let sourceRegister = waitFor sourceGm.register(memberCreds.get().idCommitment)
    check sourceRegister.isOk

    let snapshot = sourceGm.serializeTreeSnapshot()
    let snapshotRoot = sourceGm.rlnInstance.getMerkleRoot()
    check snapshotRoot.isOk

    let targetRln = newRLNInstance()
    check targetRln.isOk
    let targetGm = newOffchainGroupManager(targetRln.get(), userMessageLimit = TestUserMessageLimit)
    check (waitFor targetGm.init()).isOk

    let emptyRoot = targetGm.rlnInstance.getMerkleRoot()
    check emptyRoot.isOk
    check targetGm.validateRoot(emptyRoot.get())
    check snapshotRoot.get() != emptyRoot.get()

    let loadResult = targetGm.loadTreeSnapshot(snapshot)
    check loadResult.isOk

    check not targetGm.validateRoot(emptyRoot.get())
    check targetGm.validateRoot(snapshotRoot.get())

# Main test runner
when isMainModule:
  randomize()
  echo "Running Mix RLN Spam Protection tests..."
  echo "  (Tests require librln - link with --passL:librln.a --passL:-lm)"
