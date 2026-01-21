# Mix RLN Spam Protection Plugin
# Copyright (c) 2025 vacp2p
# Licensed under either of Apache License 2.0 or MIT license.

## Core type definitions for the RLN spam protection plugin.

import std/[times, options]
import chronos
import results
import ./constants

type
  # Cryptographic primitives (fixed-size byte arrays)
  MerkleNode* = array[HashByteSize, byte]
    ## 32-byte Poseidon hash used in Merkle tree nodes.

  Nullifier* = array[HashByteSize, byte]
    ## 32-byte nullifier derived from epoch and member's secret key.

  Epoch* = array[HashByteSize, byte]
    ## 32-byte epoch value representing a time window.

  RlnIdentifier* = array[HashByteSize, byte]
    ## 32-byte application-specific RLN identifier.

  ExternalNullifier* = array[HashByteSize, byte]
    ## 32-byte external nullifier: Poseidon(epoch, rln_identifier).

  ShareX* = array[HashByteSize, byte]
    ## 32-byte Shamir secret share X coordinate.

  ShareY* = array[HashByteSize, byte]
    ## 32-byte Shamir secret share Y coordinate.

  IDCommitment* = array[HashByteSize, byte]
    ## 32-byte identity commitment: Poseidon(identity_secret).

  IDSecretHash* = array[HashByteSize, byte]
    ## 32-byte identity secret hash (the actual secret key).

  IDTrapdoor* = array[HashByteSize, byte]
    ## 32-byte identity trapdoor (component of credential).

  IDNullifier* = array[HashByteSize, byte]
    ## 32-byte identity nullifier (component of credential).

  ZkProof* = array[ZksnarkProofByteSize, byte]
    ## 128-byte compressed zkSNARK proof.

  MembershipIndex* = uint64
    ## Index of a member in the Merkle tree (0-based).

  # Identity and credentials
  IdentityCredential* = object
    ## Complete identity credential for an RLN member.
    idTrapdoor*: IDTrapdoor
    idNullifier*: IDNullifier
    idSecretHash*: IDSecretHash
    idCommitment*: IDCommitment

  # Rate limit proof structure (as per RFC)
  RateLimitProof* = object
    ## Complete RLN proof attached to messages.
    ## Note: rlnIdentifier is NOT included as it's a network-wide constant
    ## and can be derived from configuration.
    proof*: ZkProof           ## 128 bytes: zkSNARK proof
    merkleRoot*: MerkleNode   ## 32 bytes: Merkle tree root used for proof
    epoch*: Epoch             ## 32 bytes: epoch when proof was generated
    shareX*: ShareX           ## 32 bytes: Shamir share X
    shareY*: ShareY           ## 32 bytes: Shamir share Y
    nullifier*: Nullifier     ## 32 bytes: message nullifier

  # Proof metadata for spam detection
  ProofMetadata* = object
    ## Extracted metadata from a proof for spam detection.
    nullifier*: Nullifier
    shareX*: ShareX
    shareY*: ShareY
    externalNullifier*: ExternalNullifier

  # Message validation result
  MessageValidationResult* = enum
    ## Result of validating a message's RLN proof.
    Valid       ## Proof is valid and message should be processed
    Invalid     ## Proof is invalid (wrong proof, bad epoch, etc.)
    Spam        ## Spam detected (double signaling)
    Duplicate   ## Duplicate message (same proof seen before)

  # Membership update actions
  MembershipAction* = enum
    ## Action type for membership updates.
    Add
    Remove

  # Membership update message (for coordination layer)
  MembershipUpdate* = object
    ## Message broadcast on membership content topic.
    action*: MembershipAction
    idCommitment*: IDCommitment
    index*: MembershipIndex

  # Proof metadata broadcast message (for coordination layer)
  ProofMetadataBroadcast* = object
    ## Message broadcast on proof metadata content topic.
    nullifier*: Nullifier
    shareX*: ShareX
    shareY*: ShareY
    externalNullifier*: ExternalNullifier
    epoch*: Epoch

  # Callback types for coordination layer integration
  PublishCallback* = proc(contentTopic: string, data: seq[byte]): Future[void] {.gcsafe, raises: [].}
    ## Callback for publishing messages to logos-messaging.

  MembershipUpdateHandler* = proc(update: MembershipUpdate): Future[void] {.gcsafe, raises: [].}
    ## Handler called when membership updates are received.

  ProofMetadataHandler* = proc(metadata: ProofMetadataBroadcast): Future[void] {.gcsafe, raises: [].}
    ## Handler called when proof metadata is received from network.

  # Spam handler callback
  SpamHandler* = proc(
    proof: RateLimitProof,
    recoveredSecret: IDSecretHash,
    memberIndex: MembershipIndex
  ): Future[void] {.gcsafe, raises: [].}
    ## Handler called when spam is detected.
    ## Receives the offending proof, recovered secret key, and member index.

  # Result types
  RlnResult*[T] = Result[T, string]
    ## Generic result type for RLN operations.

  # Plugin state
  PluginState* = enum
    ## State of the spam protection plugin.
    Uninitialized  ## Plugin created but not started
    Syncing        ## Waiting for initial membership sync
    Ready          ## Plugin is ready for proof generation/verification
    Stopped        ## Plugin has been stopped

# Helper functions for epoch calculation

proc calcEpoch*(timestamp: float64): Epoch =
  ## Calculate the epoch for a given Unix timestamp.
  let epochNum = uint64(timestamp / EpochDurationSeconds)
  result = default(Epoch)
  # Store as little-endian
  result[0] = byte(epochNum and 0xFF)
  result[1] = byte((epochNum shr 8) and 0xFF)
  result[2] = byte((epochNum shr 16) and 0xFF)
  result[3] = byte((epochNum shr 24) and 0xFF)
  result[4] = byte((epochNum shr 32) and 0xFF)
  result[5] = byte((epochNum shr 40) and 0xFF)
  result[6] = byte((epochNum shr 48) and 0xFF)
  result[7] = byte((epochNum shr 56) and 0xFF)

proc calcEpoch*(t: Time): Epoch =
  ## Calculate the epoch for a given Time.
  calcEpoch(t.toUnixFloat())

proc currentEpoch*(): Epoch =
  ## Get the current epoch based on system time.
  calcEpoch(getTime())

proc epochToUint64*(epoch: Epoch): uint64 =
  ## Convert an epoch to its numeric value.
  result = uint64(epoch[0]) or
           (uint64(epoch[1]) shl 8) or
           (uint64(epoch[2]) shl 16) or
           (uint64(epoch[3]) shl 24) or
           (uint64(epoch[4]) shl 32) or
           (uint64(epoch[5]) shl 40) or
           (uint64(epoch[6]) shl 48) or
           (uint64(epoch[7]) shl 56)

proc epochDiff*(e1, e2: Epoch): int64 =
  ## Calculate the difference between two epochs.
  int64(epochToUint64(e1)) - int64(epochToUint64(e2))

proc isEpochValid*(msgEpoch: Epoch, currentEpoch: Epoch): bool =
  ## Check if a message epoch is within the acceptable gap.
  let diff = abs(epochDiff(currentEpoch, msgEpoch))
  diff <= MaxEpochGap

# Serialization helpers

proc serialize*(proof: RateLimitProof): seq[byte] =
  ## Serialize a RateLimitProof to bytes (288 bytes total).
  ## Format: proof(128) + merkleRoot(32) + epoch(32) + shareX(32) + shareY(32) + nullifier(32)
  result = newSeq[byte](RateLimitProofByteSize)
  var offset = 0

  copyMem(addr result[offset], unsafeAddr proof.proof[0], ZksnarkProofByteSize)
  offset += ZksnarkProofByteSize

  copyMem(addr result[offset], unsafeAddr proof.merkleRoot[0], HashByteSize)
  offset += HashByteSize

  copyMem(addr result[offset], unsafeAddr proof.epoch[0], HashByteSize)
  offset += HashByteSize

  copyMem(addr result[offset], unsafeAddr proof.shareX[0], HashByteSize)
  offset += HashByteSize

  copyMem(addr result[offset], unsafeAddr proof.shareY[0], HashByteSize)
  offset += HashByteSize

  copyMem(addr result[offset], unsafeAddr proof.nullifier[0], HashByteSize)

proc deserialize*(T: typedesc[RateLimitProof], data: seq[byte]): RlnResult[RateLimitProof] =
  ## Deserialize bytes to a RateLimitProof.
  if data.len != RateLimitProofByteSize:
    return err("Invalid proof size: expected " & $RateLimitProofByteSize & ", got " & $data.len)

  var proof: RateLimitProof
  var offset = 0

  copyMem(addr proof.proof[0], unsafeAddr data[offset], ZksnarkProofByteSize)
  offset += ZksnarkProofByteSize

  copyMem(addr proof.merkleRoot[0], unsafeAddr data[offset], HashByteSize)
  offset += HashByteSize

  copyMem(addr proof.epoch[0], unsafeAddr data[offset], HashByteSize)
  offset += HashByteSize

  copyMem(addr proof.shareX[0], unsafeAddr data[offset], HashByteSize)
  offset += HashByteSize

  copyMem(addr proof.shareY[0], unsafeAddr data[offset], HashByteSize)
  offset += HashByteSize

  copyMem(addr proof.nullifier[0], unsafeAddr data[offset], HashByteSize)

  ok(proof)

proc serialize*(update: MembershipUpdate): seq[byte] =
  ## Serialize a MembershipUpdate to bytes.
  # Format: action(1) + idCommitment(32) + index(8) = 41 bytes
  result = newSeq[byte](41)
  result[0] = byte(ord(update.action))
  copyMem(addr result[1], unsafeAddr update.idCommitment[0], HashByteSize)
  # Index as little-endian
  let idx = update.index
  result[33] = byte(idx and 0xFF)
  result[34] = byte((idx shr 8) and 0xFF)
  result[35] = byte((idx shr 16) and 0xFF)
  result[36] = byte((idx shr 24) and 0xFF)
  result[37] = byte((idx shr 32) and 0xFF)
  result[38] = byte((idx shr 40) and 0xFF)
  result[39] = byte((idx shr 48) and 0xFF)
  result[40] = byte((idx shr 56) and 0xFF)

proc deserialize*(T: typedesc[MembershipUpdate], data: seq[byte]): RlnResult[MembershipUpdate] =
  ## Deserialize bytes to a MembershipUpdate.
  if data.len != 41:
    return err("Invalid membership update size: expected 41, got " & $data.len)

  var update: MembershipUpdate
  update.action = MembershipAction(data[0])
  copyMem(addr update.idCommitment[0], unsafeAddr data[1], HashByteSize)
  update.index = uint64(data[33]) or
                 (uint64(data[34]) shl 8) or
                 (uint64(data[35]) shl 16) or
                 (uint64(data[36]) shl 24) or
                 (uint64(data[37]) shl 32) or
                 (uint64(data[38]) shl 40) or
                 (uint64(data[39]) shl 48) or
                 (uint64(data[40]) shl 56)
  ok(update)

proc serialize*(broadcast: ProofMetadataBroadcast): seq[byte] =
  ## Serialize a ProofMetadataBroadcast to bytes.
  # Format: nullifier(32) + shareX(32) + shareY(32) + externalNullifier(32) + epoch(32) = 160 bytes
  result = newSeq[byte](160)
  var offset = 0
  copyMem(addr result[offset], unsafeAddr broadcast.nullifier[0], HashByteSize)
  offset += HashByteSize
  copyMem(addr result[offset], unsafeAddr broadcast.shareX[0], HashByteSize)
  offset += HashByteSize
  copyMem(addr result[offset], unsafeAddr broadcast.shareY[0], HashByteSize)
  offset += HashByteSize
  copyMem(addr result[offset], unsafeAddr broadcast.externalNullifier[0], HashByteSize)
  offset += HashByteSize
  copyMem(addr result[offset], unsafeAddr broadcast.epoch[0], HashByteSize)

proc deserialize*(T: typedesc[ProofMetadataBroadcast], data: seq[byte]): RlnResult[ProofMetadataBroadcast] =
  ## Deserialize bytes to a ProofMetadataBroadcast.
  if data.len != 160:
    return err("Invalid proof metadata size: expected 160, got " & $data.len)

  var broadcast: ProofMetadataBroadcast
  var offset = 0
  copyMem(addr broadcast.nullifier[0], unsafeAddr data[offset], HashByteSize)
  offset += HashByteSize
  copyMem(addr broadcast.shareX[0], unsafeAddr data[offset], HashByteSize)
  offset += HashByteSize
  copyMem(addr broadcast.shareY[0], unsafeAddr data[offset], HashByteSize)
  offset += HashByteSize
  copyMem(addr broadcast.externalNullifier[0], unsafeAddr data[offset], HashByteSize)
  offset += HashByteSize
  copyMem(addr broadcast.epoch[0], unsafeAddr data[offset], HashByteSize)
  ok(broadcast)

# Hex conversion utilities (shared across modules)

proc toHex*(data: openArray[byte]): string =
  ## Convert bytes to hex string.
  result = newStringOfCap(data.len * 2)
  const hexChars = "0123456789abcdef"
  for b in data:
    result.add(hexChars[int(b shr 4)])
    result.add(hexChars[int(b and 0x0F)])

proc fromHex*(hex: string): seq[byte] =
  ## Convert hex string to bytes. Returns empty seq on invalid input.
  if hex.len mod 2 != 0:
    return @[]

  result = newSeq[byte](hex.len div 2)
  for i in 0 ..< result.len:
    let hi = hex[i * 2]
    let lo = hex[i * 2 + 1]

    let hiVal =
      if hi >= '0' and hi <= '9': ord(hi) - ord('0')
      elif hi >= 'a' and hi <= 'f': ord(hi) - ord('a') + 10
      elif hi >= 'A' and hi <= 'F': ord(hi) - ord('A') + 10
      else: return @[]

    let loVal =
      if lo >= '0' and lo <= '9': ord(lo) - ord('0')
      elif lo >= 'a' and lo <= 'f': ord(lo) - ord('a') + 10
      elif lo >= 'A' and lo <= 'F': ord(lo) - ord('A') + 10
      else: return @[]

    result[i] = byte((hiVal shl 4) or loVal)
