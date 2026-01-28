# Mix RLN Spam Protection Plugin
# Copyright (c) 2025 vacp2p
# Licensed under either of Apache License 2.0 or MIT license.

## Core type definitions for the RLN spam protection plugin.

import std/times
import chronos
import results
import ./constants
import ./bytes_utils

export bytes_utils

type
  # Cryptographic primitives (fixed-size byte arrays)
  MerkleNode* = array[HashByteSize, byte]
    ## 32-byte Poseidon hash used in Merkle tree nodes.

  Nullifier* = array[HashByteSize, byte]
    ## 32-byte nullifier derived from epoch and member's secret key.

  Epoch* = array[HashByteSize, byte] ## 32-byte epoch value representing a time window.

  RlnIdentifier* = array[HashByteSize, byte]
    ## 32-byte application-specific RLN identifier.

  ExternalNullifier* = array[HashByteSize, byte]
    ## 32-byte external nullifier: Poseidon(epoch, rln_identifier).

  ShareX* = array[HashByteSize, byte] ## 32-byte Shamir secret share X coordinate.

  ShareY* = array[HashByteSize, byte] ## 32-byte Shamir secret share Y coordinate.

  IDCommitment* = array[HashByteSize, byte]
    ## 32-byte identity commitment: Poseidon(identity_secret).

  IDSecretHash* = array[HashByteSize, byte]
    ## 32-byte identity secret hash (the actual secret key).

  IDTrapdoor* = array[HashByteSize, byte]
    ## 32-byte identity trapdoor (component of credential).

  IDNullifier* = array[HashByteSize, byte]
    ## 32-byte identity nullifier (component of credential).

  ZkProof* = array[ZksnarkProofByteSize, byte] ## 128-byte compressed zkSNARK proof.

  MembershipIndex* = uint64 ## Index of a member in the Merkle tree (0-based).

  # Identity and credentials
  IdentityCredential* = object ## Complete identity credential for an RLN member.
    idTrapdoor*: IDTrapdoor
    idNullifier*: IDNullifier
    idSecretHash*: IDSecretHash
    idCommitment*: IDCommitment

  # Rate limit proof structure (as per RFC)
  RateLimitProof* = object
    ## Complete RLN proof attached to messages.
    ## Note: rlnIdentifier is NOT included as it's a network-wide constant
    ## and can be derived from configuration.
    proof*: ZkProof ## 128 bytes: zkSNARK proof
    merkleRoot*: MerkleNode ## 32 bytes: Merkle tree root used for proof
    epoch*: Epoch ## 32 bytes: epoch when proof was generated
    shareX*: ShareX ## 32 bytes: Shamir share X
    shareY*: ShareY ## 32 bytes: Shamir share Y
    nullifier*: Nullifier ## 32 bytes: message nullifier

  # Proof metadata for spam detection
  ProofMetadata* = object ## Extracted metadata from a proof for spam detection.
    nullifier*: Nullifier
    shareX*: ShareX
    shareY*: ShareY
    externalNullifier*: ExternalNullifier

  # Message validation result
  MessageValidationResult* = enum
    ## Result of validating a message's RLN proof.
    Valid ## Proof is valid and message should be processed
    Invalid ## Proof is invalid (wrong proof, bad epoch, etc.)
    Spam ## Spam detected (double signaling)
    Duplicate ## Duplicate message (same proof seen before)

  # Membership update actions
  MembershipAction* = enum
    ## Action type for membership updates.
    Add
    Remove

  # Membership update message (for coordination layer)
  MembershipUpdate* = object ## Message broadcast on membership content topic.
    action*: MembershipAction
    idCommitment*: IDCommitment
    index*: MembershipIndex

  # Proof metadata broadcast message (for coordination layer)
  ProofMetadataBroadcast* = object ## Message broadcast on proof metadata content topic.
    nullifier*: Nullifier
    shareX*: ShareX
    shareY*: ShareY
    externalNullifier*: ExternalNullifier
    epoch*: Epoch

  # Callback types for coordination layer integration
  PublishCallback* =
    proc(contentTopic: string, data: seq[byte]): Future[void] {.gcsafe, raises: [].}
    ## Callback for publishing messages to logos-messaging.

  # RLN Witness input for explicit Merkle proof-based proof generation
  Field* = array[32, byte] ## 32-byte field element representation (256 bits).

  RLNWitnessInput* = object
    ## Input structure for generate_proof_with_witness FFI.
    ## Contains explicit Merkle proof instead of relying on zerokit's internal cache.
    identity_secret*: Field
    user_message_limit*: Field
    message_id*: Field
    path_elements*: seq[byte] ## Concatenated 32-byte Merkle path elements
    identity_path_index*: seq[byte] ## Bit path (LSB-first) through Merkle tree
    x*: Field ## Keccak256 hash of the signal
    external_nullifier*: Field

  # Spam handler callback
  SpamHandler* = proc(
    proof: RateLimitProof, recoveredSecret: IDSecretHash, memberIndex: MembershipIndex
  ): Future[void] {.gcsafe, raises: [].}
    ## Handler called when spam is detected.
    ## Receives the offending proof, recovered secret key, and member index.

  # Result types
  RlnResult*[T] = Result[T, string] ## Generic result type for RLN operations.

  # Plugin state
  PluginState* = enum
    ## State of the spam protection plugin.
    Uninitialized ## Plugin created but not started
    Syncing ## Waiting for initial membership sync
    Ready ## Plugin is ready for proof generation/verification
    Stopped ## Plugin has been stopped

# =============================================================================
# Epoch Calculation
# =============================================================================
#
# Epochs are 32-byte arrays with the epoch number stored in the first 8 bytes
# as little-endian uint64. The remaining 24 bytes are zero-padded.

proc calcEpoch*(timestamp: float64): Epoch =
  ## Calculate the epoch for a given Unix timestamp.
  ## Epoch number = floor(timestamp / EpochDurationSeconds)
  let epochNum = uint64(timestamp / EpochDurationSeconds)
  result = default(Epoch)
  # Store epoch number in first 8 bytes as little-endian
  let epochBytes = epochNum.toBytesLE()
  for i in 0 ..< Uint64ByteSize:
    result[i] = epochBytes[i]

proc calcEpoch*(t: Time): Epoch =
  ## Calculate the epoch for a given Time.
  calcEpoch(t.toUnixFloat())

proc currentEpoch*(): Epoch =
  ## Get the current epoch based on system time.
  calcEpoch(getTime())

proc epochToUint64*(epoch: Epoch): uint64 =
  ## Convert an epoch to its numeric value (reads first 8 bytes as little-endian).
  fromBytesLE(epoch)

proc epochDiff*(e1, e2: Epoch): int64 =
  ## Calculate the difference between two epochs.
  int64(epochToUint64(e1)) - int64(epochToUint64(e2))

proc isEpochValid*(msgEpoch: Epoch, currentEpoch: Epoch): bool =
  ## Check if a message epoch is within the acceptable gap.
  let diff = abs(epochDiff(currentEpoch, msgEpoch))
  diff <= MaxEpochGap

# =============================================================================
# Hex Conversion Utilities
# =============================================================================
# Note: toHex is also available from bytes_utils, but we keep this for
# backwards compatibility and explicit typing with openArray[byte].

proc toHex*(data: openArray[byte]): string =
  ## Convert bytes to lowercase hex string.
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
      if hi >= '0' and hi <= '9':
        ord(hi) - ord('0')
      elif hi >= 'a' and hi <= 'f':
        ord(hi) - ord('a') + 10
      elif hi >= 'A' and hi <= 'F':
        ord(hi) - ord('A') + 10
      else:
        return @[]

    let loVal =
      if lo >= '0' and lo <= '9':
        ord(lo) - ord('0')
      elif lo >= 'a' and lo <= 'f':
        ord(lo) - ord('a') + 10
      elif lo >= 'A' and lo <= 'F':
        ord(lo) - ord('A') + 10
      else:
        return @[]

    result[i] = byte((hiVal shl 4) or loVal)

# =============================================================================
# Field Element Utilities (for witness-based proof generation)
# =============================================================================
#
# Field elements are 32-byte arrays representing values in the BN254 scalar field.
# Values are stored in little-endian format with zero-padding for unused bytes.

proc uint64ToField*(n: uint64): Field =
  ## Convert a uint64 to a 32-byte field element.
  ## The uint64 is stored in the first 8 bytes (little-endian), rest is zero.
  var output: Field
  let bytes = n.toBytesLE()
  for i in 0 ..< Uint64ByteSize:
    output[i] = bytes[i]
  # Remaining bytes are already zero (default)
  return output

proc seqToField*(s: openArray[byte]): Field =
  ## Convert a byte sequence to a 32-byte field element.
  ## Copies up to 32 bytes; pads with zeros if input is shorter.
  var output: Field
  let copyLen = min(s.len, 32)
  for i in 0 ..< copyLen:
    output[i] = s[i]
  return output
