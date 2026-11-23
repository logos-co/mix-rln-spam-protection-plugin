# Mix RLN Spam Protection Plugin
# Copyright (c) 2025 vacp2p
# Licensed under either of Apache License 2.0 or MIT license.

## Protobuf encoding and decoding for RLN spam protection types.
## Based on the mix-spam-protection-rln specification.
##
## Protobuf definitions:
##   message RateLimitProof {
##     bytes proof = 1;
##     bytes merkle_root = 2;
##     bytes epoch = 3;
##     bytes share_x = 4;
##     bytes share_y = 5;
##     bytes nullifier = 6;
##   }
##
##   message MembershipUpdate {
##     uint32 action = 1;
##     bytes id_commitment = 2;
##     uint64 user_message_limit = 3;
##     uint64 index = 4;
##   }

{.push raises: [].}

import ./protobuf
import ./types
import ./constants

type RateLimitProofPB {.proto3.} = object
  proof {.fieldNumber: 1.}: Opt[seq[byte]]
  merkleRoot {.fieldNumber: 2.}: Opt[seq[byte]]
  epoch {.fieldNumber: 3.}: Opt[seq[byte]]
  shareX {.fieldNumber: 4.}: Opt[seq[byte]]
  shareY {.fieldNumber: 5.}: Opt[seq[byte]]
  nullifier {.fieldNumber: 6.}: Opt[seq[byte]]

proc isCanonicalEpoch(epoch: openArray[byte]): bool =
  ## calcEpoch stores the epoch number in the first 8 bytes and zero-pads the
  ## rest, so a non-zero tail is a second encoding of the same epoch number.
  for i in Uint64ByteSize ..< HashByteSize:
    if epoch[i] != 0:
      return false
  true

proc copyBytesField[N: static int](
    field: Opt[seq[byte]], name: string, dest: var array[N, byte]
): ProtobufResult[void] =
  let bytes = field.valueOr:
    return err(ProtobufError.missingRequiredField(name))
  if bytes.len != N:
    return err(ProtobufError.invalidLengthField(name))
  copyMem(addr dest[0], unsafeAddr bytes[0], N)
  ok()
  
proc decodeRateLimitProofPB(buffer: seq[byte]): ProtobufResult[RateLimitProofPB] =
  try:
    ok(Protobuf.decode(buffer, RateLimitProofPB))
  except SerializationError as e:
    err(ProtobufError.decodeFailure(e.msg))
    
type MembershipUpdatePB {.proto3.} = object
  action {.fieldNumber: 1, pint.}: Opt[uint32]
  idCommitment {.fieldNumber: 2.}: Opt[seq[byte]]
  userMessageLimit {.fieldNumber: 3, pint.}: Opt[uint64]
  index {.fieldNumber: 4, pint.}: Opt[uint64]

type ProofMetadataBroadcastPB {.proto3.} = object
  nullifier {.fieldNumber: 1.}: Opt[seq[byte]]
  shareX {.fieldNumber: 2.}: Opt[seq[byte]]
  shareY {.fieldNumber: 3.}: Opt[seq[byte]]
  externalNullifier {.fieldNumber: 4.}: Opt[seq[byte]]
  epoch {.fieldNumber: 5.}: Opt[seq[byte]]

# RateLimitProof encoding/decoding

proc encode*(proof: RateLimitProof): seq[byte] =
  Protobuf.encode(
    RateLimitProofPB(
      proof: Opt.some(@(proof.proof)),
      merkleRoot: Opt.some(@(proof.merkleRoot)),
      epoch: Opt.some(@(proof.epoch)),
      shareX: Opt.some(@(proof.shareX)),
      shareY: Opt.some(@(proof.shareY)),
      nullifier: Opt.some(@(proof.nullifier)),
    )
  )

proc decode*(T: type RateLimitProof, buffer: seq[byte]): ProtobufResult[T] =
  let pb = ?decodeRateLimitProofPB(buffer)

  var proof: RateLimitProof
  ?pb.proof.copyBytesField("proof", proof.proof)
  ?pb.merkleRoot.copyBytesField("merkle_root", proof.merkleRoot)
  ?pb.epoch.copyBytesField("epoch", proof.epoch)
  if not isCanonicalEpoch(proof.epoch):
    return err(ProtobufError.invalidLengthField("epoch"))
  ?pb.shareX.copyBytesField("share_x", proof.shareX)
  ?pb.shareY.copyBytesField("share_y", proof.shareY)
  ?pb.nullifier.copyBytesField("nullifier", proof.nullifier)
  ok(proof)

# MembershipUpdate encoding/decoding
proc encode*(update: MembershipUpdate): seq[byte] =
  Protobuf.encode(
    MembershipUpdatePB(
      action: Opt.some(uint32(ord(update.action))),
      idCommitment: Opt.some(@(update.idCommitment)),
      userMessageLimit: Opt.some(update.userMessageLimit),
      index: Opt.some(update.index),
    )
  )

proc decodeMembershipUpdatePB(buffer: seq[byte]): ProtobufResult[MembershipUpdatePB] =
  try:
    ok(Protobuf.decode(buffer, MembershipUpdatePB))
  except SerializationError as e:
    err(ProtobufError.decodeFailure(e.msg))

proc decode*(T: type MembershipUpdate, buffer: seq[byte]): ProtobufResult[T] =
  let pb = ?decodeMembershipUpdatePB(buffer)

  var update: MembershipUpdate
  let action = pb.action.valueOr:
    return err(ProtobufError.missingRequiredField("action"))
  if action > 1:
    return err(ProtobufError.invalidLengthField("action"))
  update.action = MembershipAction(action)

  ?pb.idCommitment.copyBytesField("id_commitment", update.idCommitment)

  update.userMessageLimit = pb.userMessageLimit.valueOr:
    return err(ProtobufError.missingRequiredField("user_message_limit"))

  update.index = pb.index.valueOr:
    return err(ProtobufError.missingRequiredField("index"))
  if update.index >= MerkleTreeCapacity:
    return err(ProtobufError.invalidLengthField("index"))

  ok(update)

# ProofMetadataBroadcast encoding/decoding
# Note: This maps to a simplified version for backward compatibility

proc encode*(broadcast: ProofMetadataBroadcast): seq[byte] =
  Protobuf.encode(
    ProofMetadataBroadcastPB(
      nullifier: Opt.some(@(broadcast.nullifier)),
      shareX: Opt.some(@(broadcast.shareX)),
      shareY: Opt.some(@(broadcast.shareY)),
      externalNullifier: Opt.some(@(broadcast.externalNullifier)),
      epoch: Opt.some(@(broadcast.epoch)),
    )
  )

proc decodeProofMetadataBroadcastPB(
    buffer: seq[byte]
): ProtobufResult[ProofMetadataBroadcastPB] =
  try:
    ok(Protobuf.decode(buffer, ProofMetadataBroadcastPB))
  except SerializationError as e:
    err(ProtobufError.decodeFailure(e.msg))

proc decode*(T: type ProofMetadataBroadcast, buffer: seq[byte]): ProtobufResult[T] =
  let pb = ?decodeProofMetadataBroadcastPB(buffer)

  var broadcast: ProofMetadataBroadcast
  ?pb.nullifier.copyBytesField("nullifier", broadcast.nullifier)
  ?pb.shareX.copyBytesField("share_x", broadcast.shareX)
  ?pb.shareY.copyBytesField("share_y", broadcast.shareY)
  ?pb.externalNullifier.copyBytesField(
    "external_nullifier", broadcast.externalNullifier
  )
  ?pb.epoch.copyBytesField("epoch", broadcast.epoch)
  if not isCanonicalEpoch(broadcast.epoch):
    return err(ProtobufError.invalidLengthField("epoch"))

  ok(broadcast)

# Convenience functions for serialization to/from seq[byte]

proc toBytes*(proof: RateLimitProof): seq[byte] =
  ## Serialize a RateLimitProof to bytes using protobuf.
  proof.encode()

proc toBytes*(update: MembershipUpdate): seq[byte] =
  ## Serialize a MembershipUpdate to bytes using protobuf.
  update.encode()

proc toBytes*(broadcast: ProofMetadataBroadcast): seq[byte] =
  ## Serialize a ProofMetadataBroadcast to bytes using protobuf.
  broadcast.encode()
