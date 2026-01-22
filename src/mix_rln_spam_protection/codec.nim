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
##   message ExternalNullifier {
##     bytes internal_nullifier = 1;
##     repeated bytes x_shares = 2;
##     repeated bytes y_shares = 3;
##   }
##
##   message MessagingMetadata {
##     repeated ExternalNullifier nullifiers = 1;
##   }
##
##   message MembershipUpdate {
##     uint32 action = 1;
##     bytes id_commitment = 2;
##     uint64 index = 3;
##   }

{.push raises: [].}

import ./protobuf
import ./types
import ./constants

# RateLimitProof encoding/decoding

proc encode*(proof: RateLimitProof): ProtoBuffer =
  ## Encode a RateLimitProof to protobuf.
  var buf = initProtoBuffer()

  buf.write3(1, @(proof.proof))        # proof: 128 bytes
  buf.write3(2, @(proof.merkleRoot))   # merkle_root: 32 bytes
  buf.write3(3, @(proof.epoch))        # epoch: 32 bytes
  buf.write3(4, @(proof.shareX))       # share_x: 32 bytes
  buf.write3(5, @(proof.shareY))       # share_y: 32 bytes
  buf.write3(6, @(proof.nullifier))    # nullifier: 32 bytes
  buf.finish3()

  buf

proc decode*(T: type RateLimitProof, buffer: seq[byte]): ProtobufResult[T] =
  ## Decode protobuf bytes to a RateLimitProof.
  var proof: RateLimitProof
  let pb = initProtoBuffer(buffer)

  var proofBytes: seq[byte]
  if not ?pb.getField(1, proofBytes):
    return err(ProtobufError.missingRequiredField("proof"))
  if proofBytes.len != ZksnarkProofByteSize:
    return err(ProtobufError.invalidLengthField("proof"))
  copyMem(addr proof.proof[0], addr proofBytes[0], ZksnarkProofByteSize)

  var merkleRoot: seq[byte]
  if not ?pb.getField(2, merkleRoot):
    return err(ProtobufError.missingRequiredField("merkle_root"))
  if merkleRoot.len != HashByteSize:
    return err(ProtobufError.invalidLengthField("merkle_root"))
  copyMem(addr proof.merkleRoot[0], addr merkleRoot[0], HashByteSize)

  var epoch: seq[byte]
  if not ?pb.getField(3, epoch):
    return err(ProtobufError.missingRequiredField("epoch"))
  if epoch.len != HashByteSize:
    return err(ProtobufError.invalidLengthField("epoch"))
  copyMem(addr proof.epoch[0], addr epoch[0], HashByteSize)

  var shareX: seq[byte]
  if not ?pb.getField(4, shareX):
    return err(ProtobufError.missingRequiredField("share_x"))
  if shareX.len != HashByteSize:
    return err(ProtobufError.invalidLengthField("share_x"))
  copyMem(addr proof.shareX[0], addr shareX[0], HashByteSize)

  var shareY: seq[byte]
  if not ?pb.getField(5, shareY):
    return err(ProtobufError.missingRequiredField("share_y"))
  if shareY.len != HashByteSize:
    return err(ProtobufError.invalidLengthField("share_y"))
  copyMem(addr proof.shareY[0], addr shareY[0], HashByteSize)

  var nullifier: seq[byte]
  if not ?pb.getField(6, nullifier):
    return err(ProtobufError.missingRequiredField("nullifier"))
  if nullifier.len != HashByteSize:
    return err(ProtobufError.invalidLengthField("nullifier"))
  copyMem(addr proof.nullifier[0], addr nullifier[0], HashByteSize)

  ok(proof)

# ExternalNullifier encoding/decoding (for MessagingMetadata)

type
  ExternalNullifierProto* = object
    ## Protobuf representation matching spec's ExternalNullifier message.
    ## Used for broadcasting proof metadata across the coordination layer.
    internalNullifier*: Nullifier
    xShares*: seq[ShareX]
    yShares*: seq[ShareY]

proc encode*(extNull: ExternalNullifierProto): ProtoBuffer =
  ## Encode an ExternalNullifierProto to protobuf.
  var buf = initProtoBuffer()

  buf.write3(1, @(extNull.internalNullifier))
  for x in extNull.xShares:
    buf.write3(2, @x)
  for y in extNull.yShares:
    buf.write3(3, @y)
  buf.finish3()

  buf

proc decode*(T: type ExternalNullifierProto, buffer: seq[byte]): ProtobufResult[T] =
  ## Decode protobuf bytes to an ExternalNullifierProto.
  var extNull: ExternalNullifierProto
  let pb = initProtoBuffer(buffer)

  var internalNullifier: seq[byte]
  if not ?pb.getField(1, internalNullifier):
    return err(ProtobufError.missingRequiredField("internal_nullifier"))
  if internalNullifier.len != HashByteSize:
    return err(ProtobufError.invalidLengthField("internal_nullifier"))
  copyMem(addr extNull.internalNullifier[0], addr internalNullifier[0], HashByteSize)

  # Get repeated x_shares
  var xSharesBytes: seq[seq[byte]]
  discard ?pb.getRepeatedField(2, xSharesBytes)
  for xBytes in xSharesBytes:
    if xBytes.len != HashByteSize:
      return err(ProtobufError.invalidLengthField("x_shares"))
    var x: ShareX
    copyMem(addr x[0], unsafeAddr xBytes[0], HashByteSize)
    extNull.xShares.add(x)

  # Get repeated y_shares
  var ySharesBytes: seq[seq[byte]]
  discard ?pb.getRepeatedField(3, ySharesBytes)
  for yBytes in ySharesBytes:
    if yBytes.len != HashByteSize:
      return err(ProtobufError.invalidLengthField("y_shares"))
    var y: ShareY
    copyMem(addr y[0], unsafeAddr yBytes[0], HashByteSize)
    extNull.yShares.add(y)

  ok(extNull)

# MessagingMetadata encoding/decoding

type
  MessagingMetadata* = object
    ## Protobuf representation matching spec's MessagingMetadata message.
    ## Wrapper message collecting multiple external nullifiers for broadcast.
    nullifiers*: seq[ExternalNullifierProto]

proc encode*(meta: MessagingMetadata): ProtoBuffer =
  ## Encode a MessagingMetadata to protobuf.
  var buf = initProtoBuffer()

  for nullifier in meta.nullifiers:
    buf.write3(1, nullifier.encode().buffer)
  buf.finish3()

  buf

proc decode*(T: type MessagingMetadata, buffer: seq[byte]): ProtobufResult[T] =
  ## Decode protobuf bytes to a MessagingMetadata.
  var meta: MessagingMetadata
  let pb = initProtoBuffer(buffer)

  var nullifierBuffers: seq[seq[byte]]
  discard ?pb.getRepeatedField(1, nullifierBuffers)
  for nullifierBuf in nullifierBuffers:
    let nullifier = ?ExternalNullifierProto.decode(nullifierBuf)
    meta.nullifiers.add(nullifier)

  ok(meta)

# MembershipUpdate encoding/decoding

proc encode*(update: MembershipUpdate): ProtoBuffer =
  ## Encode a MembershipUpdate to protobuf.
  var buf = initProtoBuffer()

  buf.write3(1, uint32(ord(update.action)))
  buf.write3(2, @(update.idCommitment))
  buf.write3(3, update.index)
  buf.finish3()

  buf

proc decode*(T: type MembershipUpdate, buffer: seq[byte]): ProtobufResult[T] =
  ## Decode protobuf bytes to a MembershipUpdate.
  var update: MembershipUpdate
  let pb = initProtoBuffer(buffer)

  var action: uint32
  if not ?pb.getField(1, action):
    return err(ProtobufError.missingRequiredField("action"))
  if action > 1:
    return err(ProtobufError.invalidLengthField("action"))
  update.action = MembershipAction(action)

  var idCommitment: seq[byte]
  if not ?pb.getField(2, idCommitment):
    return err(ProtobufError.missingRequiredField("id_commitment"))
  if idCommitment.len != HashByteSize:
    return err(ProtobufError.invalidLengthField("id_commitment"))
  copyMem(addr update.idCommitment[0], addr idCommitment[0], HashByteSize)

  var index: uint64
  if not ?pb.getField(3, index):
    return err(ProtobufError.missingRequiredField("index"))
  update.index = index

  ok(update)

# ProofMetadataBroadcast encoding/decoding
# Note: This maps to a simplified version for backward compatibility

proc encode*(broadcast: ProofMetadataBroadcast): ProtoBuffer =
  ## Encode a ProofMetadataBroadcast to protobuf.
  ## Uses a flat structure for single proof metadata broadcast.
  var buf = initProtoBuffer()

  buf.write3(1, @(broadcast.nullifier))
  buf.write3(2, @(broadcast.shareX))
  buf.write3(3, @(broadcast.shareY))
  buf.write3(4, @(broadcast.externalNullifier))
  buf.write3(5, @(broadcast.epoch))
  buf.finish3()

  buf

proc decode*(T: type ProofMetadataBroadcast, buffer: seq[byte]): ProtobufResult[T] =
  ## Decode protobuf bytes to a ProofMetadataBroadcast.
  var broadcast: ProofMetadataBroadcast
  let pb = initProtoBuffer(buffer)

  var nullifier: seq[byte]
  if not ?pb.getField(1, nullifier):
    return err(ProtobufError.missingRequiredField("nullifier"))
  if nullifier.len != HashByteSize:
    return err(ProtobufError.invalidLengthField("nullifier"))
  copyMem(addr broadcast.nullifier[0], addr nullifier[0], HashByteSize)

  var shareX: seq[byte]
  if not ?pb.getField(2, shareX):
    return err(ProtobufError.missingRequiredField("share_x"))
  if shareX.len != HashByteSize:
    return err(ProtobufError.invalidLengthField("share_x"))
  copyMem(addr broadcast.shareX[0], addr shareX[0], HashByteSize)

  var shareY: seq[byte]
  if not ?pb.getField(3, shareY):
    return err(ProtobufError.missingRequiredField("share_y"))
  if shareY.len != HashByteSize:
    return err(ProtobufError.invalidLengthField("share_y"))
  copyMem(addr broadcast.shareY[0], addr shareY[0], HashByteSize)

  var externalNullifier: seq[byte]
  if not ?pb.getField(4, externalNullifier):
    return err(ProtobufError.missingRequiredField("external_nullifier"))
  if externalNullifier.len != HashByteSize:
    return err(ProtobufError.invalidLengthField("external_nullifier"))
  copyMem(addr broadcast.externalNullifier[0], addr externalNullifier[0], HashByteSize)

  var epoch: seq[byte]
  if not ?pb.getField(5, epoch):
    return err(ProtobufError.missingRequiredField("epoch"))
  if epoch.len != HashByteSize:
    return err(ProtobufError.invalidLengthField("epoch"))
  copyMem(addr broadcast.epoch[0], addr epoch[0], HashByteSize)

  ok(broadcast)

# Convenience functions for serialization to/from seq[byte]

proc toBytes*(proof: RateLimitProof): seq[byte] =
  ## Serialize a RateLimitProof to bytes using protobuf.
  proof.encode().buffer

proc toBytes*(update: MembershipUpdate): seq[byte] =
  ## Serialize a MembershipUpdate to bytes using protobuf.
  update.encode().buffer

proc toBytes*(broadcast: ProofMetadataBroadcast): seq[byte] =
  ## Serialize a ProofMetadataBroadcast to bytes using protobuf.
  broadcast.encode().buffer

proc toBytes*(meta: MessagingMetadata): seq[byte] =
  ## Serialize a MessagingMetadata to bytes using protobuf.
  meta.encode().buffer
