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
##
##   message ProofMetadataEntry {
##     bytes nullifier = 1;
##     bytes share_x = 2;
##     bytes share_y = 3;
##     bytes external_nullifier = 4;
##     bytes epoch = 5;
##   }
##
##   message ProofMetadataBatch {
##     repeated ProofMetadataEntry entries = 1;
##   }
##
## ProofMetadataEntry is the flat ProofMetadataBroadcast encoding. A publisher
## sends either one batch or one bare entry. Decoders accept either.

{.push raises: [].}

import ./protobuf
import ./types
import ./constants

proc isCanonicalEpoch(epoch: openArray[byte]): bool =
  ## calcEpoch stores the epoch number in the first 8 bytes and zero-pads the
  ## rest, so a non-zero tail is a second encoding of the same epoch number.
  for i in Uint64ByteSize ..< HashByteSize:
    if epoch[i] != 0:
      return false
  true

# RateLimitProof encoding/decoding

proc encode*(proof: RateLimitProof): ProtoBuffer =
  ## Encode a RateLimitProof to protobuf.
  var buf = initProtoBuffer()

  buf.write3(1, @(proof.proof)) # proof: 128 bytes
  buf.write3(2, @(proof.merkleRoot)) # merkle_root: 32 bytes
  buf.write3(3, @(proof.epoch)) # epoch: 32 bytes
  buf.write3(4, @(proof.shareX)) # share_x: 32 bytes
  buf.write3(5, @(proof.shareY)) # share_y: 32 bytes
  buf.write3(6, @(proof.nullifier)) # nullifier: 32 bytes
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
  if not isCanonicalEpoch(epoch):
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

# MembershipUpdate encoding/decoding

proc encode*(update: MembershipUpdate): ProtoBuffer =
  ## Encode a MembershipUpdate to protobuf.
  var buf = initProtoBuffer()

  buf.write3(1, uint32(ord(update.action)))
  buf.write3(2, @(update.idCommitment))
  buf.write3(3, update.userMessageLimit)
  buf.write3(4, update.index)
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

  var userMessageLimit: uint64
  if not ?pb.getField(3, userMessageLimit):
    return err(ProtobufError.missingRequiredField("user_message_limit"))
  update.userMessageLimit = userMessageLimit

  var index: uint64
  if not ?pb.getField(4, index):
    return err(ProtobufError.missingRequiredField("index"))
  if index >= MerkleTreeCapacity:
    return err(ProtobufError.invalidLengthField("index"))
  update.index = index

  ok(update)

# ProofMetadataBroadcast encoding/decoding
# One entry. A batch is a repeated list of these encodings.

proc encode*(broadcast: ProofMetadataBroadcast): ProtoBuffer =
  ## Encode one proof-metadata entry to protobuf.
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
  if not isCanonicalEpoch(epoch):
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
  ## Serialize one proof-metadata entry to bytes using protobuf.
  broadcast.encode().buffer

type DecodedMetadata* = object
  entries*: seq[ProofMetadataBroadcast]
  malformed*: int ## Entry blobs inside a batch that did not decode.

proc encode*(batch: ProofMetadataBatch): ProtoBuffer =
  ## Encode a batch as repeated ProofMetadataEntry messages.
  var buf = initProtoBuffer()
  for entry in batch.entries:
    buf.write3(1, entry.toBytes())
  buf.finish3()
  buf

proc toBytes*(batch: ProofMetadataBatch): seq[byte] =
  ## Serialize a proof-metadata batch to bytes using protobuf.
  batch.encode().buffer

proc decodeMetadata*(data: seq[byte]): ProtobufResult[DecodedMetadata] =
  ## Decode a legacy single entry or a batch of entries.
  ## A batch with a bad entry yields that entry in `malformed` and still
  ## returns the entries that decoded. A broken legacy frame is an error.
  let single = ProofMetadataBroadcast.decode(data)
  if single.isOk:
    return ok(DecodedMetadata(entries: @[single.get()]))

  var raw: seq[seq[byte]]
  let found = initProtoBuffer(data).getRepeatedField(1, raw)
  if found.isErr:
    return err(found.error)
  if not found.get():
    return err(ProtobufError.missingRequiredField("entries"))

  # Legacy frames carry share_x at the top level. A batch does not.
  var topLevelShare: seq[byte]
  let shareField = initProtoBuffer(data).getField(2, topLevelShare)
  if shareField.isErr:
    return err(shareField.error)
  if shareField.get():
    return err(ProtobufError.invalidLengthField("proof_metadata"))

  var decoded = DecodedMetadata()
  for blob in raw:
    let entry = ProofMetadataBroadcast.decode(blob)
    if entry.isOk:
      decoded.entries.add(entry.get())
    else:
      inc decoded.malformed
  ok(decoded)
