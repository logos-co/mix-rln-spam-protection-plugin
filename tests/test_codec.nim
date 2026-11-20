# Mix RLN Spam Protection Plugin - Tests
# Copyright (c) 2025 vacp2p
# Licensed under either of Apache License 2.0 or MIT license.

## Pins the protobuf wire encoding of every message in `codec`.
##
## Nodes that are already deployed exchange these messages, so the encoded
## bytes must stay the same whichever protobuf implementation the codec uses.
## The expected bytes were captured from the codec built on the `minprotobuf`
## module of libp2p v2.4.2. Each field starts a new string literal: its tag, its
## length prefix when it has one, and its value.

from std/strutils import repeat
import unittest2, results
import ../src/mix_rln_spam_protection/[codec, types, constants]

const
  ZeroHash = "00".repeat(HashByteSize)

  RateLimitProofHex =
    "0a8001000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f" &
    "202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f" &
    "404142434445464748494a4b4c4d4e4f505152535455565758595a5b5c5d5e5f" &
    "606162636465666768696a6b6c6d6e6f707172737475767778797a7b7c7d7e7f" &
    "1220808182838485868788898a8b8c8d8e8f909192939495969798999a9b9c9d9e9f" &
    "1a20f8f9fafbfcfdfeff000000000000000000000000000000000000000000000000" &
    "2220a0a1a2a3a4a5a6a7a8a9aaabacadaeafb0b1b2b3b4b5b6b7b8b9babbbcbdbebf" &
    "2a20c0c1c2c3c4c5c6c7c8c9cacbcccdcecfd0d1d2d3d4d5d6d7d8d9dadbdcdddedf" &
    "3220e0e1e2e3e4e5e6e7e8e9eaebecedeeeff0f1f2f3f4f5f6f7f8f9fafbfcfdfeff"

  ZeroRateLimitProofHex =
    "0a8001" & "00".repeat(ZksnarkProofByteSize) & "1220" & ZeroHash & "1a20" & ZeroHash &
    "2220" & ZeroHash & "2a20" & ZeroHash & "3220" & ZeroHash

  MembershipAddHex =
    "0800" & "1220000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f" &
    "1864" & "20b960"

  MembershipRemoveHex =
    "0801" & "1220fffefdfcfbfaf9f8f7f6f5f4f3f2f1f0efeeedecebeae9e8e7e6e5e4e3e2e1e0" &
    "18ffffffffffffffffff01" & "20ffff3f"

  # Zero-valued scalar fields are written, not omitted as proto3 defaults.
  ZeroMembershipUpdateHex = "0800" & "1220" & ZeroHash & "1800" & "2000"

  ProofMetadataBroadcastHex =
    "0a20000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f" &
    "1220202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f" &
    "1a20404142434445464748494a4b4c4d4e4f505152535455565758595a5b5c5d5e5f" &
    "2220606162636465666768696a6b6c6d6e6f707172737475767778797a7b7c7d7e7f" &
    "2a20f8f9fafbfcfdfeff000000000000000000000000000000000000000000000000"

  ZeroProofMetadataBroadcastHex =
    "0a20" & ZeroHash & "1220" & ZeroHash & "1a20" & ZeroHash & "2220" & ZeroHash &
    "2a20" & ZeroHash

template checkWireFormat(value: typed, expectedHex: string) =
  ## Encoding gives exactly the pinned bytes, and the pinned bytes decode back
  ## to the same value.
  let expected = fromHex(expectedHex)
  check expected.len > 0
  check value.toBytes() == expected
  check value.encode().buffer == expected
  let decoded = typeof(value).decode(expected)
  check decoded.isOk()
  check decoded.get() == value

suite "Codec wire format":
  test "RateLimitProof":
    var proof: RateLimitProof
    for i in 0 ..< ZksnarkProofByteSize:
      proof.proof[i] = byte(i)
    for i in 0 ..< HashByteSize:
      proof.merkleRoot[i] = byte(0x80 + i)
      proof.shareX[i] = byte(0xa0 + i)
      proof.shareY[i] = byte(0xc0 + i)
      proof.nullifier[i] = byte(0xe0 + i)
    # Epoch number lives in the low 8 bytes; the tail stays zero-padded.
    for i in 0 ..< Uint64ByteSize:
      proof.epoch[i] = byte(0xf8 + i)

    checkWireFormat(proof, RateLimitProofHex)
    check proof.toBytes().len == RateLimitProofByteSize

  test "RateLimitProof with all fields zero":
    checkWireFormat(RateLimitProof(), ZeroRateLimitProofHex)

  test "MembershipUpdate adding a member":
    var update = MembershipUpdate(
      action: MembershipAction.Add, userMessageLimit: 100, index: 12345
    )
    for i in 0 ..< HashByteSize:
      update.idCommitment[i] = byte(i)

    checkWireFormat(update, MembershipAddHex)

  test "MembershipUpdate removing a member, largest varints":
    var update = MembershipUpdate(
      action: MembershipAction.Remove,
      userMessageLimit: high(uint64),
      index: MerkleTreeCapacity - 1,
    )
    for i in 0 ..< HashByteSize:
      update.idCommitment[i] = byte(0xff - i)

    checkWireFormat(update, MembershipRemoveHex)

  test "MembershipUpdate with all fields zero":
    checkWireFormat(MembershipUpdate(), ZeroMembershipUpdateHex)

  test "ProofMetadataBroadcast":
    var broadcast: ProofMetadataBroadcast
    for i in 0 ..< HashByteSize:
      broadcast.nullifier[i] = byte(i)
      broadcast.shareX[i] = byte(0x20 + i)
      broadcast.shareY[i] = byte(0x40 + i)
      broadcast.externalNullifier[i] = byte(0x60 + i)
    # Epoch number lives in the low 8 bytes; the tail stays zero-padded.
    for i in 0 ..< Uint64ByteSize:
      broadcast.epoch[i] = byte(0xf8 + i)

    checkWireFormat(broadcast, ProofMetadataBroadcastHex)

  test "ProofMetadataBroadcast with all fields zero":
    checkWireFormat(ProofMetadataBroadcast(), ZeroProofMetadataBroadcastHex)
