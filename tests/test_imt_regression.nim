# Mix RLN Spam Protection Plugin - Tests
# Copyright (c) 2025 vacp2p
# Licensed under either of Apache License 2.0 or MIT license.

## Regression test for the Nim `IncrementalMerkleTree`.
##
## Replays the deterministic op sequence in `tests/fixtures/imt_regression.json`
## through the IMT and asserts byte-identical roots, proofs, leaf readbacks,
## and `insertLeaf`-returned indices at every step.  The fixture is generated
## by `tests/tools/regenerate_imt_fixture.nim`; regenerate it only after a
## deliberate IMT change.
##
## Build/run:
##   nim c -r --passL:<librln>.a --passL:-lm tests/test_imt_regression.nim
##
## librln is required for Poseidon (`poseidonPairLe`); the stateless
## librln archive is sufficient.

import std/[json, strformat, strutils]
import results
import std/unittest

import ../src/mix_rln_spam_protection/merkle_tree
import ../src/mix_rln_spam_protection/rln_interface
import ../src/mix_rln_spam_protection/types
import ../src/mix_rln_spam_protection/constants

const FixturePath = "tests/fixtures/imt_regression.json"

proc hexToBytes(hex: string): seq[byte] =
  doAssert hex.len mod 2 == 0, "odd hex length: " & $hex.len
  result = newSeq[byte](hex.len div 2)
  for i in 0 ..< result.len:
    result[i] = byte(parseHexInt(hex[i * 2 .. i * 2 + 1]))

proc toMerkleNode(hex: string): MerkleNode =
  let bytes = hexToBytes(hex)
  doAssert bytes.len == 32, "expected 32 bytes, got " & $bytes.len
  for i in 0 ..< 32:
    result[i] = bytes[i]

proc poseidonHash(a, b: MerkleNode): MerkleNode {.gcsafe, raises: [].} =
  let r = poseidonPairLe(a, b)
  if r.isErr:
    raiseAssert "poseidonPairLe failed: " & r.error
  r.get()

suite "IMT regression: byte-identical replay of fixture":
  test "replay fixture, assert byte-identical output at every step":
    let fixtureText = readFile(FixturePath)
    let fixture = parseJson(fixtureText)
    let depth = fixture["depth"].getInt
    let ops = fixture["ops"]
    check depth == MerkleTreeDepth
    check fixture["hashByteSize"].getInt == HashByteSize
    var tree = IncrementalMerkleTree.init(depth, poseidonHash)

    var opIdx = 0
    for op in ops:
      let kind = op["op"].getStr
      case kind
      of "insertMember":
        let leaf = toMerkleNode(op["leaf_hex"].getStr)
        let idxRes = tree.insertLeaf(leaf)
        check idxRes.isOk
        let returnedIdx = int(idxRes.get())
        let expectedIdx = op["returned_index"].getInt
        check returnedIdx == expectedIdx
        if returnedIdx != expectedIdx:
          checkpoint &"op[{opIdx}] insertMember: got idx {returnedIdx}, expected {expectedIdx}"
      of "insertMemberAt":
        let leaf = toMerkleNode(op["leaf_hex"].getStr)
        let idx = uint64(op["index"].getInt)
        let r = tree.setLeaf(idx, leaf)
        check r.isOk
      of "removeMember":
        let idx = uint64(op["index"].getInt)
        let r = tree.deleteLeaf(idx)
        check r.isOk
      of "getRoot":
        let expected = toMerkleNode(op["expected_root_hex"].getStr)
        let actual = tree.getRoot()
        check actual == expected
        if actual != expected:
          checkpoint &"op[{opIdx}] getRoot mismatch"
      of "getLeaf":
        let idx = uint64(op["index"].getInt)
        let expected = toMerkleNode(op["expected_leaf_hex"].getStr)
        let r = tree.getLeaf(idx)
        check r.isOk
        check r.get() == expected
        if r.isOk and r.get() != expected:
          checkpoint &"op[{opIdx}] getLeaf({idx}) mismatch"
      of "getMerkleProof":
        let idx = uint64(op["index"].getInt)
        let expected = hexToBytes(op["expected_proof_hex"].getStr)
        let proofRes = tree.getInclusionProof(idx)
        check proofRes.isOk
        let (pe, pi) = proofRes.get()
        let encoded = encodeProof(pe, pi)
        check encoded == expected
        if encoded != expected:
          checkpoint &"op[{opIdx}] getMerkleProof({idx}) mismatch (len got={encoded.len} expected={expected.len})"
      else:
        check false # unknown op
        checkpoint &"op[{opIdx}] unknown op kind: {kind}"
      inc opIdx

  test "additional: empty-tree root is poseidon^depth(ZERO, ZERO)":
    var t = IncrementalMerkleTree.init(MerkleTreeDepth, poseidonHash)
    var expected: MerkleNode # zero
    for _ in 1 .. MerkleTreeDepth:
      expected = poseidonHash(expected, expected)
    check t.getRoot() == expected

  test "additional: idempotent reads (getRoot/getInclusionProof/getLeaf)":
    var t = IncrementalMerkleTree.init(MerkleTreeDepth, poseidonHash)
    for i in 0 ..< 5:
      var leaf: MerkleNode
      leaf[0] = byte(0x42)
      leaf[1] = byte(i + 1)
      check t.insertLeaf(leaf).isOk

    let root1 = t.getRoot()
    let root2 = t.getRoot()
    check root1 == root2

    for idx in 0'u64 ..< 5:
      let p1 = t.getInclusionProof(idx)
      let p2 = t.getInclusionProof(idx)
      check p1.isOk and p2.isOk
      check p1.get() == p2.get()
      let l1 = t.getLeaf(idx)
      let l2 = t.getLeaf(idx)
      check l1.isOk and l2.isOk
      check l1.get() == l2.get()

  test "additional: deleteLeaf zeroes the leaf and does not move nextIndex":
    var t = IncrementalMerkleTree.init(MerkleTreeDepth, poseidonHash)
    var l0, l1, l2: MerkleNode
    l0[0] = 1
    l1[0] = 2
    l2[0] = 3
    check t.insertLeaf(l0).isOk
    check t.insertLeaf(l1).isOk
    check t.insertLeaf(l2).isOk
    check t.leavesSet() == 3

    check t.deleteLeaf(1).isOk
    let leafRead = t.getLeaf(1)
    check leafRead.isOk
    var zero: MerkleNode
    check leafRead.get() == zero
    check t.leavesSet() == 3 # unchanged

    # Subsequent insertLeaf lands at the prior nextIndex (3), not the
    # vacated slot 1 — replay-safety contract.
    var l3: MerkleNode
    l3[0] = 4
    let r = t.insertLeaf(l3)
    check r.isOk
    check r.get() == 3'u64
    check t.leavesSet() == 4

  test "additional: setLeaf at a sparse idx advances nextIndex past it":
    var t = IncrementalMerkleTree.init(MerkleTreeDepth, poseidonHash)
    var l: MerkleNode
    l[0] = 0xb0
    check t.setLeaf(15, l).isOk
    check t.leavesSet() == 16
    var l2: MerkleNode
    l2[0] = 0xc0
    let r = t.insertLeaf(l2)
    check r.isOk
    check r.get() == 16'u64

  test "additional: setLeaf out of capacity errors":
    var t = IncrementalMerkleTree.init(MerkleTreeDepth, poseidonHash)
    var l: MerkleNode
    check t.setLeaf(t.capacity(), l).isErr
    check t.setLeaf(t.capacity() + 100, l).isErr

  test "additional: proof at unmaterialised idx uses zero-subtree siblings":
    var t = IncrementalMerkleTree.init(MerkleTreeDepth, poseidonHash)
    var l: MerkleNode
    l[0] = 0x77
    check t.insertLeaf(l).isOk
    let proofRes = t.getInclusionProof(100)
    check proofRes.isOk
    # Shape-only — the strict-replay test above already locks the wire format.
    let (pe, pi) = proofRes.get()
    check pe.len == MerkleTreeDepth * 32
    check pi.len == MerkleTreeDepth
