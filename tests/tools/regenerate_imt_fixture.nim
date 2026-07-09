# Mix RLN Spam Protection Plugin - Tools
# Copyright (c) 2025 vacp2p
# Licensed under either of Apache License 2.0 or MIT license.

## Regenerates `tests/fixtures/imt_regression.json` from the current Nim
## `IncrementalMerkleTree`.  Run this only after a *deliberate* IMT change
## that updates the expected outputs; the regression test would otherwise
## hide the change.
##
## Build/run (from repo root):
##   nim c -r --passL:librln.a --passL:-lm tests/tools/regenerate_imt_fixture.nim
##
## librln is required for Poseidon (`poseidonPairLe`); the stateless
## librln archive is sufficient.

import std/[json, os, strformat]
import results

import ../../src/mix_rln_spam_protection/merkle_tree
import ../../src/mix_rln_spam_protection/rln_interface
import ../../src/mix_rln_spam_protection/types
import ../../src/mix_rln_spam_protection/constants

const
  FixturePath = "tests/fixtures/imt_regression.json"
  InitialLeafCount = 10
  OverwriteIdx = 3
  DeleteIdx = 5
  SparseIdx = 15

proc toHex(bytes: openArray[byte]): string =
  result = newStringOfCap(bytes.len * 2)
  const chars = "0123456789abcdef"
  for b in bytes:
    result.add(chars[int(b shr 4)])
    result.add(chars[int(b and 0x0F)])

proc detLeaf(tag: byte, i: int): MerkleNode =
  result = default(MerkleNode)
  result[0] = tag
  result[1] = byte((i + 1) and 0xff)
  result[2] = byte(((i + 1) shr 8) and 0xff)

proc poseidonHash(a, b: MerkleNode): MerkleNode {.gcsafe, raises: [].} =
  let r = poseidonPairLe(a, b)
  if r.isErr:
    raiseAssert "poseidonPairLe failed: " & r.error
  r.get()

proc recordRoot(t: IncrementalMerkleTree, ops: var JsonNode) =
  ops.add(%*{"op": "getRoot", "expected_root_hex": toHex(t.getRoot())})

proc recordProof(t: IncrementalMerkleTree, idx: int, ops: var JsonNode) =
  let proofRes = t.getInclusionProof(uint64(idx))
  if proofRes.isErr:
    quit(&"getInclusionProof({idx}) failed: " & proofRes.error)
  let (pe, pi) = proofRes.get()
  let encoded = encodeProof(pe, pi)
  ops.add(
    %*{"op": "getMerkleProof", "index": idx, "expected_proof_hex": toHex(encoded)}
  )

proc recordLeaf(t: IncrementalMerkleTree, idx: int, ops: var JsonNode) =
  let leafRes = t.getLeaf(uint64(idx))
  if leafRes.isErr:
    quit(&"getLeaf({idx}) failed: " & leafRes.error)
  ops.add(%*{"op": "getLeaf", "index": idx, "expected_leaf_hex": toHex(leafRes.get())})

proc main() =
  echo "Building IMT (depth=", MerkleTreeDepth, ")..."
  var tree = IncrementalMerkleTree.init(MerkleTreeDepth, poseidonHash)

  var ops = newJArray()

  recordRoot(tree, ops)

  for i in 0 ..< InitialLeafCount:
    let leaf = detLeaf(0x10, i)
    let idxRes = tree.insertLeaf(leaf)
    if idxRes.isErr:
      quit(&"insertLeaf({i}) failed: " & idxRes.error)
    ops.add(
      %*{
        "op": "insertMember",
        "leaf_hex": toHex(leaf),
        "returned_index": int(idxRes.get()),
      }
    )
    recordRoot(tree, ops)

  for i in 0 ..< InitialLeafCount:
    recordProof(tree, i, ops)
    recordLeaf(tree, i, ops)

  let overwriteLeaf = detLeaf(0xa0, OverwriteIdx)
  let overwriteRes = tree.setLeaf(uint64(OverwriteIdx), overwriteLeaf)
  if overwriteRes.isErr:
    quit(&"setLeaf({OverwriteIdx}) failed: " & overwriteRes.error)
  ops.add(
    %*{"op": "insertMemberAt", "index": OverwriteIdx, "leaf_hex": toHex(overwriteLeaf)}
  )
  recordRoot(tree, ops)
  recordProof(tree, OverwriteIdx, ops)
  recordLeaf(tree, OverwriteIdx, ops)

  let deleteRes = tree.deleteLeaf(uint64(DeleteIdx))
  if deleteRes.isErr:
    quit(&"deleteLeaf({DeleteIdx}) failed: " & deleteRes.error)
  ops.add(%*{"op": "removeMember", "index": DeleteIdx})
  recordRoot(tree, ops)
  recordProof(tree, DeleteIdx, ops)
  recordLeaf(tree, DeleteIdx, ops)

  let sparseLeaf = detLeaf(0xb0, SparseIdx)
  let sparseRes = tree.setLeaf(uint64(SparseIdx), sparseLeaf)
  if sparseRes.isErr:
    quit(&"setLeaf({SparseIdx}) failed: " & sparseRes.error)
  ops.add(%*{"op": "insertMemberAt", "index": SparseIdx, "leaf_hex": toHex(sparseLeaf)})
  recordRoot(tree, ops)
  recordProof(tree, SparseIdx, ops)
  recordLeaf(tree, SparseIdx, ops)

  for sparseProbe in [10, 12, 14]:
    recordProof(tree, sparseProbe, ops)
    recordLeaf(tree, sparseProbe, ops)

  let postSparseLeaf = detLeaf(0xc0, 0)
  let postSparseRes = tree.insertLeaf(postSparseLeaf)
  if postSparseRes.isErr:
    quit("post-sparse insertLeaf failed: " & postSparseRes.error)
  ops.add(
    %*{
      "op": "insertMember",
      "leaf_hex": toHex(postSparseLeaf),
      "returned_index": int(postSparseRes.get()),
    }
  )
  recordRoot(tree, ops)

  let fixture = %*{"depth": MerkleTreeDepth, "hashByteSize": HashByteSize, "ops": ops}

  if not dirExists("tests/fixtures"):
    createDir("tests/fixtures")
  writeFile(FixturePath, fixture.pretty)
  echo "Wrote ", FixturePath, " (", ops.len, " ops)"

main()
