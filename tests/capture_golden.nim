# Mix RLN Spam Protection Plugin - Tests
# Copyright (c) 2025 vacp2p
# Licensed under either of Apache License 2.0 or MIT license.

## One-time helper: capture pmtree-backed RLN tree output for parity testing.
##
## Runs the plugin's current (pmtree-ft backed) RLN wrappers through a
## deterministic sequence of tree operations and serialises each operation's
## byte-level result to `tests/fixtures/pmtree_golden.json`.  After the Nim
## IMT swap, `tests/test_merkle_tree.nim` replays the same sequence and
## asserts byte-identical output.
##
## This file is run ONCE while the plugin is still built against zerokit
## default features (pmtree-ft) — it links against the pmtree-ft librln
## archive.  After the swap to stateless build it will fail to link, which
## is intentional: the fixture is then frozen.
##
## Build/run:
##   LIBRLN_PATH=/path/to/librln_pmtree_v2.0.2.a \
##     nim c -r --passL:$LIBRLN_PATH --passL:-lm tests/capture_golden.nim

import std/[json, os, strformat]
import results

import ../src/mix_rln_spam_protection/rln_interface
import ../src/mix_rln_spam_protection/types
import ../src/mix_rln_spam_protection/constants

const
  FixturePath = "tests/fixtures/pmtree_golden.json"
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

proc detLeaf(tag: byte, i: int): IDCommitment =
  ## Deterministic 32-byte BN254 scalar.  Layout:
  ##   byte 0 : `tag` (distinguishes insertion families)
  ##   byte 1 : low byte of `i+1`
  ##   byte 2 : high byte of `i+1`
  ##   rest   : zero
  ## Trivially below the field modulus so any 32-byte LE interpretation is
  ## a valid Fr element.
  result = default(IDCommitment)
  result[0] = tag
  result[1] = byte((i + 1) and 0xff)
  result[2] = byte(((i + 1) shr 8) and 0xff)

proc recordRoot(rln: RLNInstance, ops: var JsonNode) =
  let root = rln.getMerkleRoot().valueOr:
    quit("getMerkleRoot failed: " & error)
  ops.add(%*{"op": "getRoot", "expected_root_hex": toHex(root)})

proc recordProof(rln: RLNInstance, idx: int, ops: var JsonNode) =
  let proof = rln.getMerkleProof(MembershipIndex(idx)).valueOr:
    quit(&"getMerkleProof({idx}) failed: " & error)
  ops.add(%*{"op": "getMerkleProof", "index": idx, "expected_proof_hex": toHex(proof)})

proc recordLeaf(rln: RLNInstance, idx: int, ops: var JsonNode) =
  let leaf = rln.getLeaf(MembershipIndex(idx)).valueOr:
    quit(&"getLeaf({idx}) failed: " & error)
  ops.add(%*{"op": "getLeaf", "index": idx, "expected_leaf_hex": toHex(leaf)})

proc main() =
  echo "Creating pmtree-backed RLN instance (depth=", MerkleTreeDepth, ")..."
  let rln = createRLNInstance().valueOr:
    quit("createRLNInstance failed: " & error)
  defer:
    rln.close()

  var ops = newJArray()

  # --- Phase 1: empty tree ---
  recordRoot(rln, ops)

  # --- Phase 2: N sequential inserts via set_next_leaf ---
  for i in 0 ..< InitialLeafCount:
    let leaf = detLeaf(0x10, i)
    let idx = rln.insertMember(leaf).valueOr:
      quit(&"insertMember({i}) failed: " & error)
    ops.add(
      %*{"op": "insertMember", "leaf_hex": toHex(leaf), "returned_index": int(idx)}
    )
    recordRoot(rln, ops)

  # --- Phase 3: proof + leaf readback at each populated idx ---
  for i in 0 ..< InitialLeafCount:
    recordProof(rln, i, ops)
    recordLeaf(rln, i, ops)

  # --- Phase 4: overwrite an existing leaf (set_leaf at populated idx) ---
  let overwriteLeaf = detLeaf(0xa0, OverwriteIdx)
  let overwriteRes = rln.insertMemberAt(MembershipIndex(OverwriteIdx), overwriteLeaf)
  if overwriteRes.isErr:
    quit(&"insertMemberAt({OverwriteIdx}) failed: " & overwriteRes.error)
  ops.add(
    %*{"op": "insertMemberAt", "index": OverwriteIdx, "leaf_hex": toHex(overwriteLeaf)}
  )
  recordRoot(rln, ops)
  recordProof(rln, OverwriteIdx, ops)
  recordLeaf(rln, OverwriteIdx, ops)

  # --- Phase 5: delete a populated leaf (delete_leaf) ---
  let deleteRes = rln.removeMember(MembershipIndex(DeleteIdx))
  if deleteRes.isErr:
    quit(&"removeMember({DeleteIdx}) failed: " & deleteRes.error)
  ops.add(%*{"op": "removeMember", "index": DeleteIdx})
  recordRoot(rln, ops)
  recordProof(rln, DeleteIdx, ops)
  recordLeaf(rln, DeleteIdx, ops)
    # Expect: leaf readback at deleted idx is 32 zero bytes (default Fr).

  # --- Phase 6: set_leaf at a sparse future index (skips 10..14) ---
  let sparseLeaf = detLeaf(0xb0, SparseIdx)
  let sparseRes = rln.insertMemberAt(MembershipIndex(SparseIdx), sparseLeaf)
  if sparseRes.isErr:
    quit(&"insertMemberAt({SparseIdx}) failed: " & sparseRes.error)
  ops.add(%*{"op": "insertMemberAt", "index": SparseIdx, "leaf_hex": toHex(sparseLeaf)})
  recordRoot(rln, ops)
  recordProof(rln, SparseIdx, ops)
  recordLeaf(rln, SparseIdx, ops)

  # --- Phase 7: proofs at still-empty sparse positions (10, 12, 14) ---
  for sparseProbe in [10, 12, 14]:
    recordProof(rln, sparseProbe, ops)
    recordLeaf(rln, sparseProbe, ops)

  # --- Phase 8: another insertMember after sparse setLeaf ---
  # This tells us whether ffi_set_leaf at idx > next_index advanced next_index.
  # If next_index advanced to SparseIdx+1, this insert lands at SparseIdx+1.
  # If not, it lands at the prior next_index.
  let postSparseLeaf = detLeaf(0xc0, 0)
  let postSparseIdx = rln.insertMember(postSparseLeaf).valueOr:
    quit("post-sparse insertMember failed: " & error)
  ops.add(
    %*{
      "op": "insertMember",
      "leaf_hex": toHex(postSparseLeaf),
      "returned_index": int(postSparseIdx),
    }
  )
  recordRoot(rln, ops)

  # --- Serialise ---
  let fixture = %*{"depth": MerkleTreeDepth, "hashByteSize": HashByteSize, "ops": ops}

  if not dirExists("tests/fixtures"):
    createDir("tests/fixtures")
  writeFile(FixturePath, fixture.pretty)
  echo "Wrote ", FixturePath, " (", ops.len, " ops)"

main()
