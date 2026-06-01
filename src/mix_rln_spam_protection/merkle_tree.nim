# Mix RLN Spam Protection Plugin - Merkle Tree
# Copyright (c) 2025 vacp2p
# Licensed under either of Apache License 2.0 or MIT license.

## Incremental Merkle Tree (Poseidon-friendly, fixed depth) implemented in
## pure Nim.  Replaces the zerokit pmtree backend so the plugin can build
## against zerokit's `--features stateless` (no embedded tree FFI), sharing
## a single zerokit archive with relay rather than carrying a second one.
##
## Design
## ------
## - `layers[level][i]` = hash of the subtree rooted at `(level, i)`.
##   `level 0` = leaves; `level = depth` holds the single root.
##   Unmaterialised positions are not stored; reads there return the
##   empty-subtree default for that level.
## - `zeros[level]` = hash of an all-zero subtree of height `level`.
##   `zeros[0] = ZERO_FIELD`, `zeros[i] = hashFn(zeros[i-1], zeros[i-1])`.
## - `nextIndex` mirrors zerokit's `leaves_set()`: advances on `insertLeaf`
##   and on `setLeaf` at `idx >= nextIndex`, but is never decremented
##   (replay safety; cf. zerokit `pm_tree_adapter.rs:378-389`).
## - The hash function is injected as a callback so this module has no
##   FFI or plugin-internal dependency.  See `tests/test_merkle_tree.nim`
##   for the strict byte-parity check against captured pmtree output.

import results
import ./types
import ./bytes_utils

{.push raises: [], gcsafe.}

type
  ImtHashFn* = proc(a, b: MerkleNode): MerkleNode {.gcsafe, raises: [].}
    ## Two-input hash compressor.  For the plugin's parity with zerokit
    ## pmtree this MUST be Poseidon over BN254 with little-endian field
    ## byte encoding (see `poseidonPairLe` in `rln_interface.nim`).

  IncrementalMerkleTree* = object
    depth*: int
    hashFn: ImtHashFn
    layers: seq[seq[MerkleNode]]
    zeros: seq[MerkleNode]
    nextIndexInternal: uint64

const ZeroField: MerkleNode = default(MerkleNode)

proc init*(
    T: type IncrementalMerkleTree, depth: int, hashFn: ImtHashFn
): IncrementalMerkleTree =
  ## Build an empty tree.  `depth` is the number of hash levels above the
  ## leaf layer; the tree holds 2^depth leaves.
  doAssert depth >= 1 and depth <= 32, "IMT depth out of range: " & $depth
  doAssert hashFn != nil, "IMT requires a non-nil hashFn"
  result.depth = depth
  result.hashFn = hashFn
  result.nextIndexInternal = 0

  result.zeros = newSeqOfCap[MerkleNode](depth + 1)
  result.zeros.add(ZeroField)
  for level in 1 .. depth:
    let h = hashFn(result.zeros[level - 1], result.zeros[level - 1])
    result.zeros.add(h)

  result.layers = newSeqOfCap[seq[MerkleNode]](depth + 1)
  for _ in 0 .. depth:
    result.layers.add(newSeq[MerkleNode]())
  result.layers[depth].add(result.zeros[depth])

# --- Accessors -----------------------------------------------------------

proc leavesSet*(t: IncrementalMerkleTree): uint64 =
  ## Parity counter for zerokit `ffi_leaves_set`.
  t.nextIndexInternal

proc capacity*(t: IncrementalMerkleTree): uint64 =
  uint64(1) shl t.depth

proc getRoot*(t: IncrementalMerkleTree): MerkleNode =
  t.layers[t.depth][0]

# --- Internal helpers ----------------------------------------------------

proc getNode(t: IncrementalMerkleTree, level, idx: int): MerkleNode =
  if idx < t.layers[level].len:
    t.layers[level][idx]
  else:
    t.zeros[level]

proc growLeaves(t: var IncrementalMerkleTree, idx: int) =
  while t.layers[0].len <= idx:
    t.layers[0].add(ZeroField)

proc recomputeUp(t: var IncrementalMerkleTree, leafIdx: int) =
  ## Walk from leaf to root recomputing affected internal nodes.  Sibling
  ## positions that haven't been materialised hash against the empty-subtree
  ## default at that level.
  var idx = leafIdx
  for level in 0 ..< t.depth:
    let isRight = (idx and 1) == 1
    let self = t.getNode(level, idx)
    let sibling = t.getNode(level, idx xor 1)
    let parent =
      if isRight:
        t.hashFn(sibling, self)
      else:
        t.hashFn(self, sibling)
    let parentLevel = level + 1
    let parentIdx = idx shr 1
    while t.layers[parentLevel].len <= parentIdx:
      t.layers[parentLevel].add(t.zeros[parentLevel])
    t.layers[parentLevel][parentIdx] = parent
    idx = parentIdx

# --- Public mutators -----------------------------------------------------

proc setLeaf*(
    t: var IncrementalMerkleTree, idx: uint64, leaf: MerkleNode
): RlnResult[void] =
  ## Set the leaf at `idx`.  Advances `nextIndex = max(nextIndex, idx+1)` —
  ## zerokit pmtree behaviour, verified in the golden fixture (post-sparse
  ## `insertMember` returns `sparseIdx + 1`, not the pre-sparse counter).
  if idx >= t.capacity():
    return err("Merkle index out of range: " & $idx)
  t.growLeaves(int(idx))
  t.layers[0][int(idx)] = leaf
  t.recomputeUp(int(idx))
  if idx + 1 > t.nextIndexInternal:
    t.nextIndexInternal = idx + 1
  ok()

proc insertLeaf*(t: var IncrementalMerkleTree, leaf: MerkleNode): RlnResult[uint64] =
  ## Append at `nextIndex` and advance.  Returns the assigned index.
  let idx = t.nextIndexInternal
  ?t.setLeaf(idx, leaf)
  ok(idx)

proc deleteLeaf*(t: var IncrementalMerkleTree, idx: uint64): RlnResult[void] =
  ## Reset the leaf at `idx` to zero and propagate up.  Does NOT change
  ## `nextIndex` (pmtree replay safety: previously used indices cannot be
  ## reused; cf. `pm_tree_adapter.rs:378-389`).
  if idx >= t.capacity():
    return err("Merkle index out of range: " & $idx)
  if int(idx) < t.layers[0].len:
    t.layers[0][int(idx)] = ZeroField
    t.recomputeUp(int(idx))
  # An unmaterialised leaf is already zero — no-op.
  ok()

# --- Read API ------------------------------------------------------------

proc getLeaf*(t: IncrementalMerkleTree, idx: uint64): RlnResult[MerkleNode] =
  if idx >= t.capacity():
    return err("Merkle index out of range: " & $idx)
  if int(idx) < t.layers[0].len:
    ok(t.layers[0][int(idx)])
  else:
    ok(ZeroField)

proc getInclusionProof*(
    t: IncrementalMerkleTree, idx: uint64
): RlnResult[tuple[pathElements: seq[byte], pathIndex: seq[byte]]] =
  ## Walk leaf-to-root collecting sibling hashes and bit positions.
  ## `pathElements` is `depth*32` bytes of concatenated LE field elements;
  ## `pathIndex` is `depth` bytes (1 = the leaf side is the right child,
  ## 0 = left).  `encodeProof` wraps these into the wire format expected
  ## by callers that consumed the old pmtree-backed `getMerkleProof`.
  if idx >= t.capacity():
    return err("Merkle index out of range: " & $idx)
  var pe = newSeq[byte](t.depth * 32)
  var pi = newSeq[byte](t.depth)
  var i = int(idx)
  for level in 0 ..< t.depth:
    let sibling = t.getNode(level, i xor 1)
    copyMem(addr pe[level * 32], unsafeAddr sibling[0], 32)
    pi[level] = byte(i and 1)
    i = i shr 1
  ok((pathElements: pe, pathIndex: pi))

proc encodeProof*(
    pathElements: openArray[byte], pathIndex: openArray[byte]
): seq[byte] =
  ## Wire format identical to the previous pmtree-backed `getMerkleProof`:
  ##   u64-LE depth | depth*32 path_elements | u64-LE depth | depth bytes path_index
  ## For depth=20 this is 8 + 640 + 8 + 20 = 676 bytes.
  let depth = pathIndex.len
  result = newSeq[byte](8 + depth * 32 + 8 + depth)
  let depthBytes = uint64(depth).toBytesLE()
  copyMem(addr result[0], unsafeAddr depthBytes[0], 8)
  if depth > 0:
    copyMem(addr result[8], unsafeAddr pathElements[0], depth * 32)
  copyMem(addr result[8 + depth * 32], unsafeAddr depthBytes[0], 8)
  if depth > 0:
    copyMem(addr result[8 + depth * 32 + 8], unsafeAddr pathIndex[0], depth)

# --- Compatibility shim --------------------------------------------------

proc flush*(t: var IncrementalMerkleTree): bool =
  ## No-op: the Nim IMT is always in-sync.  Kept so callers that mirrored
  ## the zerokit `ffi_flush` contract continue to compile.
  discard t # silence "unused" since we don't actually need a var here
  true

{.pop.}
