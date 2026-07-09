# Mix RLN Spam Protection Plugin
# Copyright (c) 2025 vacp2p
# Licensed under either of Apache License 2.0 or MIT license.

## Nim wrappers for zerokit RLN v2.0.2 built with `--features stateless`.
## The Merkle tree (set/get/delete leaves, root, inclusion proofs) lives on
## the Nim side via `IncrementalMerkleTree`; zerokit is used only for
## Poseidon hashing, witness construction, and Groth16 prove/verify.
##
## Switching to the stateless build lets the plugin share a single zerokit
## archive with relay (which is also stateless), eliminating the dual-
## archive symbol collision that was previously dodged by version-skew.
##
## Build: the plugin's zerokit dependency MUST be built with
## `--no-default-features --features stateless`.  Stateful tree FFIs are
## not present in stateless archives.

import std/os
import results, chronicles
import ./types
import ./constants
import ./merkle_tree

{.push raises: [], gcsafe.}

logScope:
  topics = "rln interface"

type
  CSize = csize_t

  CFr = object
  FFI_RLN = object
  FFI_RLNProof = object
  FFI_RLNPartialProof = object
  FFI_RLNWitnessInput = object
  FFI_RLNPartialWitnessInput = object

  Vec_CFr = object
    dataPtr: ptr CFr
    len: CSize
    cap: CSize

  Vec_uint8 = object
    dataPtr: ptr uint8
    len: CSize
    cap: CSize

  CBoolResult = object
    ok: bool
    err: Vec_uint8

  CResultRLNPtrVecU8 = object
    ok: ptr FFI_RLN
    err: Vec_uint8

  CResultCFrPtrVecU8 = object
    ok: ptr CFr
    err: Vec_uint8

  CResultProofPtrVecU8 = object
    ok: ptr FFI_RLNProof
    err: Vec_uint8

  CResultPartialProofPtrVecU8 = object
    ok: ptr FFI_RLNPartialProof
    err: Vec_uint8

  CResultWitnessInputPtrVecU8 = object
    ok: ptr FFI_RLNWitnessInput
    err: Vec_uint8

  CResultPartialWitnessInputPtrVecU8 = object
    ok: ptr FFI_RLNPartialWitnessInput
    err: Vec_uint8

  CResultVecU8VecU8 = object
    ok: Vec_uint8
    err: Vec_uint8

  FFI_RLNProofValues = object

  PartialProofCache* = object ## Cached partial proof tied to a specific Merkle root.
    root*: MerkleNode
    memberIndex*: MembershipIndex
    partialProofBytes*: seq[byte]
    pathElements*: seq[byte]
    pathIndex*: seq[byte]

  RLN* = FFI_RLN

  RLNInstance* = ref object
    ctx*: ptr RLN
    tree*: IncrementalMerkleTree

const
  FieldElementSize = 32
  # Single-message-id RLN proof wire layout: outer version byte + 128-byte
  # Groth16 + inner RLNProofValues (inner version + 5 field elements).
  ProofSerializationSize = 1 + ZksnarkProofByteSize + 1 + 5 * FieldElementSize

proc computeExternalNullifier*(
  epoch: Epoch, rlnIdentifier: RlnIdentifier
): RlnResult[ExternalNullifier]

proc ffi_cfr_free(cfr: ptr CFr) {.importc: "ffi_cfr_free", cdecl.}
proc ffi_cfr_to_bytes_le(
  cfr: ptr CFr
): Vec_uint8 {.importc: "ffi_cfr_to_bytes_le", cdecl.}

proc ffi_bytes_le_to_cfr(
  bytes: ptr Vec_uint8
): CResultCFrPtrVecU8 {.importc: "ffi_bytes_le_to_cfr", cdecl.}

# v2.0.1: hash_to_field_le / poseidon_hash_pair return ptr CFr directly
# (no Result wrapper) — caller MUST ffi_cfr_free the returned ptr.
proc ffi_hash_to_field_le(
  input: ptr Vec_uint8
): ptr CFr {.importc: "ffi_hash_to_field_le", cdecl.}

proc ffi_poseidon_hash_pair(
  a: ptr CFr, b: ptr CFr
): ptr CFr {.importc: "ffi_poseidon_hash_pair", cdecl.}

proc ffi_vec_cfr_new(capacity: CSize): Vec_CFr {.importc: "ffi_vec_cfr_new", cdecl.}
proc ffi_vec_cfr_push(
  v: ptr Vec_CFr, cfr: ptr CFr
) {.importc: "ffi_vec_cfr_push", cdecl.}

proc ffi_vec_cfr_len(v: ptr Vec_CFr): CSize {.importc: "ffi_vec_cfr_len", cdecl.}
proc ffi_vec_cfr_get(
  v: ptr Vec_CFr, i: CSize
): ptr CFr {.importc: "ffi_vec_cfr_get", cdecl.}

proc ffi_vec_cfr_free(v: Vec_CFr) {.importc: "ffi_vec_cfr_free", cdecl.}
proc ffi_vec_u8_free(v: Vec_uint8) {.importc: "ffi_vec_u8_free", cdecl.}
proc ffi_c_string_free(s: Vec_uint8) {.importc: "ffi_c_string_free", cdecl.}

# v2.0.1: extended_key_gen / seeded_extended_key_gen return Vec_CFr directly
# (no Result wrapper) — caller MUST ffi_vec_cfr_free the returned vec.
proc ffi_extended_key_gen(): Vec_CFr {.importc: "ffi_extended_key_gen", cdecl.}
proc ffi_seeded_extended_key_gen(
  seed: ptr Vec_uint8
): Vec_CFr {.importc: "ffi_seeded_extended_key_gen", cdecl.}

# Stateless ffi_rln_new takes no args; ffi_rln_new_with_params takes only the
# zkey + graph (no tree depth, no config — tree state is Nim-side now).
proc ffi_rln_new(): CResultRLNPtrVecU8 {.importc: "ffi_rln_new", cdecl.}
proc ffi_rln_new_with_params(
  zkey_data: ptr Vec_uint8, graph_data: ptr Vec_uint8
): CResultRLNPtrVecU8 {.importc: "ffi_rln_new_with_params", cdecl.}

proc ffi_rln_free(rln: ptr FFI_RLN) {.importc: "ffi_rln_free", cdecl.}

proc ffi_rln_witness_input_new(
  identity_secret: ptr CFr,
  user_message_limit: ptr CFr,
  message_id: ptr CFr,
  path_elements: ptr Vec_CFr,
  identity_path_index: ptr Vec_uint8,
  x: ptr CFr,
  external_nullifier: ptr CFr,
): CResultWitnessInputPtrVecU8 {.importc: "ffi_rln_witness_input_new", cdecl.}

proc ffi_rln_witness_input_free(
  witness: ptr FFI_RLNWitnessInput
) {.importc: "ffi_rln_witness_input_free", cdecl.}

proc ffi_rln_partial_witness_input_new(
  identity_secret: ptr CFr,
  user_message_limit: ptr CFr,
  path_elements: ptr Vec_CFr,
  identity_path_index: ptr Vec_uint8,
): CResultPartialWitnessInputPtrVecU8 {.
  importc: "ffi_rln_partial_witness_input_new", cdecl
.}

proc ffi_rln_partial_witness_input_free(
  witness: ptr FFI_RLNPartialWitnessInput
) {.importc: "ffi_rln_partial_witness_input_free", cdecl.}

proc ffi_generate_rln_proof(
  rln: ptr ptr FFI_RLN, witness: ptr ptr FFI_RLNWitnessInput
): CResultProofPtrVecU8 {.importc: "ffi_generate_rln_proof", cdecl.}

proc ffi_generate_partial_zk_proof(
  rln: ptr ptr FFI_RLN, partial_witness: ptr ptr FFI_RLNPartialWitnessInput
): CResultPartialProofPtrVecU8 {.importc: "ffi_generate_partial_zk_proof", cdecl.}

proc ffi_finish_rln_proof(
  rln: ptr ptr FFI_RLN,
  partial_proof: ptr ptr FFI_RLNPartialProof,
  witness: ptr ptr FFI_RLNWitnessInput,
): CResultProofPtrVecU8 {.importc: "ffi_finish_rln_proof", cdecl.}

proc ffi_verify_with_roots(
  rln: ptr ptr FFI_RLN, proof: ptr ptr FFI_RLNProof, roots: ptr Vec_CFr, x: ptr CFr
): CBoolResult {.importc: "ffi_verify_with_roots", cdecl.}

# Stateless build: the tree (set_next_leaf/get_root/get_merkle_proof/set_leaf
# /delete_leaf/get_leaf/leaves_set/flush/merkle_proof_free) lives on the Nim
# side; see `merkle_tree.nim` and the IncrementalMerkleTree field on
# RLNInstance.  None of those FFIs are present in stateless zerokit archives.

proc ffi_compute_id_secret(
  share1_x: ptr CFr, share1_y: ptr CFr, share2_x: ptr CFr, share2_y: ptr CFr
): CResultCFrPtrVecU8 {.importc: "ffi_compute_id_secret", cdecl.}

proc ffi_rln_proof_get_values(
  proof: ptr ptr FFI_RLNProof
): ptr FFI_RLNProofValues {.importc: "ffi_rln_proof_get_values", cdecl.}

proc ffi_rln_proof_to_bytes_le(
  proof: ptr ptr FFI_RLNProof
): CResultVecU8VecU8 {.importc: "ffi_rln_proof_to_bytes_le", cdecl.}

# v2.0.2: construct an RLNProof directly from its field elements (single
# message-id variant), avoiding the manual 290-byte wire layout.
proc ffi_rln_proof_new(
  groth16Bytes: ptr Vec_uint8,
  root: ptr CFr,
  externalNullifier: ptr CFr,
  x: ptr CFr,
  y: ptr CFr,
  nullifier: ptr CFr,
): CResultProofPtrVecU8 {.importc: "ffi_rln_proof_new", cdecl.}

proc ffi_rln_proof_free(p: ptr FFI_RLNProof) {.importc: "ffi_rln_proof_free", cdecl.}

proc ffi_rln_partial_proof_to_bytes_le(
  partial_proof: ptr ptr FFI_RLNPartialProof
): CResultVecU8VecU8 {.importc: "ffi_rln_partial_proof_to_bytes_le", cdecl.}

proc ffi_bytes_le_to_rln_partial_proof(
  bytes: ptr Vec_uint8
): CResultPartialProofPtrVecU8 {.importc: "ffi_bytes_le_to_rln_partial_proof", cdecl.}

proc ffi_rln_partial_proof_free(
  partial_proof: ptr FFI_RLNPartialProof
) {.importc: "ffi_rln_partial_proof_free", cdecl.}

proc ffi_rln_proof_values_get_y(
  pv: ptr ptr FFI_RLNProofValues
): CResultCFrPtrVecU8 {.importc: "ffi_rln_proof_values_get_y", cdecl.}

proc ffi_rln_proof_values_get_nullifier(
  pv: ptr ptr FFI_RLNProofValues
): CResultCFrPtrVecU8 {.importc: "ffi_rln_proof_values_get_nullifier", cdecl.}

proc ffi_rln_proof_values_get_root(
  pv: ptr ptr FFI_RLNProofValues
): ptr CFr {.importc: "ffi_rln_proof_values_get_root", cdecl.}

proc ffi_rln_proof_values_get_x(
  pv: ptr ptr FFI_RLNProofValues
): ptr CFr {.importc: "ffi_rln_proof_values_get_x", cdecl.}

proc ffi_rln_proof_values_free(
  pv: ptr FFI_RLNProofValues
) {.importc: "ffi_rln_proof_values_free", cdecl.}

proc asString(data: Vec_uint8): string =
  if data.dataPtr.isNil or data.len == 0:
    return ""
  result = newString(int(data.len))
  copyMem(addr result[0], data.dataPtr, int(data.len))

proc hasError(data: Vec_uint8): bool =
  not data.dataPtr.isNil

proc consumeError(prefix: string, data: Vec_uint8): string =
  let msg = asString(data)
  if hasError(data):
    ffi_c_string_free(data)
  if prefix.len == 0:
    msg
  elif msg.len == 0:
    prefix
  else:
    prefix & msg

proc toVecUint8(data: openArray[byte]): Vec_uint8 =
  if data.len == 0:
    return Vec_uint8(dataPtr: nil, len: 0, cap: 0)
  Vec_uint8(
    dataPtr: cast[ptr uint8](unsafeAddr data[0]),
    len: CSize(data.len),
    cap: CSize(data.len),
  )

proc vecToSeq(data: Vec_uint8): seq[byte] =
  result = newSeq[byte](int(data.len))
  if result.len > 0:
    copyMem(addr result[0], data.dataPtr, result.len)

proc stringToBytes(s: string): seq[byte] =
  result = newSeq[byte](s.len)
  if s.len > 0:
    copyMem(addr result[0], unsafeAddr s[0], s.len)

proc seqToFixed32(data: openArray[byte]): RlnResult[array[32, byte]] =
  if data.len != FieldElementSize:
    return err("Expected 32 bytes, got " & $data.len)
  var output: array[32, byte]
  copyMem(addr output[0], unsafeAddr data[0], FieldElementSize)
  ok(output)

proc cfrToBytesLe(cfr: ptr CFr): RlnResult[array[32, byte]] =
  let bytes = ffi_cfr_to_bytes_le(cfr)
  defer:
    ffi_vec_u8_free(bytes)

  if int(bytes.len) != FieldElementSize:
    return err("Invalid field byte length: " & $bytes.len)

  seqToFixed32(vecToSeq(bytes))

proc bytesToCfrLe(data: openArray[byte]): RlnResult[ptr CFr] =
  var vec = toVecUint8(data)
  let res = ffi_bytes_le_to_cfr(addr vec)
  if not res.ok.isNil:
    return ok(res.ok)
  err(consumeError("Failed to convert bytes to field: ", res.err))

proc hashToFieldLe(data: openArray[byte]): RlnResult[ptr CFr] =
  var vec = toVecUint8(data)
  let cfr = ffi_hash_to_field_le(addr vec)
  if cfr.isNil:
    return err("Failed to hash to field")
  ok(cfr)

proc poseidonPairLe*(a, b: openArray[byte]): RlnResult[array[32, byte]] =
  let aPtr = bytesToCfrLe(a).valueOr:
    return err(error)
  defer:
    ffi_cfr_free(aPtr)

  let bPtr = bytesToCfrLe(b).valueOr:
    return err(error)
  defer:
    ffi_cfr_free(bPtr)

  let cfr = ffi_poseidon_hash_pair(aPtr, bPtr)
  if cfr.isNil:
    return err("Poseidon hash failed")
  defer:
    ffi_cfr_free(cfr)

  cfrToBytesLe(cfr)

proc poseidonHashFn(a, b: MerkleNode): MerkleNode {.gcsafe, raises: [].} =
  ## Adapter from the IMT's hash-callback signature to `poseidonPairLe`.
  ## All inputs at this point are either `ZERO_FIELD` or a previous
  ## Poseidon output — both valid BN254 field elements — so a failure
  ## indicates FFI corruption and is treated as a contract violation.
  let r = poseidonPairLe(a, b)
  if r.isErr:
    raiseAssert "poseidonPairLe failed in IMT hash callback: " & r.error
  r.get()

proc cfrResultToBytes(
    res: CResultCFrPtrVecU8, prefix: string
): RlnResult[array[32, byte]] =
  if res.ok.isNil:
    return err(consumeError(prefix, res.err))
  defer:
    ffi_cfr_free(res.ok)
  cfrToBytesLe(res.ok)

proc toRootVec(validRoots: seq[MerkleNode]): RlnResult[Vec_CFr] =
  var roots = ffi_vec_cfr_new(CSize(validRoots.len))
  for root in validRoots:
    let cfr = bytesToCfrLe(root).valueOr:
      ffi_vec_cfr_free(roots)
      return err(error)
    ffi_vec_cfr_push(addr roots, cfr)
    ffi_cfr_free(cfr)
  ok(roots)

proc getCurrentRootRaw(instance: RLNInstance): RlnResult[MerkleNode] =
  ## Read the current Merkle root from the Nim-side incremental tree.
  ## Returns a Result for API parity with the old pmtree-backed wrapper
  ## (which could fail at the FFI boundary); the IMT path is infallible
  ## but callers don't need to know that.
  ok(instance.tree.getRoot())

proc proofPtrToRateLimitProof(
    proofPtr: ptr FFI_RLNProof, epoch: Epoch
): RlnResult[RateLimitProof] =
  var proofHandle = proofPtr
  let proofBytesRes = ffi_rln_proof_to_bytes_le(addr proofHandle)
  if hasError(proofBytesRes.err):
    return err(consumeError("Failed to serialize proof: ", proofBytesRes.err))
  defer:
    ffi_vec_u8_free(proofBytesRes.ok)

  let serialized = vecToSeq(proofBytesRes.ok)
  if serialized.len < ProofSerializationSize:
    return err("Serialized proof too short: " & $serialized.len)

  let proofValues = ffi_rln_proof_get_values(addr proofHandle)
  if proofValues.isNil:
    return err("Failed to extract proof values")
  defer:
    ffi_rln_proof_values_free(proofValues)

  var proof: RateLimitProof
  proof.epoch = epoch

  copyMem(addr proof.proof[0], unsafeAddr serialized[1], ZksnarkProofByteSize)

  let rootPtr = ffi_rln_proof_values_get_root(addr proofValues)
  if rootPtr.isNil:
    return err("Failed to read proof root")
  defer:
    ffi_cfr_free(rootPtr)
  proof.merkleRoot = cfrToBytesLe(rootPtr).valueOr:
    return err(error)

  let xPtr = ffi_rln_proof_values_get_x(addr proofValues)
  if xPtr.isNil:
    return err("Failed to read proof x")
  defer:
    ffi_cfr_free(xPtr)
  proof.shareX = cfrToBytesLe(xPtr).valueOr:
    return err(error)

  let yRes = ffi_rln_proof_values_get_y(addr proofValues)
  proof.shareY = cfrResultToBytes(yRes, "Failed to read proof y: ").valueOr:
    return err(error)

  let nullifierRes = ffi_rln_proof_values_get_nullifier(addr proofValues)
  proof.nullifier = cfrResultToBytes(nullifierRes, "Failed to read proof nullifier: ").valueOr:
    return err(error)

  ok(proof)

proc buildWitnessFromPath(
    pathElements: ptr Vec_CFr,
    pathIndex: ptr Vec_uint8,
    credential: IdentityCredential,
    epoch: Epoch,
    rlnIdentifier: RlnIdentifier,
    signal: openArray[byte],
    messageId: uint,
    userMessageLimit: uint64,
    errPrefix: string,
): RlnResult[ptr FFI_RLNWitnessInput] =
  ## Build a witness from a caller-prepared Merkle path. Both overloads of
  ## `buildWitness` funnel through here once their path inputs are in the
  ## FFI-shaped Vec form.
  let identitySecret = bytesToCfrLe(credential.idSecretHash).valueOr:
    return err(error)
  defer:
    ffi_cfr_free(identitySecret)

  let userLimit = bytesToCfrLe(uint64ToField(userMessageLimit)).valueOr:
    return err(error)
  defer:
    ffi_cfr_free(userLimit)

  let messageIdFr = bytesToCfrLe(uint64ToField(uint64(messageId))).valueOr:
    return err(error)
  defer:
    ffi_cfr_free(messageIdFr)

  let x = hashToFieldLe(signal).valueOr:
    return err(error)
  defer:
    ffi_cfr_free(x)

  let externalNullifierBytes = computeExternalNullifier(epoch, rlnIdentifier).valueOr:
    return err("Failed to compute external nullifier: " & error)

  let externalNullifier = bytesToCfrLe(externalNullifierBytes).valueOr:
    return err(error)
  defer:
    ffi_cfr_free(externalNullifier)

  let witnessRes = ffi_rln_witness_input_new(
    identitySecret, userLimit, messageIdFr, pathElements, pathIndex, x,
    externalNullifier,
  )

  if witnessRes.ok.isNil:
    return err(consumeError(errPrefix, witnessRes.err))

  ok(witnessRes.ok)

proc buildWitness(
    pathElements: openArray[byte],
    pathIndex: openArray[byte],
    credential: IdentityCredential,
    epoch: Epoch,
    rlnIdentifier: RlnIdentifier,
    signal: openArray[byte],
    messageId: uint,
    userMessageLimit: uint64,
): RlnResult[ptr FFI_RLNWitnessInput] =
  ## Reconstruct a `Vec_CFr` from the IMT-produced bytes and feed it to
  ## zerokit's witness FFI.  Both proof-generation paths (fresh and
  ## partial-cache reuse) go through this single byte-based overload now
  ## that the Merkle tree is Nim-side; the previous ptr-FFI_MerkleProof
  ## overload is gone with the pmtree backend.
  if pathElements.len != pathIndex.len * FieldElementSize:
    return err(
      "Invalid cached Merkle path: expected " & $(pathIndex.len * FieldElementSize) &
        " bytes, got " & $pathElements.len
    )

  var pathElementsVec = ffi_vec_cfr_new(CSize(pathIndex.len))
  defer:
    ffi_vec_cfr_free(pathElementsVec)

  for i in 0 ..< pathIndex.len:
    let start = i * FieldElementSize
    let element = bytesToCfrLe(
      pathElements.toOpenArray(start, start + FieldElementSize - 1)
    ).valueOr:
      return err(error)
    ffi_vec_cfr_push(addr pathElementsVec, element)
    ffi_cfr_free(element)

  var pathIndexVec = toVecUint8(pathIndex)

  buildWitnessFromPath(
    addr pathElementsVec,
    addr pathIndexVec,
    credential,
    epoch,
    rlnIdentifier,
    signal,
    messageId,
    userMessageLimit,
    "Failed to create witness from cached Merkle path: ",
  )

proc parseCredentialVec(vec: var Vec_CFr): RlnResult[IdentityCredential] =
  ## ffi_extended_key_gen returns a Vec_CFr of exactly 4 elements:
  ## [ idTrapdoor, idNullifier, idSecretHash, idCommitment ].
  if int(ffi_vec_cfr_len(addr vec)) != 4:
    return err("Unexpected credential element count")

  var cred: IdentityCredential
  let fields = [
    ffi_vec_cfr_get(addr vec, 0),
    ffi_vec_cfr_get(addr vec, 1),
    ffi_vec_cfr_get(addr vec, 2),
    ffi_vec_cfr_get(addr vec, 3),
  ]
  for field in fields:
    if field.isNil:
      return err("Missing credential field from zerokit")

  cred.idTrapdoor = cfrToBytesLe(fields[0]).valueOr:
    return err(error)
  cred.idNullifier = cfrToBytesLe(fields[1]).valueOr:
    return err(error)
  cred.idSecretHash = cfrToBytesLe(fields[2]).valueOr:
    return err(error)
  cred.idCommitment = cfrToBytesLe(fields[3]).valueOr:
    return err(error)

  ok(cred)

proc membershipKeyGen*(): RlnResult[IdentityCredential] =
  var vec = ffi_extended_key_gen()
  defer:
    ffi_vec_cfr_free(vec)
  parseCredentialVec(vec)

proc membershipKeyGen*(seed: openArray[byte]): RlnResult[IdentityCredential] =
  var seedVec = toVecUint8(seed)
  var vec = ffi_seeded_extended_key_gen(addr seedVec)
  defer:
    ffi_vec_cfr_free(vec)
  parseCredentialVec(vec)

proc generateMembershipKey*(): RlnResult[IdentityCredential] =
  membershipKeyGen()

proc generateMembershipKey*(seed: openArray[byte]): RlnResult[IdentityCredential] =
  membershipKeyGen(seed)

proc createRLNInstance*(resourcesPath: string = ""): RlnResult[RLNInstance] =
  ## Build a stateless zerokit RLN instance (used only for Poseidon hashing,
  ## witness construction, and Groth16 prove/verify) and pair it with a
  ## fresh Nim-side `IncrementalMerkleTree` for the membership Merkle tree.
  trace "Creating RLN instance", resourcesPath = resourcesPath

  let res =
    if resourcesPath.len == 0:
      ffi_rln_new()
    else:
      let zkeyPath = resourcesPath / "rln_final.arkzkey"
      let graphPath = resourcesPath / "graph.bin"
      if not fileExists(zkeyPath):
        return err("Missing RLN resource: " & zkeyPath)
      if not fileExists(graphPath):
        return err("Missing RLN resource: " & graphPath)

      let zkeyBytes =
        try:
          stringToBytes(readFile(zkeyPath))
        except IOError as e:
          return err("Failed to read " & zkeyPath & ": " & e.msg)
      let graphBytes =
        try:
          stringToBytes(readFile(graphPath))
        except IOError as e:
          return err("Failed to read " & graphPath & ": " & e.msg)
      var zkeyVec = toVecUint8(zkeyBytes)
      var graphVec = toVecUint8(graphBytes)
      ffi_rln_new_with_params(addr zkeyVec, addr graphVec)

  if res.ok.isNil:
    return err(consumeError("Failed to create RLN instance: ", res.err))

  let instance = RLNInstance(
    ctx: cast[ptr RLN](res.ok),
    tree: IncrementalMerkleTree.init(MerkleTreeDepth, poseidonHashFn),
  )

  debug "RLN instance created successfully",
    initialTreeRoot = instance.tree.getRoot().toHex(), treeDepth = MerkleTreeDepth
  ok(instance)

proc newRLNInstance*(resourcesPath: string = ""): RlnResult[RLNInstance] =
  createRLNInstance(resourcesPath)

proc close*(instance: RLNInstance) =
  ## Release the underlying zerokit FFI_RLN box. Idempotent: subsequent calls
  ## are no-ops. After close, the instance must not be used.
  if not instance.isNil and not instance.ctx.isNil:
    ffi_rln_free(instance.ctx)
    instance.ctx = nil

proc poseidonHash*(inputs: seq[seq[byte]]): RlnResult[array[32, byte]] =
  case inputs.len
  of 1:
    return err("zerokit v2 FFI does not expose unary Poseidon hashing")
  of 2:
    return poseidonPairLe(inputs[0], inputs[1])
  else:
    return err("Only 2-input Poseidon hashing is supported by this wrapper")

proc computeExternalNullifier*(
    epoch: Epoch, rlnIdentifier: RlnIdentifier
): RlnResult[ExternalNullifier] =
  poseidonPairLe(epoch, rlnIdentifier)

proc computeRateCommitment*(
    idCommitment: IDCommitment, userMessageLimit: uint64
): RlnResult[IDCommitment] =
  let limitField = uint64ToField(userMessageLimit)
  poseidonPairLe(idCommitment, limitField)

proc getMerkleRoot*(instance: RLNInstance): RlnResult[MerkleNode] =
  getCurrentRootRaw(instance)

proc getMerkleProof*(
    instance: RLNInstance, index: MembershipIndex
): RlnResult[seq[byte]] =
  ## Inclusion proof encoded in the legacy zerokit wire format:
  ##   u64-LE depth | depth*32 path_elements | u64-LE depth | depth bytes path_index
  ## At depth 20 this is 676 bytes.  Byte-for-byte equivalent to the
  ## pmtree-backed implementation it replaced (locked down by
  ## `tests/test_merkle_tree.nim`'s parity check against pmtree).
  let proofRes = instance.tree.getInclusionProof(uint64(index))
  if proofRes.isErr:
    return err(proofRes.error)
  let (pathElements, pathIndex) = proofRes.get()
  ok(encodeProof(pathElements, pathIndex))

proc getLeaf*(instance: RLNInstance, index: MembershipIndex): RlnResult[IDCommitment] =
  instance.tree.getLeaf(uint64(index))

proc insertMember*(
    instance: RLNInstance, commitment: IDCommitment
): RlnResult[MembershipIndex] =
  let idxRes = instance.tree.insertLeaf(commitment)
  if idxRes.isErr:
    return err("Failed to insert member: " & idxRes.error)
  ok(MembershipIndex(idxRes.get()))

proc removeMember*(instance: RLNInstance, index: MembershipIndex): RlnResult[void] =
  ## Reset the leaf at `index` to zero and propagate up.  Does not change
  ## the next-index counter — previously used slots cannot be reused
  ## (replay safety; matches zerokit pmtree semantics).
  let r = instance.tree.deleteLeaf(uint64(index))
  if r.isErr:
    return err("Failed to remove member: " & r.error)
  ok()

proc insertMemberAt*(
    instance: RLNInstance, index: MembershipIndex, commitment: IDCommitment
): RlnResult[void] =
  let r = instance.tree.setLeaf(uint64(index), commitment)
  if r.isErr:
    return err("Failed to insert member at index: " & r.error)
  ok()

proc flush*(ctx: ptr RLN): bool =
  ## No-op: the Nim IMT is always in-sync; callers that took a `ptr RLN`
  ## (group_manager pre-proof flush + post-load flush) keep the same signature.
  discard ctx
  true

proc imtPath(
    instance: RLNInstance, memberIndex: MembershipIndex
): RlnResult[tuple[pathElements: seq[byte], pathIndex: seq[byte]]] =
  ## Pull a Merkle inclusion path for `memberIndex` out of the Nim IMT in
  ## the (path_elements bytes, path_index bytes) shape that the byte-based
  ## `buildWitness` and the `ffi_rln_partial_witness_input_new` reconstruction
  ## both consume.
  instance.tree.getInclusionProof(uint64(memberIndex))

proc pathBytesToVec(
    pathElements: openArray[byte], pathIndexLen: int
): RlnResult[Vec_CFr] =
  ## Reconstruct a `Vec_CFr` from concatenated 32-byte LE elements.  Caller
  ## owns the returned Vec_CFr and must free it with `ffi_vec_cfr_free`.
  if pathElements.len != pathIndexLen * FieldElementSize:
    return err(
      "Invalid Merkle path: expected " & $(pathIndexLen * FieldElementSize) &
        " bytes, got " & $pathElements.len
    )
  var vec = ffi_vec_cfr_new(CSize(pathIndexLen))
  for i in 0 ..< pathIndexLen:
    let start = i * FieldElementSize
    let element = bytesToCfrLe(
      pathElements.toOpenArray(start, start + FieldElementSize - 1)
    ).valueOr:
      ffi_vec_cfr_free(vec)
      return err(error)
    ffi_vec_cfr_push(addr vec, element)
    ffi_cfr_free(element)
  ok(vec)

proc generatePartialProofCache*(
    instance: RLNInstance,
    credential: IdentityCredential,
    memberIndex: MembershipIndex,
    userMessageLimit: uint64 = UserMessageLimit,
): RlnResult[PartialProofCache] =
  let (pathElements, pathIndex) = instance.imtPath(memberIndex).valueOr:
    return err(error)

  let currentRoot = instance.getMerkleRoot().valueOr:
    return err("Failed to get current root for partial proof cache: " & error)

  var pathElementsVec = pathBytesToVec(pathElements, pathIndex.len).valueOr:
    return err(error)
  defer:
    ffi_vec_cfr_free(pathElementsVec)
  var pathIndexVec = toVecUint8(pathIndex)

  let identitySecret = bytesToCfrLe(credential.idSecretHash).valueOr:
    return err(error)
  defer:
    ffi_cfr_free(identitySecret)

  let userLimit = bytesToCfrLe(uint64ToField(userMessageLimit)).valueOr:
    return err(error)
  defer:
    ffi_cfr_free(userLimit)

  let partialWitnessRes = ffi_rln_partial_witness_input_new(
    identitySecret, userLimit, addr pathElementsVec, addr pathIndexVec
  )
  if partialWitnessRes.ok.isNil:
    return
      err(consumeError("Failed to create partial witness: ", partialWitnessRes.err))

  var ctx = instance.ctx
  var partialWitness = partialWitnessRes.ok
  let partialProofRes = ffi_generate_partial_zk_proof(addr ctx, addr partialWitness)
  ffi_rln_partial_witness_input_free(partialWitness)
  if partialProofRes.ok.isNil:
    return err(consumeError("Failed to generate partial proof: ", partialProofRes.err))

  var partialProof = partialProofRes.ok
  let bytesRes = ffi_rln_partial_proof_to_bytes_le(addr partialProof)
  ffi_rln_partial_proof_free(partialProof)
  if hasError(bytesRes.err):
    return err(consumeError("Failed to serialize partial proof: ", bytesRes.err))
  defer:
    ffi_vec_u8_free(bytesRes.ok)

  ok(
    PartialProofCache(
      root: currentRoot,
      memberIndex: memberIndex,
      partialProofBytes: vecToSeq(bytesRes.ok),
      pathElements: pathElements,
      pathIndex: pathIndex,
    )
  )

proc generateRlnProofWithWitness*(
    instance: RLNInstance,
    credential: IdentityCredential,
    memberIndex: MembershipIndex,
    epoch: Epoch,
    rlnIdentifier: RlnIdentifier,
    signal: openArray[byte],
    messageId: uint = 0,
    userMessageLimit: uint64 = UserMessageLimit,
): RlnResult[RateLimitProof] =
  let (pathElements, pathIndex) = instance.imtPath(memberIndex).valueOr:
    return err(error)

  let witness = buildWitness(
    pathElements, pathIndex, credential, epoch, rlnIdentifier, signal, messageId,
    userMessageLimit,
  ).valueOr:
    return err(error)
  defer:
    ffi_rln_witness_input_free(witness)

  var ctx = instance.ctx
  var witnessHandle = witness
  let proofRes = ffi_generate_rln_proof(addr ctx, addr witnessHandle)
  if proofRes.ok.isNil:
    return err(consumeError("Failed to generate RLN proof: ", proofRes.err))
  defer:
    ffi_rln_proof_free(proofRes.ok)

  proofPtrToRateLimitProof(proofRes.ok, epoch)

proc finishRlnProofWithCache*(
    instance: RLNInstance,
    cache: PartialProofCache,
    credential: IdentityCredential,
    memberIndex: MembershipIndex,
    epoch: Epoch,
    rlnIdentifier: RlnIdentifier,
    signal: openArray[byte],
    messageId: uint = 0,
    userMessageLimit: uint64 = UserMessageLimit,
): RlnResult[RateLimitProof] =
  let currentRoot = instance.getMerkleRoot().valueOr:
    return err("Failed to get current root: " & error)

  if currentRoot != cache.root:
    return err("Cached partial proof is stale for the current Merkle root")

  if memberIndex != cache.memberIndex:
    return err("Cached partial proof does not match the requested membership index")

  let witness = buildWitness(
    cache.pathElements, cache.pathIndex, credential, epoch, rlnIdentifier, signal,
    messageId, userMessageLimit,
  ).valueOr:
    return err(error)
  defer:
    ffi_rln_witness_input_free(witness)

  var partialBytesVec = toVecUint8(cache.partialProofBytes)
  let partialProofRes = ffi_bytes_le_to_rln_partial_proof(addr partialBytesVec)
  if partialProofRes.ok.isNil:
    return err(
      consumeError("Failed to deserialize cached partial proof: ", partialProofRes.err)
    )
  defer:
    ffi_rln_partial_proof_free(partialProofRes.ok)

  var ctx = instance.ctx
  var partialProof = partialProofRes.ok
  var witnessHandle = witness
  let proofRes = ffi_finish_rln_proof(addr ctx, addr partialProof, addr witnessHandle)
  if proofRes.ok.isNil:
    return err(consumeError("Failed to finish RLN proof: ", proofRes.err))
  defer:
    ffi_rln_proof_free(proofRes.ok)

  proofPtrToRateLimitProof(proofRes.ok, epoch)

proc verifyRlnProof*(
    instance: RLNInstance,
    proof: RateLimitProof,
    rlnIdentifier: RlnIdentifier,
    signal: openArray[byte],
    validRoots: seq[MerkleNode],
): RlnResult[bool] =
  # v2.0.2: build the FFI_RLNProof directly from its field elements via
  # ffi_rln_proof_new, instead of round-tripping through the 290-byte
  # wire layout.
  if validRoots.len == 0:
    return err("verifyRlnProof requires at least one valid root")

  let externalNullifier = computeExternalNullifier(proof.epoch, rlnIdentifier).valueOr:
    return err("Failed to compute external nullifier: " & error)

  var groth16Vec = toVecUint8(proof.proof)

  let rootFr = bytesToCfrLe(proof.merkleRoot).valueOr:
    return err("Failed to convert root: " & error)
  defer:
    ffi_cfr_free(rootFr)

  let extNullFr = bytesToCfrLe(externalNullifier).valueOr:
    return err("Failed to convert external nullifier: " & error)
  defer:
    ffi_cfr_free(extNullFr)

  let shareXFr = bytesToCfrLe(proof.shareX).valueOr:
    return err("Failed to convert shareX: " & error)
  defer:
    ffi_cfr_free(shareXFr)

  let shareYFr = bytesToCfrLe(proof.shareY).valueOr:
    return err("Failed to convert shareY: " & error)
  defer:
    ffi_cfr_free(shareYFr)

  let nullifierFr = bytesToCfrLe(proof.nullifier).valueOr:
    return err("Failed to convert nullifier: " & error)
  defer:
    ffi_cfr_free(nullifierFr)

  let proofRes = ffi_rln_proof_new(
    addr groth16Vec, rootFr, extNullFr, shareXFr, shareYFr, nullifierFr
  )
  if proofRes.ok.isNil:
    return
      err(consumeError("Failed to build RLN proof for verification: ", proofRes.err))
  defer:
    ffi_rln_proof_free(proofRes.ok)

  let x = hashToFieldLe(signal).valueOr:
    return err(error)
  defer:
    ffi_cfr_free(x)

  var ctx = instance.ctx
  var proofHandle = proofRes.ok

  var roots = toRootVec(validRoots).valueOr:
    return err("Failed to build root vector: " & error)
  defer:
    ffi_vec_cfr_free(roots)

  let verifyRes = ffi_verify_with_roots(addr ctx, addr proofHandle, addr roots, x)
  if hasError(verifyRes.err):
    return err(consumeError("Proof verification failed: ", verifyRes.err))
  ok(verifyRes.ok)

proc recoverSecret*(
    instance: RLNInstance, proof1: RateLimitProof, proof2: RateLimitProof
): RlnResult[array[32, byte]] =
  discard instance
  if proof1.nullifier != proof2.nullifier:
    return err("Cannot recover secret: proofs have different nullifiers")

  let share1X = bytesToCfrLe(proof1.shareX).valueOr:
    return err(error)
  defer:
    ffi_cfr_free(share1X)

  let share1Y = bytesToCfrLe(proof1.shareY).valueOr:
    return err(error)
  defer:
    ffi_cfr_free(share1Y)

  let share2X = bytesToCfrLe(proof2.shareX).valueOr:
    return err(error)
  defer:
    ffi_cfr_free(share2X)

  let share2Y = bytesToCfrLe(proof2.shareY).valueOr:
    return err(error)
  defer:
    ffi_cfr_free(share2Y)

  let secretRes = ffi_compute_id_secret(share1X, share1Y, share2X, share2Y)
  cfrResultToBytes(secretRes, "Failed to recover secret: ")
