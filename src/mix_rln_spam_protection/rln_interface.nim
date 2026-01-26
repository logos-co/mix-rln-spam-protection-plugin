# Mix RLN Spam Protection Plugin
# Copyright (c) 2025 vacp2p
# Licensed under either of Apache License 2.0 or MIT license.

## Nim wrappers for the functions defined in librln.
## This module closely follows logos-messaging-nim's waku_rln_relay/rln/rln_interface.nim
## to ensure compatibility with their zerokit (v0.9.0) integration.

import results, chronicles
import nimcrypto/keccak as keccak
import stew/[arrayops, endians2]
import ./types
import ./constants

{.push raises: [].}

logScope:
  topics = "rln interface"

# Buffer struct - matches zerokit FFI interface
# https://github.com/celo-org/celo-threshold-bls-rs/blob/master/crates/threshold-bls-ffi/src/ffi.rs
type
  Buffer* = object
    `ptr`*: ptr uint8
    len*: uint

  RLN* = object ## Opaque RLN context handle

proc toBuffer*(x: openArray[byte]): Buffer =
  ## Converts the input to a Buffer object.
  ## The Buffer object is used to communicate data with the rln lib.
  var temp = @x
  let baseAddr = cast[pointer](x)
  let output = Buffer(`ptr`: cast[ptr uint8](baseAddr), len: uint(temp.len))
  return output

######################################################################
## RLN Zerokit module APIs
######################################################################

#-------------------------------- zkSNARKs operations -----------------------------------------

proc key_gen*(
  output_buffer: ptr Buffer, is_little_endian: bool
): bool {.importc: "extended_key_gen".}

## Generates identity trapdoor, identity nullifier, identity secret hash and id commitment
## tuple serialized inside output_buffer as:
## | identity_trapdoor<32> | identity_nullifier<32> | identity_secret_hash<32> | id_commitment<32> |
## identity secret hash is the poseidon hash of [identity_trapdoor, identity_nullifier]
## id commitment is the poseidon hash of the identity secret hash
## the return bool value indicates the success or failure of the operation

proc seeded_key_gen*(
  input_buffer: ptr Buffer, output_buffer: ptr Buffer, is_little_endian: bool
): bool {.importc: "seeded_extended_key_gen".}

## Generates identity credentials using ChaCha20 seeded with an arbitrary long seed
## serialized in input_buffer. The input seed is hashed using Keccak256 before
## being passed to ChaCha20 as seed.
## Output format same as key_gen.

proc generate_proof*(
  ctx: ptr RLN, input_buffer: ptr Buffer, output_buffer: ptr Buffer
): bool {.importc: "generate_rln_proof".}

## rln-v2
## input_buffer: [ identity_secret<32> | identity_index<8> | user_message_limit<32> | message_id<32> | external_nullifier<32> | signal_len<8> | signal<var> ]
## output_buffer: [ proof<128> | root<32> | external_nullifier<32> | share_x<32> | share_y<32> | nullifier<32> ]

proc generate_proof_with_witness*(
  ctx: ptr RLN, input_buffer: ptr Buffer, output_buffer: ptr Buffer
): bool {.importc: "generate_rln_proof_with_witness".}

## rln-v2 with witness (collection of secret inputs with proper serialization)
## input_buffer: [ identity_secret<32> | user_message_limit<32> | message_id<32> | path_elements<Vec<32>> | identity_path_index<Vec<1>> | x<32> | external_nullifier<32> ]
## output_buffer: [ proof<128> | root<32> | external_nullifier<32> | share_x<32> | share_y<32> | nullifier<32> ]

proc verify*(
  ctx: ptr RLN, proof_buffer: ptr Buffer, proof_is_valid_ptr: ptr bool
): bool {.importc: "verify_rln_proof".}

## rln-v2
## proof_buffer: [ proof<128> | root<32> | external_nullifier<32> | share_x<32> | share_y<32> | nullifier<32> | signal_len<8> | signal<var> ]
## proof_is_valid_ptr: true if proof is valid, false otherwise
## return: true if function executed successfully

proc verify_with_roots*(
  ctx: ptr RLN,
  proof_buffer: ptr Buffer,
  roots_buffer: ptr Buffer,
  proof_is_valid_ptr: ptr bool,
): bool {.importc: "verify_with_roots".}

## Same as verify but accepts multiple valid roots for verification
## roots_buffer: concatenation of 32-byte root values in little endian

proc zk_prove*(
  ctx: ptr RLN, input_buffer: ptr Buffer, output_buffer: ptr Buffer
): bool {.importc: "prove".}

## Low-level zkSNARK proof generation
## output_buffer: [ proof<128> ]

proc zk_verify*(
  ctx: ptr RLN, proof_buffer: ptr Buffer, proof_is_valid_ptr: ptr bool
): bool {.importc: "verify".}

## Low-level zkSNARK proof verification

#-------------------------------- Merkle tree operations -----------------------------------------

proc set_leaf*(
  ctx: ptr RLN, index: uint, input_buffer: ptr Buffer
): bool {.importc: "set_leaf".}

## Sets a leaf at the given index in the Merkle tree

proc set_next_leaf*(
  ctx: ptr RLN, input_buffer: ptr Buffer
): bool {.importc: "set_next_leaf".}

## Sets the next available leaf in the Merkle tree

proc delete_leaf*(ctx: ptr RLN, index: uint): bool {.importc: "delete_leaf".}
## Deletes a leaf at the given index

proc get_leaf*(
  ctx: ptr RLN, index: uint, output_buffer: ptr Buffer
): bool {.importc: "get_leaf".}

## Gets the leaf value at the given index

proc leaves_set*(ctx: ptr RLN): uint {.importc: "leaves_set".}
## Returns the number of leaves set in the tree

proc get_root*(ctx: ptr RLN, output_buffer: ptr Buffer): bool {.importc: "get_root".}
## Gets the current Merkle root

proc get_proof*(
  ctx: ptr RLN, index: uint, output_buffer: ptr Buffer
): bool {.importc: "get_proof".}

## Gets the Merkle proof for a leaf at the given index

proc init_tree_with_leaves*(
  ctx: ptr RLN, input_buffer: ptr Buffer
): bool {.importc: "init_tree_with_leaves".}

## Initializes the tree with a batch of leaves

proc set_leaves_from*(
  ctx: ptr RLN, index: uint, input_buffer: ptr Buffer
): bool {.importc: "set_leaves_from".}

## Sets multiple leaves starting from the given index

proc atomic_operation*(
  ctx: ptr RLN, index: uint, leaves_buffer: ptr Buffer, indices_buffer: ptr Buffer
): bool {.importc: "atomic_operation".}

## Atomic batch update operation

proc seq_atomic_operation*(
  ctx: ptr RLN, leaves_buffer: ptr Buffer, indices_buffer: ptr Buffer
): bool {.importc: "seq_atomic_operation".}

## Sequential atomic batch operation

#-------------------------------- Common procedures -------------------------------------------

# Note: new_circuit functions are called via inline C to avoid Nim overload issues

proc new_circuit_from_data*(
  zkey_buffer: ptr Buffer, graph_buffer: ptr Buffer, ctx: ptr (ptr RLN)
): bool {.importc: "new_with_params".}

## Creates an RLN instance from raw circuit data buffers

#-------------------------------- Hashing utils -------------------------------------------

proc sha256*(
  input_buffer: ptr Buffer, output_buffer: ptr Buffer, is_little_endian: bool
): bool {.importc: "hash".}

## SHA256 hash mapped to field element (for signal hashing)

proc poseidon*(
  input_buffer: ptr Buffer, output_buffer: ptr Buffer, is_little_endian: bool
): bool {.importc: "poseidon_hash".}

## Poseidon hash (for identity secret hash, external nullifier computation)

#-------------------------------- Secret recovery (for slashing) ----------------------------

proc recover_id_secret*(
  ctx: ptr RLN,
  proof1_buffer: ptr Buffer,
  proof2_buffer: ptr Buffer,
  output_buffer: ptr Buffer,
): bool {.importc: "recover_id_secret".}

## Recovers the identity secret from two proofs with the same nullifier

#-------------------------------- Metadata -------------------------------------------

proc set_metadata*(
  ctx: ptr RLN, input_buffer: ptr Buffer
): bool {.importc: "set_metadata".}

## Sets metadata on the RLN instance

proc get_metadata*(
  ctx: ptr RLN, output_buffer: ptr Buffer
): bool {.importc: "get_metadata".}

## Gets metadata from the RLN instance

proc flush*(ctx: ptr RLN): bool {.importc: "flush".}
## Flushes any pending writes

######################################################################
## High-level Nim wrappers (matching logos-messaging patterns)
######################################################################

type RLNInstance* = ref object ## High-level wrapper around the zerokit RLN instance.
  ctx*: ptr RLN

# Note: RlnResult[T] is defined in types.nim to avoid circular imports

proc membershipKeyGen*(): RlnResult[IdentityCredential] =
  ## Generates an IdentityCredential that can be used for registration.
  ## Returns an error if the key generation fails.
  ## This matches logos-messaging-nim's membershipKeyGen in wrappers.nim
  var
    keysBuffer: Buffer
    keysBufferPtr = addr(keysBuffer)
    done = key_gen(keysBufferPtr, true)

  if not done:
    return err("error in key generation")

  if keysBuffer.len != 4 * 32:
    return err("keysBuffer is of invalid length: " & $keysBuffer.len)

  var generatedKeys = cast[ptr array[4 * 32, byte]](keysBufferPtr.`ptr`)[]

  var cred: IdentityCredential
  for i in 0 ..< 32:
    cred.idTrapdoor[i] = generatedKeys[i + 0 * 32]
    cred.idNullifier[i] = generatedKeys[i + 1 * 32]
    cred.idSecretHash[i] = generatedKeys[i + 2 * 32]
    cred.idCommitment[i] = generatedKeys[i + 3 * 32]

  return ok(cred)

proc membershipKeyGen*(seed: openArray[byte]): RlnResult[IdentityCredential] =
  ## Generates a deterministic IdentityCredential from a seed.
  ## The seed is hashed with Keccak256 before being passed to ChaCha20.
  var
    seedData = @seed
    seedBuffer = seedData.toBuffer()
    keysBuffer: Buffer
    keysBufferPtr = addr(keysBuffer)
    done = seeded_key_gen(addr seedBuffer, keysBufferPtr, true)

  if not done:
    return err("error in seeded key generation")

  if keysBuffer.len != 4 * 32:
    return err("keysBuffer is of invalid length: " & $keysBuffer.len)

  var generatedKeys = cast[ptr array[4 * 32, byte]](keysBufferPtr.`ptr`)[]

  var cred: IdentityCredential
  for i in 0 ..< 32:
    cred.idTrapdoor[i] = generatedKeys[i + 0 * 32]
    cred.idNullifier[i] = generatedKeys[i + 1 * 32]
    cred.idSecretHash[i] = generatedKeys[i + 2 * 32]
    cred.idCommitment[i] = generatedKeys[i + 3 * 32]

  return ok(cred)

# Aliases to match existing API
proc generateMembershipKey*(): RlnResult[IdentityCredential] =
  membershipKeyGen()

proc generateMembershipKey*(seed: openArray[byte]): RlnResult[IdentityCredential] =
  membershipKeyGen(seed)

proc createRLNInstance*(resourcesPath: string = ""): RlnResult[RLNInstance] =
  ## Creates an RLN instance.
  ## If resourcesPath is empty, uses bundled resources.
  trace "Creating RLN instance", resourcesPath = resourcesPath
  var ctx: ptr RLN
  var success: bool

  # Use JSON config format like waku-rln-relay
  # "tree_height_/" is a special placeholder that tells zerokit to use bundled resources
  let folder = if resourcesPath.len == 0: "tree_height_/" else: resourcesPath

  # Create JSON config matching waku-rln-relay format
  let configJson =
    "{\"resources_folder\":\"" & folder &
    "\",\"tree_config\":{\"cache_capacity\":15000,\"mode\":\"high_throughput\",\"compression\":false,\"flush_every_ms\":500}}"

  trace "RLN config", config = configJson
  var configBytes = newSeq[byte](configJson.len)
  copyMem(addr configBytes[0], unsafeAddr configJson[0], configJson.len)
  var configBuffer = configBytes.toBuffer()
  let treeDepth = MerkleTreeDepth.uint

  {.
    emit:
      """
  extern NIM_BOOL new(unsigned int tree_depth, void* input_buffer, void** ctx);
  `success` = new(`treeDepth`, &`configBuffer`, &`ctx`);
  """
  .}

  if not success or ctx.isNil:
    error "Failed to create RLN instance", success = success, ctxIsNil = ctx.isNil
    return err("Failed to create RLN instance")

  # Log the initial root of the fresh tree
  var initialRootBuffer: Buffer
  var initialRoot: array[32, byte]
  if get_root(ctx, addr initialRootBuffer):
    if initialRootBuffer.len == 32:
      copyMem(addr initialRoot[0], initialRootBuffer.`ptr`, 32)

  debug "RLN instance created successfully", initialTreeRoot = initialRoot.toHex()

  ok(RLNInstance(ctx: ctx))

# Alias
proc newRLNInstance*(resourcesPath: string = ""): RlnResult[RLNInstance] =
  createRLNInstance(resourcesPath)

proc poseidonHash*(inputs: seq[seq[byte]]): RlnResult[array[32, byte]] =
  ## Poseidon hash of concatenated inputs.
  ## Matches logos-messaging-nim's poseidon wrapper.
  ## 
  ## The RLN library expects input format:
  ## [length<8 bytes LE>][field_element_1<32>][field_element_2<32>]...
  var inputData = newSeq[byte]()

  # Add length prefix (number of field elements as u64 little-endian)
  let numElements = uint64(inputs.len)
  var lengthBytes: array[8, byte]
  copyMem(addr lengthBytes[0], unsafeAddr numElements, 8)
  inputData.add(lengthBytes)

  # Add each field element
  for input in inputs:
    inputData.add(input)

  trace "Computing Poseidon hash", inputLen = inputData.len, numInputs = inputs.len
  var inputBuffer = inputData.toBuffer()
  var outputBuffer: Buffer

  if not poseidon(addr inputBuffer, addr outputBuffer, true):
    error "Poseidon FFI call failed", inputLen = inputData.len
    return err("Poseidon hash failed")

  if outputBuffer.len != 32:
    error "Invalid poseidon output length", outputLen = outputBuffer.len
    return err("Invalid poseidon output length")

  var hashResult: array[32, byte]
  copyMem(addr hashResult[0], outputBuffer.`ptr`, 32)
  trace "Poseidon hash computed successfully", outputLen = outputBuffer.len
  ok(hashResult)

proc keccak256Hash*(data: openArray[byte]): RlnResult[array[32, byte]] =
  ## Compute Keccak256 hash of data using nimcrypto.
  ## Note: zerokit doesn't export keccak256, so we use nimcrypto directly.
  let hashDigest = keccak.keccak256.digest(data)
  var hashResult: array[32, byte]
  copyMem(addr hashResult[0], unsafeAddr hashDigest.data[0], 32)
  ok(hashResult)

proc computeExternalNullifier*(
    epoch: Epoch, rlnIdentifier: RlnIdentifier
): RlnResult[ExternalNullifier] =
  ## Compute external nullifier = Poseidon(epoch, rlnIdentifier)
  ## This matches logos-messaging-nim's generateExternalNullifier
  poseidonHash(@[@epoch, @rlnIdentifier])

proc computeRateCommitment*(
    idCommitment: IDCommitment, userMessageLimit: uint64
): RlnResult[IDCommitment] =
  ## Compute rate commitment = Poseidon(idCommitment, userMessageLimit)
  ## This is the actual leaf value stored in the RLN Merkle tree.
  ## Note: The tree stores rate_commitment, not id_commitment!
  var limitBytes: array[32, byte]
  # Convert userMessageLimit to 32-byte little-endian field element
  limitBytes[0] = byte(userMessageLimit and 0xFF)
  limitBytes[1] = byte((userMessageLimit shr 8) and 0xFF)
  limitBytes[2] = byte((userMessageLimit shr 16) and 0xFF)
  limitBytes[3] = byte((userMessageLimit shr 24) and 0xFF)
  limitBytes[4] = byte((userMessageLimit shr 32) and 0xFF)
  limitBytes[5] = byte((userMessageLimit shr 40) and 0xFF)
  limitBytes[6] = byte((userMessageLimit shr 48) and 0xFF)
  limitBytes[7] = byte((userMessageLimit shr 56) and 0xFF)
  # Rest is zero-padded

  let hashResult = poseidonHash(@[@idCommitment, @limitBytes]).valueOr:
    return err("Failed to compute rate commitment: " & error)

  var rateCommitment: IDCommitment
  copyMem(addr rateCommitment[0], unsafeAddr hashResult[0], 32)
  ok(rateCommitment)

proc getMerkleRoot*(instance: RLNInstance): RlnResult[MerkleNode] =
  ## Gets the current Merkle root.
  var outputBuffer: Buffer

  if not get_root(instance.ctx, addr outputBuffer):
    return err("Failed to get Merkle root")

  if outputBuffer.len != 32:
    return err("Invalid root length")

  var root: MerkleNode
  copyMem(addr root[0], outputBuffer.`ptr`, 32)
  ok(root)

proc getMerkleProof*(
    instance: RLNInstance, index: MembershipIndex
): RlnResult[seq[byte]] =
  ## Gets the Merkle proof for a member at the given index.
  var outputBuffer: Buffer

  if not get_proof(instance.ctx, uint(index), addr outputBuffer):
    return err("Failed to get Merkle proof")

  var proof = newSeq[byte](outputBuffer.len)
  if outputBuffer.len > 0:
    copyMem(addr proof[0], outputBuffer.`ptr`, outputBuffer.len)

  trace "getMerkleProof returned", index = index, proofLen = proof.len

  ok(proof)

proc getLeaf*(instance: RLNInstance, index: MembershipIndex): RlnResult[IDCommitment] =
  ## Gets the leaf value (ID commitment) at the given index.
  var outputBuffer: Buffer

  if not get_leaf(instance.ctx, uint(index), addr outputBuffer):
    return err("Failed to get leaf at index " & $index)

  if outputBuffer.len != 32:
    return err("Invalid leaf length: " & $outputBuffer.len)

  var commitment: IDCommitment
  copyMem(addr commitment[0], outputBuffer.`ptr`, 32)
  ok(commitment)

proc insertMember*(
    instance: RLNInstance, commitment: IDCommitment
): RlnResult[MembershipIndex] =
  ## Inserts a new member into the Merkle tree.
  ## Returns the index of the inserted member.
  let currentIndex = leaves_set(instance.ctx)

  var commitmentData = @commitment
  var inputBuffer = commitmentData.toBuffer()

  if not set_next_leaf(instance.ctx, addr inputBuffer):
    return err("Failed to insert member")

  ok(MembershipIndex(currentIndex))

proc insertMembers*(
    instance: RLNInstance, startIndex: MembershipIndex, commitments: seq[IDCommitment]
): RlnResult[void] =
  ## Inserts multiple members starting at the given index.
  if commitments.len == 0:
    return ok()

  var inputData = newSeq[byte](commitments.len * HashByteSize)
  for i, commitment in commitments:
    copyMem(addr inputData[i * HashByteSize], unsafeAddr commitment[0], HashByteSize)

  var inputBuffer = inputData.toBuffer()

  if not set_leaves_from(instance.ctx, uint(startIndex), addr inputBuffer):
    return err("Failed to insert members")

  ok()

proc removeMember*(instance: RLNInstance, index: MembershipIndex): RlnResult[void] =
  ## Removes a member from the Merkle tree.
  if not delete_leaf(instance.ctx, uint(index)):
    return err("Failed to remove member")
  ok()

proc insertMemberAt*(
    instance: RLNInstance, index: MembershipIndex, commitment: IDCommitment
): RlnResult[void] =
  ## Inserts a member at a specific index in the Merkle tree.
  var commitmentData = @commitment
  var inputBuffer = commitmentData.toBuffer()

  if not set_leaf(instance.ctx, uint(index), addr inputBuffer):
    return err("Failed to insert member at index")
  ok()

# ----------------- Witness-based proof generation -----------------

proc serialize*(witness: RLNWitnessInput): seq[byte] =
  ## Serializes the RLN witness into a byte array following zerokit's expected format.
  ## The serialized format includes:
  ## - identity_secret (32 bytes)
  ## - user_message_limit (32 bytes)
  ## - message_id (32 bytes)
  ## - merkle tree depth (8 bytes, little-endian) = path_elements.len / 32
  ## - path_elements (each 32 bytes, ordered bottom-to-top)
  ## - merkle tree depth again (8 bytes, little-endian)
  ## - identity_path_index (sequence of bits as bytes, 0 = left, 1 = right)
  ## - x (32 bytes)
  ## - external_nullifier (32 bytes)
  var buffer: seq[byte]
  buffer.add(@(witness.identity_secret))
  buffer.add(@(witness.user_message_limit))
  buffer.add(@(witness.message_id))

  let depth = uint64(witness.path_elements.len div 32)
  # Depth as 8-byte little-endian
  for i in 0 ..< 8:
    buffer.add(byte((depth shr (i * 8)) and 0xFF))

  # Path elements (should be depth * 32 bytes)
  buffer.add(witness.path_elements)

  # Depth again as 8-byte little-endian
  for i in 0 ..< 8:
    buffer.add(byte((depth shr (i * 8)) and 0xFF))

  # Identity path index (depth bytes, each 0 or 1)
  buffer.add(witness.identity_path_index)

  buffer.add(@(witness.x))
  buffer.add(@(witness.external_nullifier))
  return buffer

proc generateRlnProofWithWitness*(
    instance: RLNInstance,
    credential: IdentityCredential,
    memberIndex: MembershipIndex,
    epoch: Epoch,
    rlnIdentifier: RlnIdentifier,
    signal: openArray[byte],
    messageId: uint = 0,
): RlnResult[RateLimitProof] =
  ## Generate an RLN proof using explicit Merkle proof (witness-based).
  ## This bypasses zerokit's internal Merkle cache by fetching the proof
  ## explicitly and using generate_proof_with_witness FFI.
  ## 
  ## This matches waku's OnchainGroupManager approach for reliable proof generation.

  const MerkleTreeDepth = 20 # Standard RLN tree depth

  # Flush tree to ensure it's synced
  discard flush(instance.ctx)

  # Get the Merkle proof for our index
  let merkleProofBytes = instance.getMerkleProof(memberIndex).valueOr:
    return err("Failed to get Merkle proof: " & error)

  trace "Got Merkle proof for witness-based proof generation",
    memberIndex = memberIndex, proofBytesLen = merkleProofBytes.len

  # Verify we got expected number of bytes
  # Format: [8-byte len][20*32 path_elements][8-byte len][20 identity_path_index]
  # Total: 8 + 640 + 8 + 20 = 676 bytes
  const ExpectedProofSize = 8 + MerkleTreeDepth * 32 + 8 + MerkleTreeDepth
  if merkleProofBytes.len < ExpectedProofSize:
    return err(
      "Merkle proof too short: expected " & $ExpectedProofSize & " bytes, got " &
        $merkleProofBytes.len
    )

  # Extract path elements from zerokit's get_proof output
  # Format: [8-byte length LE][path_elements...][8-byte length LE][identity_path_index...]
  # See zerokit/rln/src/utils.rs vec_fr_to_bytes_le and vec_u8_to_bytes_le
  const PathElementsOffset = 8 # Skip 8-byte length prefix
  const IdentityPathIndexOffset = PathElementsOffset + MerkleTreeDepth * 32 + 8
    # Skip path elements + second length prefix

  var pathElements = newSeq[byte](MerkleTreeDepth * 32)
  for i in 0 ..< MerkleTreeDepth * 32:
    pathElements[i] = merkleProofBytes[PathElementsOffset + i]

  # Extract identity path index from the proof (zerokit already computed it)
  var identityPathIndex = newSeq[byte](MerkleTreeDepth)
  for i in 0 ..< MerkleTreeDepth:
    identityPathIndex[i] = merkleProofBytes[IdentityPathIndexOffset + i]

  # Compute external nullifier = Poseidon(epoch, rlnIdentifier)
  let externalNullifier = poseidonHash(@[@epoch, @rlnIdentifier]).valueOr:
    return err("Failed to compute external nullifier: " & error)

  # Compute signal hash x = keccak256(signal)
  var x: Field
  if signal.len > 0:
    let signalHash = keccak256.digest(signal)
    for i in 0 ..< 32:
      x[i] = signalHash.data[i]

  # Build the witness input
  let witness = RLNWitnessInput(
    identity_secret: seqToField(@(credential.idSecretHash)),
    user_message_limit: uint64ToField(uint64(UserMessageLimit)),
    message_id: uint64ToField(uint64(messageId)),
    path_elements: pathElements,
    identity_path_index: identityPathIndex,
    x: x,
    external_nullifier: seqToField(@externalNullifier),
  )

  # Debug: log first path element and identity path index for verification
  var firstPathElement: string
  if pathElements.len >= 32:
    firstPathElement = pathElements[0 .. 31].toHex()
  var pathIndexStr: string
  for i in 0 ..< min(identityPathIndex.len, 10):
    pathIndexStr.add($identityPathIndex[i] & " ")

  trace "Built RLN witness for proof generation",
    memberIndex = memberIndex,
    pathElementsLen = pathElements.len,
    identityPathIndexLen = identityPathIndex.len,
    messageId = messageId

  # Serialize the witness
  let serializedWitness = witness.serialize()

  trace "Serialized witness for FFI", serializedLen = serializedWitness.len

  var inputBuffer = serializedWitness.toBuffer()
  var outputBuffer: Buffer

  # Call generate_proof_with_witness FFI
  if not generate_proof_with_witness(instance.ctx, addr inputBuffer, addr outputBuffer):
    error "generate_proof_with_witness FFI call failed"
    return err("Failed to generate RLN proof with witness")

  trace "generate_proof_with_witness FFI succeeded", outputLen = outputBuffer.len

  # Parse output: proof<128> | root<32> | external_nullifier<32> | share_x<32> | share_y<32> | nullifier<32>
  if outputBuffer.len < 288:
    return err("Invalid proof output length: " & $outputBuffer.len)

  let outputData = cast[ptr UncheckedArray[byte]](outputBuffer.`ptr`)

  var proof: RateLimitProof
  var offset = 0

  # zkSNARK proof (128 bytes)
  for i in 0 ..< 128:
    proof.proof[i] = outputData[offset + i]
  offset += 128

  # Merkle root (32 bytes)
  for i in 0 ..< 32:
    proof.merkleRoot[i] = outputData[offset + i]
  offset += 32

  # External nullifier / epoch (32 bytes) - we store epoch in proof
  for i in 0 ..< 32:
    proof.epoch[i] = epoch[i]
  offset += 32

  # Share X (32 bytes)
  for i in 0 ..< 32:
    proof.shareX[i] = outputData[offset + i]
  offset += 32

  # Share Y (32 bytes)
  for i in 0 ..< 32:
    proof.shareY[i] = outputData[offset + i]
  offset += 32

  # Nullifier (32 bytes)
  for i in 0 ..< 32:
    proof.nullifier[i] = outputData[offset + i]

  # Verify the proof root matches our current tree root
  let currentRoot = instance.getMerkleRoot().valueOr:
    warn "Could not verify proof root", error = error
    return ok(proof)

  debug "Witness-based proof generation complete",
    proofMerkleRoot = proof.merkleRoot.toHex(),
    currentMerkleRoot = currentRoot.toHex(),
    rootsMatch = proof.merkleRoot == currentRoot

  ok(proof)

proc generateRlnProof*(
    instance: RLNInstance,
    credential: IdentityCredential,
    memberIndex: MembershipIndex,
    epoch: Epoch,
    rlnIdentifier: RlnIdentifier,
    signal: openArray[byte],
    messageId: uint = 0,
): RlnResult[RateLimitProof] =
  ## Generate an RLN proof for a message using the standard generate_proof FFI.
  ## This lets zerokit handle Merkle proof retrieval internally.

  # Get root before flush for comparison
  var preFlushRoot: MerkleNode
  var preFlushRootBuffer: Buffer
  if get_root(instance.ctx, addr preFlushRootBuffer):
    if preFlushRootBuffer.len == 32:
      copyMem(addr preFlushRoot[0], preFlushRootBuffer.`ptr`, 32)

  # Flush tree to ensure internal state is synced
  let flushResult1 = flush(instance.ctx)

  # Get root after first flush
  var postFlush1Root: MerkleNode
  var postFlush1RootBuffer: Buffer
  if get_root(instance.ctx, addr postFlush1RootBuffer):
    if postFlush1RootBuffer.len == 32:
      copyMem(addr postFlush1Root[0], postFlush1RootBuffer.`ptr`, 32)

  # Second flush
  let flushResult2 = flush(instance.ctx)

  # Get root after second flush
  var postFlush2Root: MerkleNode
  var postFlush2RootBuffer: Buffer
  if get_root(instance.ctx, addr postFlush2RootBuffer):
    if postFlush2RootBuffer.len == 32:
      copyMem(addr postFlush2Root[0], postFlush2RootBuffer.`ptr`, 32)

  trace "Root comparison during proof generation",
    preFlushRoot = preFlushRoot.toHex(),
    postFlush1Root = postFlush1Root.toHex(),
    postFlush2Root = postFlush2Root.toHex(),
    flushResult1 = flushResult1,
    flushResult2 = flushResult2

  # Compute external nullifier = Poseidon(epoch, rlnIdentifier)
  let externalNullifier = poseidonHash(@[@epoch, @rlnIdentifier]).valueOr:
    return err("Failed to compute external nullifier: " & error)

  # Serialize input for standard generate_proof
  # Format: identity_secret<32> | identity_index<8> | user_message_limit<32> | message_id<32> | external_nullifier<32> | signal_len<8> | signal<var>
  var inputData = newSeq[byte]()

  # Identity secret (use identity secret hash, not trapdoor - matching waku)
  # The RLN circuit expects idSecretHash = Poseidon(idTrapdoor, idNullifier)
  inputData.add(@(credential.idSecretHash))

  # Member index (8 bytes, little-endian)
  let indexBytes = toBytes(uint64(memberIndex), Endianness.littleEndian)
  inputData.add(@indexBytes)

  # User message limit (32 bytes, little-endian)
  var userMsgLimit: array[32, byte]
  let limitBytes = toBytes(uint64(UserMessageLimit), Endianness.littleEndian)
  discard userMsgLimit.copyFrom(limitBytes)
  inputData.add(@userMsgLimit)

  # Message ID (32 bytes, little-endian)
  var msgIdBytes: array[32, byte]
  let msgIdEncoded = toBytes(uint64(messageId), Endianness.littleEndian)
  discard msgIdBytes.copyFrom(msgIdEncoded)
  inputData.add(@msgIdBytes)

  # External nullifier (32 bytes)
  inputData.add(@externalNullifier)

  # Signal length (8 bytes, little-endian)
  let signalLenBytes = toBytes(uint64(signal.len), Endianness.littleEndian)
  inputData.add(@signalLenBytes)

  # Signal data
  if signal.len > 0:
    inputData.add(@signal)

  trace "Calling generate_proof FFI",
    inputLen = inputData.len, signalLen = signal.len, memberIndex = memberIndex

  var inputBuffer = inputData.toBuffer()
  var outputBuffer: Buffer

  if not generate_proof(instance.ctx, addr inputBuffer, addr outputBuffer):
    error "generate_proof FFI call failed",
      inputLen = inputData.len, outputBufferLen = outputBuffer.len
    return err("Failed to generate RLN proof")

  trace "generate_proof FFI succeeded", outputLen = outputBuffer.len

  # Parse output: proof<128> | root<32> | external_nullifier<32> | share_x<32> | share_y<32> | nullifier<32>
  if outputBuffer.len < 288:
    return err("Invalid proof output length: " & $outputBuffer.len)

  let outputData = cast[ptr UncheckedArray[byte]](outputBuffer.`ptr`)

  var proof: RateLimitProof
  var offset = 0

  # zkSNARK proof (128 bytes)
  for i in 0 ..< 128:
    proof.proof[i] = outputData[offset + i]
  offset += 128

  # Merkle root (32 bytes)
  for i in 0 ..< 32:
    proof.merkleRoot[i] = outputData[offset + i]
  offset += 32

  # External nullifier / epoch (32 bytes) - we store epoch in proof
  for i in 0 ..< 32:
    proof.epoch[i] = epoch[i]
  offset += 32

  # Share X (32 bytes)
  for i in 0 ..< 32:
    proof.shareX[i] = outputData[offset + i]
  offset += 32

  # Share Y (32 bytes)
  for i in 0 ..< 32:
    proof.shareY[i] = outputData[offset + i]
  offset += 32

  # Nullifier (32 bytes)
  for i in 0 ..< 32:
    proof.nullifier[i] = outputData[offset + i]

  ok(proof)

proc verifyRlnProof*(
    instance: RLNInstance,
    proof: RateLimitProof,
    rlnIdentifier: RlnIdentifier,
    signal: openArray[byte],
    validRoots: seq[MerkleNode] = @[],
): RlnResult[bool] =
  ## Verify an RLN proof.

  # Compute external nullifier
  let externalNullifier = poseidonHash(@[@(proof.epoch), @rlnIdentifier]).valueOr:
    return err("Failed to compute external nullifier: " & error)

  # Serialize proof for verification
  # Format: proof<128> | root<32> | external_nullifier<32> | share_x<32> | share_y<32> | nullifier<32> | signal_len<8> | signal<var>
  var proofData = newSeq[byte]()

  proofData.add(@(proof.proof))
  proofData.add(@(proof.merkleRoot))
  proofData.add(@externalNullifier)
  proofData.add(@(proof.shareX))
  proofData.add(@(proof.shareY))
  proofData.add(@(proof.nullifier))

  # Signal length (8 bytes little-endian)
  let sigLen = uint64(signal.len)
  for i in 0 ..< 8:
    proofData.add(byte((sigLen shr (i * 8)) and 0xFF))

  # Signal
  proofData.add(@signal)

  var proofBuffer = proofData.toBuffer()
  var isValid: bool = false

  if validRoots.len > 0:
    # Verify with multiple roots
    var rootsData = newSeq[byte]()
    for root in validRoots:
      rootsData.add(@root)
    var rootsBuffer = rootsData.toBuffer()

    if not verify_with_roots(
      instance.ctx, addr proofBuffer, addr rootsBuffer, addr isValid
    ):
      return err("Proof verification call failed")
  else:
    # Verify with current root only
    if not verify(instance.ctx, addr proofBuffer, addr isValid):
      return err("Proof verification call failed")

  ok(isValid)

proc serializeForFfi(proof: RateLimitProof): seq[byte] =
  ## Serialize a RateLimitProof in the format expected by librln FFI.
  ## Format: proof(128) + merkleRoot(32) + epoch(32) + shareX(32) + shareY(32) + nullifier(32) = 288 bytes
  ## Note: This is different from protobuf encoding used for network transmission.
  result = newSeq[byte](RateLimitProofByteSize)
  var offset = 0

  copyMem(addr result[offset], unsafeAddr proof.proof[0], ZksnarkProofByteSize)
  offset += ZksnarkProofByteSize

  copyMem(addr result[offset], unsafeAddr proof.merkleRoot[0], HashByteSize)
  offset += HashByteSize

  copyMem(addr result[offset], unsafeAddr proof.epoch[0], HashByteSize)
  offset += HashByteSize

  copyMem(addr result[offset], unsafeAddr proof.shareX[0], HashByteSize)
  offset += HashByteSize

  copyMem(addr result[offset], unsafeAddr proof.shareY[0], HashByteSize)
  offset += HashByteSize

  copyMem(addr result[offset], unsafeAddr proof.nullifier[0], HashByteSize)

proc recoverSecret*(
    instance: RLNInstance, proof1: RateLimitProof, proof2: RateLimitProof
): RlnResult[array[32, byte]] =
  ## Recovers the identity secret from two proofs with the same nullifier.
  ## Used for slashing/logging spammers.
  var proof1Data = proof1.serializeForFfi()
  var proof2Data = proof2.serializeForFfi()
  var proof1Buffer = proof1Data.toBuffer()
  var proof2Buffer = proof2Data.toBuffer()
  var outputBuffer: Buffer

  if not recover_id_secret(
    instance.ctx, addr proof1Buffer, addr proof2Buffer, addr outputBuffer
  ):
    return err("Failed to recover secret")

  if outputBuffer.len != 32:
    return err("Invalid secret length")

  var secret: array[32, byte]
  copyMem(addr secret[0], outputBuffer.`ptr`, 32)
  ok(secret)
