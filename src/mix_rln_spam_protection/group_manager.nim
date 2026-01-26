# Mix RLN Spam Protection Plugin
# Copyright (c) 2025 vacp2p
# Licensed under either of Apache License 2.0 or MIT license.

## Group Manager module providing abstract interface and offchain implementation
## for RLN membership management.
##
## The GroupManager is designed to be extensible:
## - GroupManager: Abstract base class defining the interface
## - OffchainGroupManager: Implementation using content-topic based propagation
## - (Future) OnchainGroupManager: Implementation using smart contract events
##
## This design allows swapping the membership backend without changing the
## spam protection logic.

import std/[tables, deques, options, hashes, sets]
import chronos
import results
import chronicles

import ./types
import ./constants
import ./codec
import ./rln_interface

export types, constants, codec

logScope:
  topics = "mix-rln-group-manager"

type
  # Callback types for group manager events
  OnRegisterCallback* = proc(
    commitment: IDCommitment, index: MembershipIndex
  ): Future[void] {.gcsafe, raises: [].}
  OnWithdrawCallback* = proc(
    commitment: IDCommitment, index: MembershipIndex
  ): Future[void] {.gcsafe, raises: [].}

  # Membership entry in the group
  Membership* = object
    commitment*: IDCommitment
    index*: MembershipIndex

  # Root tracker for maintaining valid roots window
  MerkleRootTracker* = ref object
    validRoots: Deque[MerkleNode] # Maintains order for getValidRoots
    rootSet: HashSet[MerkleNode] # O(1) lookup for containsRoot
    windowSize: int

  # Abstract base class for group managers
  GroupManager* = ref object of RootObj
    ## Abstract base class for group membership management.
    ## Concrete implementations must override all methods.
    rlnInstance*: RLNInstance
    credentials*: Option[IdentityCredential]
    membershipIndex*: Option[MembershipIndex]
    rootTracker*: MerkleRootTracker
    onRegister: Option[OnRegisterCallback]
    onWithdraw: Option[OnWithdrawCallback]
    isInitialized*: bool
    isSynced*: bool

  # Offchain group manager using content-topic propagation
  OffchainGroupManager* = ref object of GroupManager
    ## Group manager that propagates membership via logos-messaging content topics.
    ## Membership additions and deletions are broadcast to all nodes.
    publishCallback: Option[PublishCallback]
    membershipByCommitment: Table[IDCommitment, MembershipIndex]
    membershipByIndex: Table[MembershipIndex, IDCommitment]
    nextIndex: MembershipIndex
    membershipContentTopic*: string ## Content topic for membership updates

# Hash function for MerkleNode (needed for HashSet)
proc hash*(node: MerkleNode): Hash =
  var h: Hash = 0
  for b in node:
    h = h !& int(b)
  result = !$h

# MerkleRootTracker implementation

proc newMerkleRootTracker*(
    windowSize: int = AcceptableRootWindowSize
): MerkleRootTracker =
  ## Create a new Merkle root tracker.
  MerkleRootTracker(
    validRoots: initDeque[MerkleNode](),
    rootSet: initHashSet[MerkleNode](),
    windowSize: windowSize,
  )

proc addRoot*(tracker: MerkleRootTracker, root: MerkleNode) =
  ## Add a new root to the tracker, removing oldest if at capacity.
  if tracker.validRoots.len >= tracker.windowSize:
    let oldRoot = tracker.validRoots.popFirst()
    tracker.rootSet.excl(oldRoot)
  tracker.validRoots.addLast(root)
  tracker.rootSet.incl(root)

proc containsRoot*(tracker: MerkleRootTracker, root: MerkleNode): bool =
  ## Check if a root is in the valid window. O(1) lookup.
  root in tracker.rootSet

proc indexOfRoot*(tracker: MerkleRootTracker, root: MerkleNode): int =
  ## Get the index of a root in the valid window, or -1 if not found.
  var idx = 0
  for r in tracker.validRoots:
    if r == root:
      return idx
    inc idx
  -1

proc getValidRoots*(tracker: MerkleRootTracker): seq[MerkleNode] =
  ## Get all valid roots.
  result = newSeq[MerkleNode](tracker.validRoots.len)
  for i, r in tracker.validRoots:
    result[i] = r

proc updateFromInstance*(
    tracker: MerkleRootTracker, instance: RLNInstance
): RlnResult[void] =
  ## Update the tracker with the current root from the RLN instance.
  let root = instance.getMerkleRoot().valueOr:
    return err("Failed to get Merkle root: " & error)
  tracker.addRoot(root)
  ok()

proc updateRootTrackerOrLog(gm: OffchainGroupManager) =
  ## Update root tracker, logging any errors (non-fatal).
  let result = gm.rootTracker.updateFromInstance(gm.rlnInstance)
  if result.isErr:
    warn "Failed to update root tracker", error = result.error

# GroupManager base implementation (abstract methods)

method init*(gm: GroupManager): Future[RlnResult[void]] {.base, async.} =
  ## Initialize the group manager.
  return err("init must be implemented by concrete type")

method start*(gm: GroupManager): Future[RlnResult[void]] {.base, async.} =
  ## Start the group manager (begin syncing membership).
  return err("start must be implemented by concrete type")

method stop*(gm: GroupManager): Future[void] {.base, async.} =
  ## Stop the group manager.
  discard

method register*(
    gm: GroupManager, commitment: IDCommitment
): Future[RlnResult[MembershipIndex]] {.base, async.} =
  ## Register a new member (without credentials - external member).
  return err("register must be implemented by concrete type")

method register*(
    gm: GroupManager, credentials: IdentityCredential
): Future[RlnResult[MembershipIndex]] {.base, async.} =
  ## Register self with the given credentials.
  return err("register with credentials must be implemented by concrete type")

method withdraw*(
    gm: GroupManager, index: MembershipIndex
): Future[RlnResult[void]] {.base, async.} =
  ## Remove a member at the given index.
  return err("withdraw must be implemented by concrete type")

{.push raises: [], gcsafe.}

method isReady*(gm: GroupManager): bool {.base.} =
  ## Check if the group manager is ready for proof operations.
  gm.isInitialized and gm.isSynced and gm.credentials.isSome and
    gm.membershipIndex.isSome

method validateRoot*(gm: GroupManager, root: MerkleNode): bool {.base.} =
  ## Check if a Merkle root is valid (in the acceptable window).
  gm.rootTracker.containsRoot(root)

method generateProof*(
    gm: GroupManager,
    signal: openArray[byte],
    epoch: Epoch,
    rlnIdentifier: RlnIdentifier,
    messageId: uint = 0,
): RlnResult[RateLimitProof] {.base.} =
  ## Generate an RLN proof for a message.
  if not gm.isReady():
    return err("Group manager not ready")

  let creds = gm.credentials.get()
  let index = gm.membershipIndex.get()

  info "Generating proof with credentials",
    membershipIndex = index,
    commitment = creds.idCommitment.toHex(),
    idSecretHash = creds.idSecretHash.toHex()[0..15] & "...",
    idTrapdoor = creds.idTrapdoor.toHex()[0..15] & "..."

  # Flush tree to ensure internal state is synced
  if not flush(gm.rlnInstance.ctx):
    return err("Failed to flush tree before proof generation")
  
  # Verify the tree has the expected rate commitment at our index
  # Tree stores rate_commitment = Poseidon(id_commitment, user_message_limit), NOT id_commitment
  let treeCommitment = gm.rlnInstance.getLeaf(index).valueOr:
    return err("Failed to get leaf at membership index: " & error)

  let expectedRateCommitment = computeRateCommitment(creds.idCommitment, UserMessageLimit).valueOr:
    return err("Failed to compute expected rate commitment: " & error)

  info "Tree state verification before proof generation",
    membershipIndex = index,
    treeCommitment = treeCommitment.toHex(),
    expectedCommitment = expectedRateCommitment.toHex(),
    commitmentsMatch = treeCommitment == expectedRateCommitment

  if treeCommitment != expectedRateCommitment:
    error "CRITICAL: Tree commitment at index does not match our credentials!",
      index = index,
      treeCommitment = treeCommitment.toHex(),
      expectedCommitment = expectedRateCommitment.toHex()
    # This could mean:
    # 1. Wrong index stored
    # 2. Tree loaded incorrectly
    # 3. Tree was modified after registration
  
  # Get current Merkle root before generating proof
  let currentRoot = gm.rlnInstance.getMerkleRoot().valueOr:
    return err("Failed to get current Merkle root: " & error)

  info "Generating RLN proof",
    signalLen = signal.len,
    epochLen = epoch.len,
    rlnIdentifierLen = rlnIdentifier.len,
    messageId = messageId,
    membershipIndex = index,
    currentMerkleRoot = currentRoot.toHex()

  # Use witness-based proof generation for reliable Merkle proof handling
  # This explicitly fetches the Merkle proof and passes it to zerokit,
  # bypassing the internal cache that may be stale
  let proofResult = gm.rlnInstance.generateRlnProofWithWitness(
    creds, index, epoch, rlnIdentifier, signal, messageId
  )

  if proofResult.isErr:
    error "RLN proof generation failed", error = proofResult.error
    return proofResult

  # Log the root that ended up in the generated proof
  let generatedProof = proofResult.get()
  info "RLN proof generated successfully",
    proofMerkleRoot = generatedProof.merkleRoot.toHex(),
    currentMerkleRoot = currentRoot.toHex(),
    rootsMatch = generatedProof.merkleRoot == currentRoot

  if generatedProof.merkleRoot != currentRoot:
    error "WARNING: Generated proof contains different root than current tree!",
      proofRoot = generatedProof.merkleRoot.toHex(), currentRoot = currentRoot.toHex()

  return proofResult

method verifyProof*(
    gm: GroupManager,
    proof: RateLimitProof,
    signal: openArray[byte],
    rlnIdentifier: RlnIdentifier,
): RlnResult[bool] {.base.} =
  ## Verify an RLN proof using the valid roots window.
  if not gm.isInitialized:
    return err("Group manager not initialized")

  let validRoots = gm.rootTracker.getValidRoots()
  gm.rlnInstance.verifyRlnProof(proof, rlnIdentifier, signal, validRoots)

{.pop.}

proc setOnRegister*(gm: GroupManager, callback: OnRegisterCallback) =
  ## Set callback for when new members are registered.
  gm.onRegister = some(callback)

proc setOnWithdraw*(gm: GroupManager, callback: OnWithdrawCallback) =
  ## Set callback for when members are withdrawn.
  gm.onWithdraw = some(callback)

# OffchainGroupManager implementation

proc newOffchainGroupManager*(
    rlnInstance: RLNInstance, membershipContentTopic: string = MembershipContentTopic
): OffchainGroupManager =
  ## Create a new offchain group manager.
  ## The membershipContentTopic can be customized for different networks.
  OffchainGroupManager(
    rlnInstance: rlnInstance,
    credentials: none(IdentityCredential),
    membershipIndex: none(MembershipIndex),
    rootTracker: newMerkleRootTracker(),
    onRegister: none(OnRegisterCallback),
    onWithdraw: none(OnWithdrawCallback),
    isInitialized: false,
    isSynced: false,
    publishCallback: none(PublishCallback),
    membershipByCommitment: initTable[IDCommitment, MembershipIndex](),
    membershipByIndex: initTable[MembershipIndex, IDCommitment](),
    nextIndex: 0,
    membershipContentTopic: membershipContentTopic,
  )

proc setPublishCallback*(gm: OffchainGroupManager, callback: PublishCallback) =
  ## Set the callback for publishing membership updates.
  gm.publishCallback = some(callback)

method init*(gm: OffchainGroupManager): Future[RlnResult[void]] {.async.} =
  ## Initialize the offchain group manager.
  if gm.isInitialized:
    return ok()

  # Update root tracker with initial (empty) root
  let updateResult = gm.rootTracker.updateFromInstance(gm.rlnInstance)
  if updateResult.isErr:
    return err("Failed to initialize root tracker: " & updateResult.error)

  gm.isInitialized = true
  info "Offchain group manager initialized"
  ok()

method start*(gm: OffchainGroupManager): Future[RlnResult[void]] {.async.} =
  ## Start the offchain group manager.
  ## For offchain mode, we consider it synced immediately (caller should
  ## load tree from file or wait for updates via handleMembershipUpdate).
  if not gm.isInitialized:
    return err("Group manager not initialized")

  gm.isSynced = true
  info "Offchain group manager started"
  ok()

method stop*(gm: OffchainGroupManager): Future[void] {.async.} =
  ## Stop the offchain group manager.
  gm.isSynced = false
  info "Offchain group manager stopped"

proc restoreMemberFromKeystore*(
    gm: OffchainGroupManager, commitment: IDCommitment, index: MembershipIndex
): RlnResult[void] =
  ## Restore a member from keystore into the tree and membership tables.
  ## This is used when loading credentials with an existing index.
  if not gm.isInitialized:
    return err("Group manager not initialized")

  # Compute rate commitment = Poseidon(idCommitment, userMessageLimit)
  # This is the actual leaf value stored in the RLN Merkle tree
  let rateCommitment = computeRateCommitment(commitment, UserMessageLimit).valueOr:
    return err("Failed to compute rate commitment: " & error)

  # Insert into RLN tree at the stored index
  let insertResult = gm.rlnInstance.insertMemberAt(index, rateCommitment)
  if insertResult.isErr:
    return err("Failed to insert member at stored index: " & insertResult.error)

  # Update local tracking
  gm.membershipByCommitment[commitment] = index
  gm.membershipByIndex[index] = commitment

  # Update nextIndex if needed
  if index >= gm.nextIndex:
    gm.nextIndex = index + 1

  info "Restored member from keystore", index = index
  ok()

proc hasMember*(gm: OffchainGroupManager, commitment: IDCommitment): bool =
  ## Check if a member with the given commitment is already in the tree.
  gm.membershipByCommitment.hasKey(commitment)

method register*(
    gm: OffchainGroupManager, commitment: IDCommitment
): Future[RlnResult[MembershipIndex]] {.async.} =
  ## Register a new external member.
  if not gm.isInitialized:
    return err("Group manager not initialized")

  # Check if already registered
  if gm.membershipByCommitment.hasKey(commitment):
    return err("Commitment already registered")

  let index = gm.nextIndex
  info "Registering member",
    index = index,
    nextIndex = gm.nextIndex,
    currentMemberCount = gm.membershipByIndex.len
  gm.nextIndex += 1

  # Compute rate commitment = Poseidon(idCommitment, userMessageLimit)
  # This is the actual leaf value stored in the RLN Merkle tree
  let rateCommitment = computeRateCommitment(commitment, UserMessageLimit).valueOr:
    return err("Failed to compute rate commitment: " & error)

  # Insert into RLN tree
  let insertResult = gm.rlnInstance.insertMemberAt(index, rateCommitment)
  if insertResult.isErr:
    return err("Failed to insert member: " & insertResult.error)

  # Update local tracking
  gm.membershipByCommitment[commitment] = index
  gm.membershipByIndex[index] = commitment
  
  info "Member added to local tables",
    index = index,
    newMemberCount = gm.membershipByIndex.len,
    newNextIndex = gm.nextIndex

  # Update root tracker
  gm.updateRootTrackerOrLog()

  # Broadcast membership update
  if gm.publishCallback.isSome:
    let update = MembershipUpdate(
      action: MembershipAction.Add, idCommitment: commitment, index: index
    )
    let data = update.toBytes()
    await gm.publishCallback.get()(gm.membershipContentTopic, data)

  # Call callback
  if gm.onRegister.isSome:
    await gm.onRegister.get()(commitment, index)

  info "Member registered", index = index
  ok(index)

method register*(
    gm: OffchainGroupManager, credentials: IdentityCredential
): Future[RlnResult[MembershipIndex]] {.async.} =
  ## Register self with the given credentials.
  # Check if already registered (by checking if we have a membership index)
  # Note: credentials may be set during init() for ephemeral mode, so we check
  # membershipIndex instead to determine if we're actually registered in the tree.
  if gm.membershipIndex.isSome:
    return err("Already registered with index " & $gm.membershipIndex.get())

  let indexResult = await gm.register(credentials.idCommitment)
  if indexResult.isErr:
    return err(indexResult.error)

  let index = indexResult.get()
  gm.credentials = some(credentials)
  gm.membershipIndex = some(index)

  info "Self registered", index = index
  ok(index)

method withdraw*(
    gm: OffchainGroupManager, index: MembershipIndex
): Future[RlnResult[void]] {.async.} =
  ## Remove a member at the given index.
  if not gm.isInitialized:
    return err("Group manager not initialized")

  if not gm.membershipByIndex.hasKey(index):
    return err("Member not found at index")

  let commitment = gm.membershipByIndex[index]

  # Delete from RLN tree
  let deleteResult = gm.rlnInstance.removeMember(index)
  if deleteResult.isErr:
    return err("Failed to delete member: " & deleteResult.error)

  # Update local tracking
  gm.membershipByCommitment.del(commitment)
  gm.membershipByIndex.del(index)

  # Update root tracker
  gm.updateRootTrackerOrLog()

  # Broadcast membership update
  if gm.publishCallback.isSome:
    let update = MembershipUpdate(
      action: MembershipAction.Remove, idCommitment: commitment, index: index
    )
    let data = update.toBytes()
    await gm.publishCallback.get()(gm.membershipContentTopic, data)

  # Call callback
  if gm.onWithdraw.isSome:
    await gm.onWithdraw.get()(commitment, index)

  # Check if we withdrew ourselves
  if gm.membershipIndex.isSome and gm.membershipIndex.get() == index:
    gm.credentials = none(IdentityCredential)
    gm.membershipIndex = none(MembershipIndex)
    warn "Self membership withdrawn"

  info "Member withdrawn", index = index
  ok()

proc handleMembershipUpdate*(
    gm: OffchainGroupManager, update: MembershipUpdate
): Future[RlnResult[void]] {.async.} =
  ## Handle a membership update received from the network.
  ## This is called when receiving updates on the membership content topic.
  if not gm.isInitialized:
    return err("Group manager not initialized")

  case update.action
  of MembershipAction.Add:
    # Check if already have this member
    if gm.membershipByCommitment.hasKey(update.idCommitment):
      # Already have it, skip
      return ok()

    # Compute rate commitment = Poseidon(idCommitment, userMessageLimit)
    # This is the actual leaf value stored in the RLN Merkle tree
    let rateCommitment = computeRateCommitment(update.idCommitment, UserMessageLimit).valueOr:
      return err("Failed to compute rate commitment: " & error)

    # Insert into RLN tree at the specified index
    let insertResult = gm.rlnInstance.insertMemberAt(update.index, rateCommitment)
    if insertResult.isErr:
      return err("Failed to insert member from update: " & insertResult.error)

    # Update local tracking
    gm.membershipByCommitment[update.idCommitment] = update.index
    gm.membershipByIndex[update.index] = update.idCommitment

    # Update next index if needed
    if update.index >= gm.nextIndex:
      gm.nextIndex = update.index + 1

    # Update root tracker
    gm.updateRootTrackerOrLog()

    # Call callback
    if gm.onRegister.isSome:
      await gm.onRegister.get()(update.idCommitment, update.index)

    debug "Member added from network update", index = update.index
  of MembershipAction.Remove:
    if not gm.membershipByIndex.hasKey(update.index):
      # Don't have this member, skip
      return ok()

    # Delete from RLN tree
    let deleteResult = gm.rlnInstance.removeMember(update.index)
    if deleteResult.isErr:
      return err("Failed to delete member from update: " & deleteResult.error)

    # Update local tracking
    let commitment = gm.membershipByIndex[update.index]
    gm.membershipByCommitment.del(commitment)
    gm.membershipByIndex.del(update.index)

    # Update root tracker
    gm.updateRootTrackerOrLog()

    # Call callback
    if gm.onWithdraw.isSome:
      await gm.onWithdraw.get()(commitment, update.index)

    # Check if we were removed
    if gm.membershipIndex.isSome and gm.membershipIndex.get() == update.index:
      gm.credentials = none(IdentityCredential)
      gm.membershipIndex = none(MembershipIndex)
      warn "Self membership removed by network"

    debug "Member removed from network update", index = update.index

  ok()

proc getMemberCount*(gm: OffchainGroupManager): int =
  ## Get the number of registered members.
  gm.membershipByIndex.len

proc getMemberIndex*(
    gm: OffchainGroupManager, commitment: IDCommitment
): Option[MembershipIndex] {.raises: [].} =
  ## Get the index of a member by commitment.
  try:
    if gm.membershipByCommitment.hasKey(commitment):
      some(gm.membershipByCommitment[commitment])
    else:
      none(MembershipIndex)
  except KeyError:
    none(MembershipIndex)

proc getMemberCommitment*(
    gm: OffchainGroupManager, index: MembershipIndex
): Option[IDCommitment] {.raises: [].} =
  ## Get the commitment of a member by index.
  try:
    if gm.membershipByIndex.hasKey(index):
      some(gm.membershipByIndex[index])
    else:
      none(IDCommitment)
  except KeyError:
    none(IDCommitment)

# Tree serialization for bootstrap

proc serializeTreeSnapshot*(gm: OffchainGroupManager): seq[byte] =
  ## Serialize the current tree state for bootstrap sharing.
  ## Binary format:
  ##   - member_count (8 bytes, little-endian)
  ##   - next_index (8 bytes, little-endian)
  ##   - for each member:
  ##     - commitment (32 bytes)
  ##     - index (8 bytes, little-endian)

  let memberCount = gm.membershipByIndex.len
  let dataSize = 16 + (memberCount * 40) # 8 + 8 + n * (32 + 8)
  result = newSeq[byte](dataSize)

  var offset = 0

  # Member count
  let count = uint64(memberCount)
  result[offset + 0] = byte(count and 0xFF)
  result[offset + 1] = byte((count shr 8) and 0xFF)
  result[offset + 2] = byte((count shr 16) and 0xFF)
  result[offset + 3] = byte((count shr 24) and 0xFF)
  result[offset + 4] = byte((count shr 32) and 0xFF)
  result[offset + 5] = byte((count shr 40) and 0xFF)
  result[offset + 6] = byte((count shr 48) and 0xFF)
  result[offset + 7] = byte((count shr 56) and 0xFF)
  offset += 8

  # Next index
  let nextIdx = gm.nextIndex
  result[offset + 0] = byte(nextIdx and 0xFF)
  result[offset + 1] = byte((nextIdx shr 8) and 0xFF)
  result[offset + 2] = byte((nextIdx shr 16) and 0xFF)
  result[offset + 3] = byte((nextIdx shr 24) and 0xFF)
  result[offset + 4] = byte((nextIdx shr 32) and 0xFF)
  result[offset + 5] = byte((nextIdx shr 40) and 0xFF)
  result[offset + 6] = byte((nextIdx shr 48) and 0xFF)
  result[offset + 7] = byte((nextIdx shr 56) and 0xFF)
  offset += 8

  # Members
  for index, commitment in gm.membershipByIndex:
    copyMem(addr result[offset], unsafeAddr commitment[0], HashByteSize)
    offset += HashByteSize

    result[offset + 0] = byte(index and 0xFF)
    result[offset + 1] = byte((index shr 8) and 0xFF)
    result[offset + 2] = byte((index shr 16) and 0xFF)
    result[offset + 3] = byte((index shr 24) and 0xFF)
    result[offset + 4] = byte((index shr 32) and 0xFF)
    result[offset + 5] = byte((index shr 40) and 0xFF)
    result[offset + 6] = byte((index shr 48) and 0xFF)
    result[offset + 7] = byte((index shr 56) and 0xFF)
    offset += 8

proc loadTreeSnapshot*(gm: OffchainGroupManager, data: seq[byte]): RlnResult[void] =
  ## Load a tree snapshot for bootstrap.
  if data.len < 16:
    return err("Invalid snapshot data: too short")

  var offset = 0

  # Member count
  let memberCount =
    uint64(data[offset + 0]) or (uint64(data[offset + 1]) shl 8) or
    (uint64(data[offset + 2]) shl 16) or (uint64(data[offset + 3]) shl 24) or
    (uint64(data[offset + 4]) shl 32) or (uint64(data[offset + 5]) shl 40) or
    (uint64(data[offset + 6]) shl 48) or (uint64(data[offset + 7]) shl 56)
  offset += 8

  # Next index
  let nextIndex =
    uint64(data[offset + 0]) or (uint64(data[offset + 1]) shl 8) or
    (uint64(data[offset + 2]) shl 16) or (uint64(data[offset + 3]) shl 24) or
    (uint64(data[offset + 4]) shl 32) or (uint64(data[offset + 5]) shl 40) or
    (uint64(data[offset + 6]) shl 48) or (uint64(data[offset + 7]) shl 56)
  offset += 8

  info "Parsed tree snapshot header",
    memberCount = memberCount,
    nextIndex = nextIndex,
    dataLen = data.len,
    expectedSize = 16 + int(memberCount) * 40

  let expectedSize = 16 + int(memberCount) * 40
  if data.len != expectedSize:
    error "Snapshot size mismatch",
      dataLen = data.len,
      expectedSize = expectedSize,
      memberCount = memberCount,
      nextIndex = nextIndex
    return err("Invalid snapshot data: size mismatch")

  # Clear current state
  gm.membershipByCommitment.clear()
  gm.membershipByIndex.clear()

  # Parse and insert members one by one
  for i in 0 ..< memberCount:
    var commitment: IDCommitment
    copyMem(addr commitment[0], unsafeAddr data[offset], HashByteSize)
    offset += HashByteSize

    let index =
      uint64(data[offset + 0]) or (uint64(data[offset + 1]) shl 8) or
      (uint64(data[offset + 2]) shl 16) or (uint64(data[offset + 3]) shl 24) or
      (uint64(data[offset + 4]) shl 32) or (uint64(data[offset + 5]) shl 40) or
      (uint64(data[offset + 6]) shl 48) or (uint64(data[offset + 7]) shl 56)
    offset += 8

    # Compute rate commitment = Poseidon(idCommitment, userMessageLimit)
    # This is the actual leaf value stored in the RLN Merkle tree
    let rateCommitment = computeRateCommitment(commitment, UserMessageLimit).valueOr:
      error "Failed to compute rate commitment", index = index, error = error
      return err("Failed to compute rate commitment: " & error)

    # Insert into RLN tree at the correct index
    let insertResult = gm.rlnInstance.insertMemberAt(MembershipIndex(index), rateCommitment)
    if insertResult.isErr:
      error "Failed to insert member from snapshot",
        index = index, error = insertResult.error
      return err("Failed to insert member from snapshot: " & insertResult.error)

    gm.membershipByCommitment[commitment] = MembershipIndex(index)
    gm.membershipByIndex[MembershipIndex(index)] = commitment

  gm.nextIndex = MembershipIndex(nextIndex)

  # Update root tracker
  gm.updateRootTrackerOrLog()

  info "Loaded tree snapshot", memberCount = memberCount, nextIndex = nextIndex
  ok()

proc saveTreeToFile*(gm: OffchainGroupManager, path: string): RlnResult[void] =
  ## Save the current tree state to a file.
  let data = gm.serializeTreeSnapshot()
  info "saveTreeToFile called",
    path = path,
    memberCount = gm.membershipByIndex.len,
    nextIndex = gm.nextIndex,
    dataLen = data.len
  try:
    writeFile(path, data)
    info "Tree file written successfully", path = path, size = data.len
    ok()
  except IOError as e:
    err("Failed to write tree file: " & e.msg)

proc loadTreeFromFile*(gm: OffchainGroupManager, path: string): RlnResult[void] =
  ## Load tree state from a file.
  info "loadTreeFromFile called", path = path
  try:
    let strData = readFile(path)
    info "Tree file read successfully", dataLen = strData.len
    # Properly convert string to seq[byte] without cast
    var data = newSeq[byte](strData.len)
    if strData.len > 0:
      copyMem(addr data[0], unsafeAddr strData[0], strData.len)
    let loadResult = gm.loadTreeSnapshot(data)
    if loadResult.isErr:
      return loadResult
    
    # Flush the tree after loading to ensure internal cache is synced
    # Loading calls insertMemberAt() for each member, which modifies the tree
    if not flush(gm.rlnInstance.ctx):
      return err("Failed to flush tree after loading")
    
    # Get root immediately after loading to verify tree state
    let rootAfterLoad = gm.rlnInstance.getMerkleRoot().valueOr:
      return err("Failed to get root after loading: " & error)
    
    # Also try generating a test proof to see what root it contains
    var testLeaves = newSeq[byte](32)  # Empty signal for test
    let testSignal = testLeaves
    
    info "Tree loaded and flushed",
      path = path,
      memberCount = gm.membershipByIndex.len,
      rootAfterLoad = rootAfterLoad.toHex()
    
    # If we have credentials, try getting the proof root for comparison
    if gm.credentials.isSome and gm.membershipIndex.isSome:
      let creds = gm.credentials.get()
      let idx = gm.membershipIndex.get()

      # Compute expected rate commitment (this is what's stored in the tree)
      let expectedRateCommitment = computeRateCommitment(creds.idCommitment, UserMessageLimit).valueOr:
        warn "Failed to compute rate commitment for verification", error = error
        return ok()  # Don't fail the load just for verification

      # Try to see what leaf is at our index
      let leafAtIndex = gm.rlnInstance.getLeaf(idx)
      if leafAtIndex.isOk:
        info "Leaf verification after tree load",
          index = idx,
          expectedCommitment = expectedRateCommitment.toHex(),
          treeCommitment = leafAtIndex.get().toHex(),
          match = (leafAtIndex.get() == expectedRateCommitment)
    
    return ok()
  except IOError as e:
    warn "Failed to read tree file", path = path, error = e.msg
    err("Failed to read tree file: " & e.msg)
