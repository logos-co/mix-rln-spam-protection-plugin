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
import metrics

import ./types
import ./constants
import ./codec
import ./rln_interface

export types, constants, codec

logScope:
  topics = "mix-rln-group-manager"

declareHistogram mix_rln_proof_generation_duration_seconds,
  "Duration of RLN proof generation in seconds", labels = ["mode"]
declareHistogram mix_rln_proof_verification_duration_seconds,
  "Duration of RLN zkSNARK proof verification in seconds"
declareCounter mix_rln_proof_generation_failures_total,
  "Number of failed RLN proof generation attempts"
declareCounter mix_rln_partial_proof_cache_total,
  "Partial proof cache usage during proof generation (hit, miss, refresh)",
  labels = ["result"]
declareCounter mix_rln_root_mismatch_total,
  "Number of generated proofs whose Merkle root differed from the current tree root"
declareGauge mix_rln_group_size, "Number of members in the local RLN membership tree"

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
    userMessageLimit*: uint64 ## Max messages per epoch for this group
    partialProofCache*: Option[PartialProofCache]

  # Offchain group manager using content-topic propagation
  OffchainGroupManager* = ref object of GroupManager
    ## Group manager that propagates membership via logos-messaging content topics.
    ## Membership additions and deletions are broadcast to all nodes.
    publishCallback: Option[PublishCallback]
    membershipByIdCommitment: Table[IDCommitment, MembershipIndex] ## idCommitment -> index (for spam recovery)
    membershipByIndex: Table[MembershipIndex, IDCommitment] ## index -> idCommitment
    # We track per-user rate limits because the Merkle tree stores rateCommitment = Poseidon(idCommitment, userMessageLimit),
    # not the raw userMessageLimit. When serializing tree snapshots, we need the original userMessageLimit to correctly
    # recompute rateCommitment on load. Without this, we'd have to assume all members use the same limit.
    rateLimitByIdCommitment: Table[IDCommitment, uint64] ## idCommitment -> userMessageLimit
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

proc resetRoots*(tracker: MerkleRootTracker) =
  ## Drop all tracked roots.
  tracker.validRoots = initDeque[MerkleNode]()
  tracker.rootSet = initHashSet[MerkleNode]()

proc resetToRoot*(tracker: MerkleRootTracker, root: MerkleNode) =
  ## Replace the valid root window with a single root.
  tracker.resetRoots()
  tracker.addRoot(root)

proc containsRoot*(tracker: MerkleRootTracker, root: MerkleNode): bool =
  ## Check if a root is in the valid window. O(1) lookup.
  root in tracker.rootSet

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

proc resetToInstance*(
    tracker: MerkleRootTracker, instance: RLNInstance
): RlnResult[void] =
  ## Reset the tracker to only the current root from the RLN instance.
  let root = instance.getMerkleRoot().valueOr:
    return err("Failed to get Merkle root: " & error)
  tracker.resetToRoot(root)
  ok()

proc updateRootTrackerOrLog(gm: OffchainGroupManager) =
  ## Update root tracker, logging any errors (non-fatal).
  let result = gm.rootTracker.updateFromInstance(gm.rlnInstance)
  if result.isErr:
    warn "Failed to update root tracker", error = result.error

proc resetRootTrackerOrLog(gm: OffchainGroupManager) =
  ## Reset root tracker to the current tree root, logging any errors (non-fatal).
  let result = gm.rootTracker.resetToInstance(gm.rlnInstance)
  if result.isErr:
    warn "Failed to reset root tracker", error = result.error

proc refreshProofCache*(gm: OffchainGroupManager): RlnResult[void] =
  ## Rebuild the cached partial proof for the local member, if available.
  if gm.credentials.isNone or gm.membershipIndex.isNone:
    gm.partialProofCache = none(PartialProofCache)
    return ok()

  let cache = gm.rlnInstance.generatePartialProofCache(
    gm.credentials.get(),
    gm.membershipIndex.get(),
    gm.userMessageLimit,
  ).valueOr:
    gm.partialProofCache = none(PartialProofCache)
    return err("Failed to refresh partial proof cache: " & error)

  gm.partialProofCache = some(cache)
  ok()

proc refreshProofCacheOrLog(gm: OffchainGroupManager) =
  let result = gm.refreshProofCache()
  if result.isErr:
    warn "Failed to refresh partial proof cache", error = result.error

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

  trace "Generating proof with credentials",
    membershipIndex = index,
    commitment = creds.idCommitment.toHex()

  # Flush tree to ensure internal state is synced
  if not flush(gm.rlnInstance.ctx):
    return err("Failed to flush tree before proof generation")

  # Verify the tree has the expected rate commitment at our index
  # Tree stores rate_commitment = Poseidon(id_commitment, user_message_limit), NOT id_commitment
  let treeCommitment = gm.rlnInstance.getLeaf(index).valueOr:
    return err("Failed to get leaf at membership index: " & error)

  let expectedRateCommitment = computeRateCommitment(
    creds.idCommitment, gm.userMessageLimit
  ).valueOr:
    return err("Failed to compute expected rate commitment: " & error)

  trace "Tree state verification before proof generation",
    membershipIndex = index,
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

  trace "Generating RLN proof",
    signalLen = signal.len,
    messageId = messageId,
    membershipIndex = index

  # Happy path: cached partial-proof should be available and valid most of the time.
  # On cache miss/staleness, rebuild once and retry. Fall back to full proof generation.
  let proofGenStart = Moment.now()
  var proofResult: RlnResult[RateLimitProof] = err("partial-proof cache not used")
  var usedPartialCache = false

  if gm.partialProofCache.isSome:
    proofResult = gm.rlnInstance.finishRlnProofWithCache(
      gm.partialProofCache.get(),
      creds,
      index,
      epoch,
      rlnIdentifier,
      signal,
      messageId,
      gm.userMessageLimit,
    )
    usedPartialCache = proofResult.isOk
    if proofResult.isErr:
      warn "Cached partial proof could not be used", error = proofResult.error

  mix_rln_partial_proof_cache_total.inc(
    labelValues = [if usedPartialCache: "hit" else: "miss"]
  )

  if not usedPartialCache and gm of OffchainGroupManager:
    OffchainGroupManager(gm).refreshProofCacheOrLog()
    mix_rln_partial_proof_cache_total.inc(labelValues = ["refresh"])
    if gm.partialProofCache.isSome:
      proofResult = gm.rlnInstance.finishRlnProofWithCache(
        gm.partialProofCache.get(),
        creds,
        index,
        epoch,
        rlnIdentifier,
        signal,
        messageId,
        gm.userMessageLimit,
      )
      usedPartialCache = proofResult.isOk
      if proofResult.isErr:
        warn "Refreshed partial proof cache could not be used", error = proofResult.error

  if not usedPartialCache:
    proofResult = gm.rlnInstance.generateRlnProofWithWitness(
      creds, index, epoch, rlnIdentifier, signal, messageId, gm.userMessageLimit
    )

  if proofResult.isErr:
    mix_rln_proof_generation_failures_total.inc()
    error "RLN proof generation failed", error = proofResult.error
    return proofResult

  mix_rln_proof_generation_duration_seconds.observe(
    (Moment.now() - proofGenStart).nanoseconds.float / 1e9,
    labelValues = [if usedPartialCache: "cached" else: "full"],
  )

  # Log the root that ended up in the generated proof
  let generatedProof = proofResult.get()
  debug "RLN proof generated successfully",
    rootsMatch = generatedProof.merkleRoot == currentRoot

  if generatedProof.merkleRoot != currentRoot:
    mix_rln_root_mismatch_total.inc()
    warn "Generated proof contains different root than current tree",
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
  let verifyStart = Moment.now()
  let verifyResult = gm.rlnInstance.verifyRlnProof(proof, rlnIdentifier, signal, validRoots)
  if verifyResult.isOk:
    mix_rln_proof_verification_duration_seconds.observe(
      (Moment.now() - verifyStart).nanoseconds.float / 1e9
    )
  verifyResult

{.pop.}

proc setOnRegister*(gm: GroupManager, callback: OnRegisterCallback) =
  ## Set callback for when new members are registered.
  gm.onRegister = some(callback)

proc setOnWithdraw*(gm: GroupManager, callback: OnWithdrawCallback) =
  ## Set callback for when members are withdrawn.
  gm.onWithdraw = some(callback)

# OffchainGroupManager implementation

proc newOffchainGroupManager*(
    rlnInstance: RLNInstance,
    membershipContentTopic: string = MembershipContentTopic,
    userMessageLimit: uint64 = UserMessageLimit,
): OffchainGroupManager =
  ## Create a new offchain group manager.
  ## The membershipContentTopic can be customized for different networks.
  ## userMessageLimit sets the max messages per epoch (must match network-wide setting).
  OffchainGroupManager(
    rlnInstance: rlnInstance,
    credentials: none(IdentityCredential),
    membershipIndex: none(MembershipIndex),
    rootTracker: newMerkleRootTracker(),
    onRegister: none(OnRegisterCallback),
    onWithdraw: none(OnWithdrawCallback),
    isInitialized: false,
    isSynced: false,
    userMessageLimit: userMessageLimit,
    partialProofCache: none(PartialProofCache),
    publishCallback: none(PublishCallback),
    membershipByIdCommitment: initTable[IDCommitment, MembershipIndex](),
    membershipByIndex: initTable[MembershipIndex, IDCommitment](),
    rateLimitByIdCommitment: initTable[IDCommitment, uint64](),
    nextIndex: 0,
    membershipContentTopic: membershipContentTopic,
  )

proc setPublishCallback*(gm: OffchainGroupManager, callback: PublishCallback) =
  ## Set the callback for publishing membership updates.
  gm.publishCallback = some(callback)

proc updateGroupSizeMetric(gm: OffchainGroupManager) =
  ## Keep the group size gauge in sync; call after every membership mutation.
  mix_rln_group_size.set(gm.membershipByIndex.len.int64)

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
    gm: OffchainGroupManager,
    commitment: IDCommitment,
    index: MembershipIndex,
    userMessageLimit: uint64 = 0,
): RlnResult[void] =
  ## Restore a member from keystore into the tree and membership tables.
  ## This is used when loading credentials with an existing index.
  ## If userMessageLimit is 0, uses the node's configured default.
  if not gm.isInitialized:
    return err("Group manager not initialized")

  let memberLimit =
    if userMessageLimit > 0:
      userMessageLimit
    else:
      gm.userMessageLimit

  # Compute rate commitment = Poseidon(idCommitment, userMessageLimit)
  # This is the actual leaf value stored in the RLN Merkle tree
  let rateCommitment = computeRateCommitment(commitment, memberLimit).valueOr:
    return err("Failed to compute rate commitment: " & error)

  # Insert into RLN tree at the stored index
  let insertResult = gm.rlnInstance.insertMemberAt(index, rateCommitment)
  if insertResult.isErr:
    return err("Failed to insert member at stored index: " & insertResult.error)

  # Update local tracking - track by idCommitment for spam recovery
  gm.membershipByIdCommitment[commitment] = index
  gm.membershipByIndex[index] = commitment
  gm.rateLimitByIdCommitment[commitment] = memberLimit
  gm.updateGroupSizeMetric()

  # Update nextIndex if needed
  if index >= gm.nextIndex:
    gm.nextIndex = index + 1

  gm.updateRootTrackerOrLog()
  gm.refreshProofCacheOrLog()

  info "Restored member from keystore", index = index, userMessageLimit = memberLimit
  ok()

proc hasMemberByIdCommitment*(
    gm: OffchainGroupManager, idCommitment: IDCommitment
): bool =
  ## Check if a member with the given identity commitment is already registered.
  gm.membershipByIdCommitment.hasKey(idCommitment)

method register*(
    gm: OffchainGroupManager, commitment: IDCommitment
): Future[RlnResult[MembershipIndex]] {.async.} =
  ## Register a new external member (by idCommitment).
  ## Computes rateCommitment using the node's configured userMessageLimit.
  if not gm.isInitialized:
    return err("Group manager not initialized")

  # Check if already registered by idCommitment
  if gm.membershipByIdCommitment.hasKey(commitment):
    return err("Member already registered")

  # Compute rate commitment = Poseidon(idCommitment, userMessageLimit)
  # This is the actual leaf value stored in the RLN Merkle tree
  let rateCommitment = computeRateCommitment(commitment, gm.userMessageLimit).valueOr:
    return err("Failed to compute rate commitment: " & error)

  let index = gm.nextIndex
  trace "Registering member", index = index
  gm.nextIndex += 1

  # Insert rateCommitment into RLN tree (this is the actual leaf value)
  let insertResult = gm.rlnInstance.insertMemberAt(index, rateCommitment)
  if insertResult.isErr:
    return err("Failed to insert member: " & insertResult.error)

  # Update local tracking - track by idCommitment for spam recovery
  gm.membershipByIdCommitment[commitment] = index
  gm.membershipByIndex[index] = commitment
  gm.rateLimitByIdCommitment[commitment] = gm.userMessageLimit
  gm.updateGroupSizeMetric()

  trace "Member added to local tables", index = index

  # Update root tracker
  gm.updateRootTrackerOrLog()
  gm.refreshProofCacheOrLog()

  # Broadcast membership update with idCommitment + userMessageLimit (like waku-rln-relay)
  if gm.publishCallback.isSome:
    let update = MembershipUpdate(
      action: MembershipAction.Add,
      idCommitment: commitment,
      userMessageLimit: gm.userMessageLimit,
      index: index,
    )
    let data = update.toBytes()
    await gm.publishCallback.get()(gm.membershipContentTopic, data)

  # Call callback
  if gm.onRegister.isSome:
    await gm.onRegister.get()(commitment, index)

  debug "Member registered", index = index
  ok(index)

proc registerWithLimit*(
    gm: OffchainGroupManager, commitment: IDCommitment, userMessageLimit: uint64
): Future[RlnResult[MembershipIndex]] {.async.} =
  ## Register a new external member with a specific rate limit.
  ## Used for setup scripts where different members have different limits.
  if not gm.isInitialized:
    return err("Group manager not initialized")

  # Check if already registered by idCommitment
  if gm.membershipByIdCommitment.hasKey(commitment):
    return err("Member already registered")

  # Compute rate commitment = Poseidon(idCommitment, userMessageLimit)
  let rateCommitment = computeRateCommitment(commitment, userMessageLimit).valueOr:
    return err("Failed to compute rate commitment: " & error)

  let index = gm.nextIndex
  trace "Registering member with custom limit", index = index, userMessageLimit = userMessageLimit
  gm.nextIndex += 1

  # Insert rateCommitment into RLN tree
  let insertResult = gm.rlnInstance.insertMemberAt(index, rateCommitment)
  if insertResult.isErr:
    return err("Failed to insert member: " & insertResult.error)

  # Update local tracking
  gm.membershipByIdCommitment[commitment] = index
  gm.membershipByIndex[index] = commitment
  gm.rateLimitByIdCommitment[commitment] = userMessageLimit
  gm.updateGroupSizeMetric()

  # Update root tracker
  gm.updateRootTrackerOrLog()
  gm.refreshProofCacheOrLog()

  # Broadcast membership update with the specific rate limit
  if gm.publishCallback.isSome:
    let update = MembershipUpdate(
      action: MembershipAction.Add,
      idCommitment: commitment,
      userMessageLimit: userMessageLimit,
      index: index,
    )
    let data = update.toBytes()
    await gm.publishCallback.get()(gm.membershipContentTopic, data)

  # Call callback
  if gm.onRegister.isSome:
    await gm.onRegister.get()(commitment, index)

  debug "Member registered with custom limit", index = index, userMessageLimit = userMessageLimit
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
  gm.refreshProofCacheOrLog()

  debug "Self registered", index = index
  ok(index)

method withdraw*(
    gm: OffchainGroupManager, index: MembershipIndex
): Future[RlnResult[void]] {.async.} =
  ## Remove a member at the given index.
  if not gm.isInitialized:
    return err("Group manager not initialized")

  if not gm.membershipByIndex.hasKey(index):
    return err("Member not found at index")

  let idCommitment = gm.membershipByIndex[index]

  # Delete from RLN tree
  let deleteResult = gm.rlnInstance.removeMember(index)
  if deleteResult.isErr:
    return err("Failed to delete member: " & deleteResult.error)

  # Get the member's rate limit before deleting (for broadcast)
  let memberRateLimit = gm.rateLimitByIdCommitment.getOrDefault(
    idCommitment, gm.userMessageLimit
  )

  # Update local tracking
  gm.membershipByIdCommitment.del(idCommitment)
  gm.membershipByIndex.del(index)
  gm.rateLimitByIdCommitment.del(idCommitment)
  gm.updateGroupSizeMetric()

  # Removals invalidate previously accepted roots.
  gm.resetRootTrackerOrLog()
  gm.refreshProofCacheOrLog()

  # Broadcast membership update
  if gm.publishCallback.isSome:
    let update = MembershipUpdate(
      action: MembershipAction.Remove,
      idCommitment: idCommitment,
      userMessageLimit: memberRateLimit,
      index: index,
    )
    let data = update.toBytes()
    await gm.publishCallback.get()(gm.membershipContentTopic, data)

  # Call callback
  if gm.onWithdraw.isSome:
    await gm.onWithdraw.get()(idCommitment, index)

  # Check if we withdrew ourselves
  if gm.membershipIndex.isSome and gm.membershipIndex.get() == index:
    gm.credentials = none(IdentityCredential)
    gm.membershipIndex = none(MembershipIndex)
    gm.partialProofCache = none(PartialProofCache)
    warn "Self membership withdrawn"

  debug "Member withdrawn", index = index
  ok()

proc handleMembershipUpdate*(
    gm: OffchainGroupManager, update: MembershipUpdate
): Future[RlnResult[void]] {.async.} =
  ## Handle a membership update received from the network.
  ## This is called when receiving updates on the membership content topic.
  ## Update contains idCommitment + userMessageLimit; we compute rateCommitment for tree.
  if not gm.isInitialized:
    return err("Group manager not initialized")

  case update.action
  of MembershipAction.Add:
    # Check if already have this member (by idCommitment)
    if gm.membershipByIdCommitment.hasKey(update.idCommitment):
      # Already have it, skip
      return ok()

    # Compute rateCommitment = Poseidon(idCommitment, userMessageLimit)
    # This is the actual leaf value stored in the RLN Merkle tree
    let rateCommitment = computeRateCommitment(
      update.idCommitment, update.userMessageLimit
    ).valueOr:
      return err("Failed to compute rate commitment: " & error)

    # Insert rateCommitment into RLN tree
    let insertResult = gm.rlnInstance.insertMemberAt(update.index, rateCommitment)
    if insertResult.isErr:
      return err("Failed to insert member from update: " & insertResult.error)

    # Update local tracking - track by idCommitment for spam recovery
    gm.membershipByIdCommitment[update.idCommitment] = update.index
    gm.membershipByIndex[update.index] = update.idCommitment
    gm.rateLimitByIdCommitment[update.idCommitment] = update.userMessageLimit
    gm.updateGroupSizeMetric()

    # Update next index if needed
    if update.index >= gm.nextIndex:
      gm.nextIndex = update.index + 1

    # Additions can keep the valid root window.
    gm.updateRootTrackerOrLog()
    gm.refreshProofCacheOrLog()

    # Call callback
    if gm.onRegister.isSome:
      await gm.onRegister.get()(update.idCommitment, update.index)

    debug "Member added from network update",
      index = update.index, userMessageLimit = update.userMessageLimit
  of MembershipAction.Remove:
    if not gm.membershipByIndex.hasKey(update.index):
      # Don't have this member, skip
      return ok()

    # Delete from RLN tree
    let deleteResult = gm.rlnInstance.removeMember(update.index)
    if deleteResult.isErr:
      return err("Failed to delete member from update: " & deleteResult.error)

    # Update local tracking
    let idCommitment = gm.membershipByIndex[update.index]
    gm.membershipByIdCommitment.del(idCommitment)
    gm.membershipByIndex.del(update.index)
    gm.rateLimitByIdCommitment.del(idCommitment)
    gm.updateGroupSizeMetric()

    # Removals invalidate previously accepted roots.
    gm.resetRootTrackerOrLog()
    gm.refreshProofCacheOrLog()

    # Call callback
    if gm.onWithdraw.isSome:
      await gm.onWithdraw.get()(idCommitment, update.index)

    # Check if we were removed
    if gm.membershipIndex.isSome and gm.membershipIndex.get() == update.index:
      gm.credentials = none(IdentityCredential)
      gm.membershipIndex = none(MembershipIndex)
      gm.partialProofCache = none(PartialProofCache)
      warn "Self membership removed by network"

    debug "Member removed from network update", index = update.index

  ok()

proc getMemberCount*(gm: OffchainGroupManager): int =
  ## Get the number of registered members.
  gm.membershipByIndex.len

proc getMemberIndexByIdCommitment*(
    gm: OffchainGroupManager, idCommitment: IDCommitment
): Option[MembershipIndex] {.raises: [].} =
  ## Get the index of a member by idCommitment.
  try:
    if gm.membershipByIdCommitment.hasKey(idCommitment):
      some(gm.membershipByIdCommitment[idCommitment])
    else:
      none(MembershipIndex)
  except KeyError:
    none(MembershipIndex)

proc getMemberIdCommitment*(
    gm: OffchainGroupManager, index: MembershipIndex
): Option[IDCommitment] {.raises: [].} =
  ## Get the identity commitment of a member by index.
  try:
    if gm.membershipByIndex.hasKey(index):
      some(gm.membershipByIndex[index])
    else:
      none(IDCommitment)
  except KeyError:
    none(IDCommitment)

proc getMemberRateLimit*(
    gm: OffchainGroupManager, idCommitment: IDCommitment
): uint64 {.raises: [].} =
  ## Get the rate limit of a member by idCommitment.
  ## Returns the node's default userMessageLimit if not found.
  gm.rateLimitByIdCommitment.getOrDefault(idCommitment, gm.userMessageLimit)

# =============================================================================
# Tree Snapshot Serialization
# =============================================================================
#
# Binary format for tree snapshots (used for bootstrap/sync):
#
# ┌─────────────────────────────────────────────────────────────┐
# │ Header (16 bytes)                                           │
# ├─────────────────────────────────────────────────────────────┤
# │ member_count: uint64 (8 bytes, little-endian)               │
# │ next_index:   uint64 (8 bytes, little-endian)               │
# ├─────────────────────────────────────────────────────────────┤
# │ Members (48 bytes each)                                     │
# ├─────────────────────────────────────────────────────────────┤
# │ For each member:                                            │
# │   commitment:        32 bytes (IDCommitment)                │
# │   index:             8 bytes (uint64, little-endian)        │
# │   userMessageLimit:  8 bytes (uint64, little-endian)        │
# └─────────────────────────────────────────────────────────────┘

const
  SnapshotHeaderSize = 16        # member_count (8) + next_index (8)
  SnapshotMemberSize = 48        # commitment (32) + index (8) + userMessageLimit (8)

# Note: writeUint64LE and readUint64LE are imported from bytes_utils via types

proc serializeTreeSnapshot*(gm: OffchainGroupManager): seq[byte] =
  ## Serialize the current membership tree state for bootstrap sharing.
  ## Returns a binary blob that can be saved to disk or sent over the network.
  let memberCount = gm.membershipByIndex.len
  let totalSize = SnapshotHeaderSize + (memberCount * SnapshotMemberSize)
  result = newSeq[byte](totalSize)

  var offset = 0

  # Write header
  result.writeUint64LE(offset, uint64(memberCount))
  offset += Uint64ByteSize

  result.writeUint64LE(offset, uint64(gm.nextIndex))
  offset += Uint64ByteSize

  # Write each member entry
  for index, commitment in gm.membershipByIndex:
    # Write commitment (32 bytes)
    copyMem(addr result[offset], unsafeAddr commitment[0], HashByteSize)
    offset += HashByteSize

    # Write index
    result.writeUint64LE(offset, uint64(index))
    offset += Uint64ByteSize

    # Write userMessageLimit
    let rateLimit = gm.rateLimitByIdCommitment.getOrDefault(
      commitment, gm.userMessageLimit
    )
    result.writeUint64LE(offset, rateLimit)
    offset += Uint64ByteSize

proc loadTreeSnapshot*(gm: OffchainGroupManager, data: seq[byte]): RlnResult[void] =
  ## Load a tree snapshot from binary data.
  ## This replaces the current tree state with the snapshot contents.

  # Validate minimum size for header
  if data.len < SnapshotHeaderSize:
    return err("Invalid snapshot: data too short for header")

  var offset = 0

  # Read header
  let memberCount = data.readUint64LE(offset)
  offset += Uint64ByteSize

  let nextIndex = data.readUint64LE(offset)
  offset += Uint64ByteSize

  # Validate total size matches expected
  let expectedSize = SnapshotHeaderSize + int(memberCount) * SnapshotMemberSize
  if data.len != expectedSize:
    error "Snapshot size mismatch",
      actual = data.len, expected = expectedSize, memberCount = memberCount
    return err("Invalid snapshot: size mismatch (expected " & $expectedSize & ", got " & $data.len & ")")

  trace "Loading tree snapshot", memberCount = memberCount, nextIndex = nextIndex

  # Clear existing state before loading
  gm.membershipByIdCommitment.clear()
  gm.membershipByIndex.clear()
  gm.rateLimitByIdCommitment.clear()
  gm.rootTracker.resetRoots()

  # Load each member
  for i in 0 ..< memberCount:
    # Read idCommitment
    var idCommitment: IDCommitment
    copyMem(addr idCommitment[0], unsafeAddr data[offset], HashByteSize)
    offset += HashByteSize

    # Read index
    let index = MembershipIndex(data.readUint64LE(offset))
    offset += Uint64ByteSize

    # Read userMessageLimit
    let userMessageLimit = data.readUint64LE(offset)
    offset += Uint64ByteSize

    # Compute rate commitment for the RLN tree using the stored userMessageLimit
    # Tree stores: rate_commitment = Poseidon(id_commitment, user_message_limit)
    let rateCommitment = computeRateCommitment(idCommitment, userMessageLimit).valueOr:
      error "Failed to compute rate commitment during snapshot load", index = index
      return err("Failed to compute rate commitment: " & error)

    # Insert into RLN Merkle tree
    let insertResult = gm.rlnInstance.insertMemberAt(index, rateCommitment)
    if insertResult.isErr:
      error "Failed to insert member from snapshot", index = index, error = insertResult.error
      return err("Failed to insert member: " & insertResult.error)

    # Update tracking tables - track by idCommitment for spam recovery
    gm.membershipByIdCommitment[idCommitment] = index
    gm.membershipByIndex[index] = idCommitment
    gm.rateLimitByIdCommitment[idCommitment] = userMessageLimit

  gm.nextIndex = MembershipIndex(nextIndex)
  gm.updateGroupSizeMetric()

  # Replace any previously accepted roots with the snapshot root.
  gm.resetRootTrackerOrLog()
  gm.refreshProofCacheOrLog()

  debug "Tree snapshot loaded successfully", memberCount = memberCount, nextIndex = nextIndex
  ok()

proc saveTreeToFile*(gm: OffchainGroupManager, path: string): RlnResult[void] =
  ## Save the current tree state to a file.
  let data = gm.serializeTreeSnapshot()
  trace "saveTreeToFile called", path = path, memberCount = gm.membershipByIndex.len
  try:
    writeFile(path, data)
    debug "Tree file written successfully", path = path
    ok()
  except IOError as e:
    err("Failed to write tree file: " & e.msg)

proc loadTreeFromFile*(gm: OffchainGroupManager, path: string): RlnResult[void] =
  ## Load tree state from a file.
  trace "loadTreeFromFile called", path = path
  try:
    let strData = readFile(path)
    trace "Tree file read successfully", dataLen = strData.len
    # Properly convert string to seq[byte] without cast
    var data = newSeq[byte](strData.len)
    if strData.len > 0:
      copyMem(addr data[0], unsafeAddr strData[0], strData.len)
    let loadResult = gm.loadTreeSnapshot(data)
    if loadResult.isErr:
      return loadResult

    # Flush the tree after loading to ensure internal cache is synced
    if not flush(gm.rlnInstance.ctx):
      return err("Failed to flush tree after loading")

    debug "Tree loaded and flushed",
      path = path,
      memberCount = gm.membershipByIndex.len

    return ok()
  except IOError as e:
    warn "Failed to read tree file", path = path, error = e.msg
    err("Failed to read tree file: " & e.msg)
