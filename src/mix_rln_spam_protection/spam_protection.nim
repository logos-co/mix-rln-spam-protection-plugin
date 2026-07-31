# Mix RLN Spam Protection Plugin
# Copyright (c) 2025 vacp2p
# Licensed under either of Apache License 2.0 or MIT license.

## Main spam protection interface implementing the libp2p_mix SpamProtectionInterface.
##
## This module provides the MixRlnSpamProtection type that can be used with
## the mix protocol for per-hop proof generation and verification.

import std/[math, options, deques, times, sequtils]
import chronos
import results
import chronicles
import stew/endians2

# Import libp2p_mix spam protection interface
import libp2p_mix/spam_protection as libp2p_spam

import ./types
import ./constants
import ./codec
import ./rln_interface
import ./group_manager
import ./nullifier_log
import ./credentials

export types, constants, codec, group_manager, nullifier_log, credentials
# Re-export libp2p_mix types for convenience
export libp2p_spam.SpamProtection

logScope:
  topics = "mix-rln-spam-protection"

type
  # Configuration for the spam protection plugin
  MixRlnConfig* = object ## Configuration for the RLN spam protection plugin.
    rlnIdentifier*: RlnIdentifier
      ## Application-specific RLN identifier. Must be the same across all nodes.
    epochDurationSeconds*: float ## Duration of each epoch in seconds. Default: 10.0
    maxEpochGap*: int ## Maximum allowed epoch gap. Default: 5
    userMessageLimit*: int ## Maximum messages per epoch per member. Default: 100
    keystorePath*: string ## Path to the credentials keystore file.
    keystorePassword*: string ## Password for the keystore.
    treePath*: string ## Path for persisting the Merkle tree.
    rlnResourcesPath*: string ## Path to RLN circuit resources (empty for bundled).
    membershipContentTopic*: string
      ## Content topic for broadcasting membership updates. Default: "/mix/rln/membership/v1"
    proofMetadataContentTopic*: string
      ## Content topic for broadcasting proof metadata. Default: "/mix/rln/metadata/v1"

  # Main spam protection implementation - inherits from libp2p_mix interface
  MixRlnSpamProtection* = ref object of libp2p_spam.SpamProtection
    ## RLN-based spam protection for mix networks.
    ##
    ## Implements the SpamProtection interface from libp2p_mix for
    ## per-hop proof generation and verification.
    config: MixRlnConfig
    rlnInstance: RLNInstance
    groupManager: OffchainGroupManager
    nullifierLog: NullifierLog
    state: PluginState
    messageIdCounter: uint # Tracks messages within current epoch
    freedMessageIds: Deque[uint] # Reclaimed IDs from discarded cover packets
    lastEpoch: Epoch
    publishCallback: Option[PublishCallback]
    spamHandler: Option[SpamHandler]
    epochTimerLoop: Future[void]
    pendingBroadcasts: seq[Future[void]]
      ## In-flight best-effort proof-metadata broadcasts. verifyProof is
      ## synchronous so it cannot await these; they are tracked here (pruned
      ## when finished) and cancelled in stop() instead of being orphaned.

proc defaultRlnIdentifier*(): RlnIdentifier =
  ## Get the default RLN identifier.
  var id: RlnIdentifier
  let idStr = MixRlnIdentifier
  let copyLen = min(idStr.len, HashByteSize)
  if copyLen > 0:
    copyMem(addr id[0], unsafeAddr idStr[0], copyLen)
  id

proc defaultConfig*(): MixRlnConfig =
  ## Get the default configuration.
  MixRlnConfig(
    rlnIdentifier: defaultRlnIdentifier(),
    epochDurationSeconds: EpochDurationSeconds,
    maxEpochGap: MaxEpochGap,
    userMessageLimit: UserMessageLimit,
    keystorePath: DefaultKeystorePath,
    keystorePassword: "",
    treePath: DefaultTreePath,
    rlnResourcesPath: "",
    membershipContentTopic: MembershipContentTopic,
    proofMetadataContentTopic: ProofMetadataContentTopic,
  )

proc new*(
    T: typedesc[MixRlnSpamProtection], config: MixRlnConfig
): RlnResult[MixRlnSpamProtection] =
  ## Create a new MixRlnSpamProtection instance.
  ##
  ## The instance must be initialized with init() before use.

  # Create RLN instance
  let rlnInstance = newRLNInstance(config.rlnResourcesPath).valueOr:
    return err("Failed to create RLN instance: " & error)

  # Create group manager with configured content topic and message limit
  let groupManager = newOffchainGroupManager(
    rlnInstance, config.membershipContentTopic, uint64(config.userMessageLimit)
  )

  # Create nullifier log
  let nullifierLog = newNullifierLog()

  ok(
    MixRlnSpamProtection(
      proofSize: RateLimitProofByteSize, # Set on base class
      config: config,
      rlnInstance: rlnInstance,
      groupManager: groupManager,
      nullifierLog: nullifierLog,
      state: PluginState.Uninitialized,
      messageIdCounter: 0,
      freedMessageIds: initDeque[uint](),
      lastEpoch: default(Epoch),
      publishCallback: none(PublishCallback),
      spamHandler: none(SpamHandler),
    )
  )

proc setPublishCallback*(sp: MixRlnSpamProtection, callback: PublishCallback) =
  ## Set the callback for publishing to logos-messaging.
  sp.publishCallback = some(callback)
  sp.groupManager.setPublishCallback(callback)

proc setSpamHandler*(sp: MixRlnSpamProtection, handler: SpamHandler) =
  ## Set the handler called when spam is detected.
  sp.spamHandler = some(handler)

proc init*(sp: MixRlnSpamProtection): Future[RlnResult[void]] {.async.} =
  ## Initialize the spam protection plugin.
  ##
  ## This loads or generates credentials and initializes the group manager.
  ## After init(), the plugin is in Syncing state waiting for membership sync.

  if sp.state != PluginState.Uninitialized:
    return err("Plugin already initialized")

  info "Initializing MixRlnSpamProtection"

  # Initialize group manager
  let gmInitResult = await sp.groupManager.init()
  if gmInitResult.isErr:
    return err("Failed to initialize group manager: " & gmInitResult.error)

  # Load or generate credentials
  if sp.config.keystorePassword.len > 0:
    let (cred, maybeIndex, maybeRateLimit, wasGenerated) = loadOrGenerateCredentials(
      sp.config.keystorePath, sp.config.keystorePassword
    ).valueOr:
      return err("Failed to load/generate credentials: " & error)

    sp.groupManager.credentials = some(cred)
    sp.groupManager.membershipIndex = maybeIndex
    # If keystore has a stored rate limit, use it (overrides node's config)
    if maybeRateLimit.isSome:
      sp.groupManager.userMessageLimit = maybeRateLimit.get()
      info "Using rate limit from keystore", userMessageLimit = maybeRateLimit.get()
    # Note: We don't restore to tree here if we have an index, because loadTree()
    # might be called next which would clear membership tables.
    # The restoration happens in restoreCredentialsToTree() after tree operations.

    if wasGenerated:
      info "Generated new credentials",
        commitment = cred.idCommitment[0 .. 7].toHex() & "..."
    else:
      info "Loaded existing credentials",
        commitment = cred.idCommitment[0 .. 7].toHex() & "...",
        hasIndex = maybeIndex.isSome,
        hasRateLimit = maybeRateLimit.isSome
  else:
    # Generate credentials without saving
    let cred = generateCredentials().valueOr:
      return err("Failed to generate credentials: " & error)
    sp.groupManager.credentials = some(cred)
    info "Generated ephemeral credentials (not saved)",
      commitment = cred.idCommitment[0 .. 7].toHex() & "..."

  sp.state = PluginState.Syncing
  info "MixRlnSpamProtection initialized, waiting for sync"
  ok()

proc advanceEpoch(sp: MixRlnSpamProtection, epoch: Epoch) =
  ## Reset all per-epoch state and notify listeners. Centralised so any new
  ## per-epoch field (counters, pools, caches) only needs to be cleared here.
  sp.messageIdCounter = 0
  sp.freedMessageIds.clear()
  sp.lastEpoch = epoch
  sp.notifyEpochChange(epochToUint64(epoch))

proc runEpochTimer(sp: MixRlnSpamProtection) {.async: (raises: [CancelledError]).} =
  ## Background timer that detects epoch boundaries and fires OnEpochChange
  ## callbacks even when no proofs are being generated.
  ##
  ## Sleeps until the next absolute epoch boundary on each iteration to avoid
  ## cumulative drift from processing overhead. This also ensures the first
  ## tick aligns to the next real epoch boundary rather than
  ## `startTime + epochDuration`.
  ##
  ## A 1 ms epsilon is added to `sleepMs` so we wake strictly *after* the
  ## boundary: `calcEpoch` uses ceil semantics, so the boundary time itself
  ## (e.g. t == 10.0 for epochDur == 10) still belongs to the previous epoch.
  ## Without the epsilon, a wake-up landing exactly on the boundary would see
  ## the old epoch and miss the transition for a full period.
  while sp.state != PluginState.Stopped:
    let
      nowSec = getTime().toUnixFloat()
      epochDur = sp.config.epochDurationSeconds
      timeIntoEpoch = floorMod(nowSec, epochDur)
      sleepMs = max(1, int((epochDur - timeIntoEpoch) * 1000.0)) + 1
    # chronos.milliseconds is qualified to disambiguate from std/times.milliseconds
    # (which returns TimeInterval, not chronos.Duration).
    await sleepAsync(chronos.milliseconds(sleepMs))

    let epoch = currentEpoch(sp.config.epochDurationSeconds)
    if epoch != sp.lastEpoch:
      sp.advanceEpoch(epoch)

proc start*(sp: MixRlnSpamProtection): Future[RlnResult[void]] {.async.} =
  ## Start the spam protection plugin.
  ##
  ## This starts the group manager sync, nullifier log cleanup,
  ## and epoch boundary detection timer.
  ## After start() completes, the plugin is in Ready state.

  if sp.state == PluginState.Uninitialized:
    return err("Plugin not initialized")

  if sp.state == PluginState.Ready:
    return ok()

  let gmStartResult = await sp.groupManager.start()
  if gmStartResult.isErr:
    return err("Failed to start group manager: " & gmStartResult.error)

  sp.nullifierLog.start()
  sp.epochTimerLoop = sp.runEpochTimer()

  sp.state = PluginState.Ready
  info "MixRlnSpamProtection started"
  ok()

proc stop*(sp: MixRlnSpamProtection) {.async.} =
  ## Stop the spam protection plugin.
  if sp.state == PluginState.Stopped:
    return

  sp.state = PluginState.Stopped

  if not sp.epochTimerLoop.isNil:
    await sp.epochTimerLoop.cancelAndWait()

  # Cancel any in-flight proof-metadata broadcasts.
  for fut in sp.pendingBroadcasts:
    if not fut.isNil and not fut.finished:
      await fut.cancelAndWait()
  sp.pendingBroadcasts.setLen(0)

  await sp.groupManager.stop()
  await sp.nullifierLog.stop()

  info "MixRlnSpamProtection stopped"

proc broadcastProofMetadata(
    sp: MixRlnSpamProtection, data: seq[byte]
) {.async, gcsafe.} =
  ## Best-effort broadcast of proof metadata to the coordination layer.
  ## verifyProof is synchronous (it overrides a sync base method), so this runs
  ## as a tracked background future rather than a fire-and-forget asyncSpawn.
  (await sp.publishCallback.get()(sp.config.proofMetadataContentTopic, data)).isOkOr:
    warn "Failed to broadcast proof metadata", error = error

{.push raises: [], gcsafe.}

proc isReady*(sp: MixRlnSpamProtection): bool =
  ## Check if the plugin is ready for proof operations.
  sp.state == PluginState.Ready and sp.groupManager.isReady()

proc registerSelf*(
    sp: MixRlnSpamProtection
): Future[RlnResult[MembershipIndex]] {.async.} =
  ## Register this node's credentials with the group.
  ##
  ## This should be called after init() to register the node in the membership tree.

  if sp.state == PluginState.Uninitialized:
    return err("Plugin not initialized")

  if sp.groupManager.credentials.isNone:
    return err("No credentials available")

  let creds = sp.groupManager.credentials.get()

  # Check if already registered
  if sp.groupManager.membershipIndex.isSome:
    return ok(sp.groupManager.membershipIndex.get())

  # Register with group manager
  let index = await sp.groupManager.register(creds)
  if index.isErr:
    return err("Failed to register: " & index.error)

  # Update keystore with membership index
  if sp.config.keystorePassword.len > 0:
    discard saveKeystore(
      creds, sp.config.keystorePassword, sp.config.keystorePath, some(index.get())
    )

  info "Self registered", index = index.get()
  ok(index.get())

# SpamProtection implementation

# Proof token layout (opaque to callers):
#   [epoch: 8 BE][messageId: 8 BE][merkleRoot: 32]
const
  ProofTokenEpochOffset = 0
  ProofTokenMsgIdOffset = 8
  ProofTokenRootOffset = 16
  ProofTokenSize = ProofTokenRootOffset + sizeof(MerkleNode) # 48

type ProofToken = object
  epoch: uint64
  messageId: uint64
  merkleRoot: MerkleNode

func encode(t: ProofToken): seq[byte] =
  result = newSeq[byte](ProofTokenSize)
  result[ProofTokenEpochOffset ..< ProofTokenMsgIdOffset] = t.epoch.toBytesBE()
  result[ProofTokenMsgIdOffset ..< ProofTokenRootOffset] = t.messageId.toBytesBE()
  copyMem(
    addr result[ProofTokenRootOffset], unsafeAddr t.merkleRoot[0], sizeof(MerkleNode)
  )

func decode(T: type ProofToken, bytes: openArray[byte]): Result[ProofToken, string] =
  if bytes.len != ProofTokenSize:
    return err("invalid proof token length: " & $bytes.len)
  var token: ProofToken
  token.epoch = uint64.fromBytesBE(
    bytes.toOpenArray(ProofTokenEpochOffset, ProofTokenMsgIdOffset - 1)
  )
  token.messageId = uint64.fromBytesBE(
    bytes.toOpenArray(ProofTokenMsgIdOffset, ProofTokenRootOffset - 1)
  )
  copyMem(
    addr token.merkleRoot[0], unsafeAddr bytes[ProofTokenRootOffset], sizeof(MerkleNode)
  )
  ok(token)

method generateProof*(
    sp: MixRlnSpamProtection, bindingData: seq[byte]
): Result[libp2p_spam.ProofResult, string] {.gcsafe, raises: [].} =
  ## Generate an RLN proof bound to the given packet data.
  ##
  ## For per-hop generation, bindingData is the outgoing Sphinx packet.
  ## The proof is generated using the node's credentials and current epoch.
  ## Returns a ProofResult with the proof and an opaque token encoding the
  ## messageId used, which can be reclaimed via reclaimProofToken if the
  ## packet is discarded before sending.

  trace "MixRlnSpamProtection.generateProof called", bindingDataLen = bindingData.len

  if not sp.isReady():
    warn "Spam protection not ready for proof generation"
    return err("Plugin not ready")

  let epoch = currentEpoch(sp.config.epochDurationSeconds)

  if epoch != sp.lastEpoch:
    sp.advanceEpoch(epoch)

  # Reuse a freed messageId if available, otherwise allocate the next one.
  # Guard against exceeding userMessageLimit here so callers see a clear
  # rate-limit error instead of a cryptic failure from deep inside RLN.
  let (msgId, reused) =
    if sp.freedMessageIds.len > 0:
      (sp.freedMessageIds.popFirst(), true)
    else:
      let id = sp.messageIdCounter
      if id >= uint(sp.config.userMessageLimit):
        return err(
          "Message rate limit exceeded for current epoch (messageId=" & $id & ", limit=" &
            $sp.config.userMessageLimit & ")"
        )
      sp.messageIdCounter += 1
      (id, false)

  trace "Calling groupManager.generateProof",
    bindingDataLen = bindingData.len, messageId = msgId, reused = reused

  # Generate proof
  let proof = sp.groupManager.generateProof(
    bindingData, epoch, sp.config.rlnIdentifier, msgId
  ).valueOr:
    error "GroupManager proof generation failed", error = error
    return err("Failed to generate proof: " & error)

  # Serialize proof using protobuf
  let serialized = proof.toBytes()

  # Encode epoch + messageId + merkleRoot as opaque token.
  # The epoch qualifier is critical for safe reclaim: a token built in
  # epoch N must NOT be reclaimed into epoch N+1's freed pool, or the same
  # (epoch, messageId) pair could be issued twice in N+1, causing an RLN
  # double-signal (slashing risk).
  let
    epochU64 = epochToUint64(epoch)
    token = ProofToken(
      epoch: epochU64, messageId: msgId.uint64, merkleRoot: proof.merkleRoot
    ).encode()

  debug "Generated RLN proof successfully", epoch = epochU64, messageId = msgId

  ok(libp2p_spam.ProofResult(proof: serialized, token: token))

method reclaimProofToken*(
    sp: MixRlnSpamProtection, token: seq[byte]
) {.gcsafe, raises: [].} =
  ## Reclaim a proof slot from a discarded precomputed cover packet.
  ##
  ## Drops the reclaim silently (trace only) on any of:
  ##   - malformed token
  ##   - cross-epoch token (epoch N reclaimed in epoch N+1)
  ##   - out-of-range messageId (>= userMessageLimit)
  ##   - messageId not yet allocated in this epoch (>= messageIdCounter)
  ##   - duplicate reclaim of an id already in the freed pool
  ##
  ## Each guard prevents the same (epoch, messageId) pair from being issued
  ## twice in one epoch — i.e. an RLN double-signal / slashing risk.
  let decoded = ProofToken.decode(token).valueOr:
    trace "Malformed proof token - dropping reclaim", len = token.len
    return

  let currentEpochU64 = epochToUint64(currentEpoch(sp.config.epochDurationSeconds))
  if decoded.epoch != currentEpochU64:
    trace "Cross-epoch proof token reclaim dropped",
      tokenEpoch = decoded.epoch, currentEpoch = currentEpochU64
    return

  if decoded.messageId >= uint64(sp.config.userMessageLimit):
    trace "Out-of-range messageId in reclaim - dropping",
      messageId = decoded.messageId, limit = sp.config.userMessageLimit
    return

  if decoded.messageId >= sp.messageIdCounter.uint64:
    trace "Reclaim of unallocated messageId - dropping",
      messageId = decoded.messageId, counter = sp.messageIdCounter
    return

  # Linear scan for duplicate is O(N) but N is bounded by userMessageLimit;
  # this keeps the hot generateProof path scan-free.
  let id = uint(decoded.messageId)
  for existing in sp.freedMessageIds:
    if existing == id:
      trace "Duplicate proof token reclaim - dropping",
        epoch = decoded.epoch, messageId = decoded.messageId
      return

  sp.freedMessageIds.addLast(id)
  trace "Reclaimed proof token", epoch = decoded.epoch, messageId = decoded.messageId

method isProofTokenValid*(
    sp: MixRlnSpamProtection, token: seq[byte]
): bool {.gcsafe, raises: [].} =
  ## Check if the Merkle root embedded in the proof token is still in the
  ## acceptable roots window. If the root has fallen out of the window
  ## (due to membership changes), the prebuilt proof would be rejected
  ## by verifiers and the sender could be flagged as a spammer.
  let decoded = ProofToken.decode(token).valueOr:
    trace "Malformed proof token - rejecting", len = token.len
    return false
  let root = decoded.merkleRoot
  let valid = sp.groupManager.validateRoot(root)
  if not valid:
    trace "Prebuilt proof token has stale Merkle root",
      root = root[0 .. 7].toHex() & "..."
  valid

{.pop.}

proc handleSpamDetected(
    sp: MixRlnSpamProtection, proof: RateLimitProof, conflictingEntry: NullifierEntry
) {.async.} =
  ## Handle spam detection: recover secret, log it, remove member, broadcast removal.

  # Build a fake "conflicting proof" from the entry for secret recovery
  # In reality we'd need the full proof, but we can use shares for Shamir reconstruction
  var conflictingProof = proof
  conflictingProof.shareX = conflictingEntry.metadata.shareX
  conflictingProof.shareY = conflictingEntry.metadata.shareY

  # Recover secret
  let secret = sp.rlnInstance.recoverSecret(proof, conflictingProof).valueOr:
    error "Failed to recover secret from spam proofs", err = error
    return

  # Log the secret (as requested - no slashing for now)
  error "SPAM DETECTED - Recovered secret key",
    secretHex = secret.toHex(),
    nullifier = proof.nullifier.toHex(),
    epoch = epochToUint64(proof.epoch)

  # Compute the spammer's identity commitment from their secret
  # idCommitment = Poseidon(idSecretHash)
  let spammerCommitment = poseidonHash(@[@secret]).valueOr:
    warn "Recovered spammer secret but could not map it back to a member commitment",
      err = error
    if sp.spamHandler.isSome:
      await sp.spamHandler.get()(proof, secret, 0)
    return

  var idCommitment: IDCommitment
  copyMem(addr idCommitment[0], unsafeAddr spammerCommitment[0], HashByteSize)

  # Look up the spammer by their idCommitment (tracked for spam recovery)
  let memberIndex = sp.groupManager.getMemberIndexByIdCommitment(idCommitment)

  if memberIndex.isSome:
    let index = memberIndex.get()

    info "Removing spammer from membership",
      index = index, idCommitment = idCommitment[0 .. 7].toHex() & "..."

    # Remove from local tree and broadcast deletion
    # The withdraw method handles both local removal and broadcast
    let withdrawResult = await sp.groupManager.withdraw(index)
    if withdrawResult.isErr:
      error "Failed to withdraw spammer", err = withdrawResult.error
    else:
      info "Spammer membership removed and deletion broadcast", index = index

    # Call spam handler if set
    if sp.spamHandler.isSome:
      await sp.spamHandler.get()(proof, secret, index)
  else:
    # Member not found locally - might have been removed already or
    # we don't have their commitment in our tree
    warn "Spammer commitment not found in local membership tree",
      commitment = idCommitment[0 .. 7].toHex() & "..."

    # Still call spam handler with index 0 as placeholder
    if sp.spamHandler.isSome:
      await sp.spamHandler.get()(proof, secret, 0)

method verifyProof*(
    sp: MixRlnSpamProtection, encodedProofData: seq[byte], bindingData: seq[byte]
): Result[bool, string] {.gcsafe, raises: [].} =
  ## Verify an RLN proof and check for spam.
  ##
  ## This performs:
  ## 1. Epoch validation (within acceptable gap)
  ## 2. Merkle root validation (in valid roots window)
  ## 3. zkSNARK proof verification
  ## 4. Nullifier check for spam/duplicate detection

  if not sp.isReady():
    return err("Plugin not ready")

  # Deserialize proof using protobuf
  let proof = RateLimitProof.decode(encodedProofData).valueOr:
    return err("Failed to decode proof: " & $error)

  let curEpoch = currentEpoch(sp.config.epochDurationSeconds)

  # Check epoch validity
  if not isEpochValid(proof.epoch, curEpoch, sp.config.maxEpochGap):
    debug "Proof rejected: epoch out of range",
      proofEpoch = epochToUint64(proof.epoch),
      currentEpoch = epochToUint64(curEpoch),
      maxGap = sp.config.maxEpochGap
    return ok(false)

  # Check Merkle root validity
  if not sp.groupManager.validateRoot(proof.merkleRoot):
    debug "Proof rejected: invalid Merkle root"
    return ok(false)

  # Verify the zkSNARK proof
  let isValid = sp.groupManager.verifyProof(proof, bindingData, sp.config.rlnIdentifier).valueOr:
    return err("Proof verification error: " & error)

  if not isValid:
    debug "Proof rejected: invalid zkSNARK proof"
    return ok(false)

  # Compute external nullifier for spam checking
  let extNullifier = computeExternalNullifier(proof.epoch, sp.config.rlnIdentifier).valueOr:
    return err("Failed to compute external nullifier: " & error)

  # Check nullifier log for spam/duplicate
  let metadata = ProofMetadata(
    nullifier: proof.nullifier,
    shareX: proof.shareX,
    shareY: proof.shareY,
    externalNullifier: extNullifier,
    epoch: proof.epoch,
  )

  let spamResult =
    try:
      sp.nullifierLog.checkAndInsert(metadata)
    except KeyError as e:
      return err("Nullifier log error: " & e.msg)

  if spamResult.isDuplicate:
    debug "Duplicate message detected, discarding"
    return ok(false)

  if spamResult.isSpam:
    warn "Spam detected!",
      nullifier = proof.nullifier.toHex(), epoch = epochToUint64(proof.epoch)

    # Handle spam asynchronously
    if spamResult.conflictingEntry.isSome:
      asyncSpawn sp.handleSpamDetected(proof, spamResult.conflictingEntry.get())

    return ok(false)

  # Broadcast proof metadata to coordination layer
  if sp.publishCallback.isSome:
    let broadcast = ProofMetadataBroadcast(
      nullifier: proof.nullifier,
      shareX: proof.shareX,
      shareY: proof.shareY,
      externalNullifier: extNullifier,
      epoch: proof.epoch,
    )
    let data = broadcast.toBytes()
    # verifyProof is synchronous, so track the background broadcast future
    # (pruning finished ones) rather than firing an untracked asyncSpawn;
    # stop() cancels any that are still in flight.
    sp.pendingBroadcasts.keepItIf(not it.finished)
    sp.pendingBroadcasts.add(sp.broadcastProofMetadata(data))

  debug "Proof verified successfully",
    epoch = epochToUint64(proof.epoch),
    nullifier = proof.nullifier[0 .. 7].toHex() & "..."

  ok(true)

method epochDurationSeconds*(sp: MixRlnSpamProtection): float64 {.gcsafe, raises: [].} =
  sp.config.epochDurationSeconds

method rateLimitBudget*(sp: MixRlnSpamProtection): int {.gcsafe, raises: [].} =
  sp.config.userMessageLimit

# Coordination layer handlers

proc handleMembershipUpdate*(
    sp: MixRlnSpamProtection, data: seq[byte]
): Future[RlnResult[void]] {.async.} =
  ## Handle a membership update received from the coordination layer.
  let update = MembershipUpdate.decode(data).valueOr:
    return err("Failed to decode membership update: " & $error)

  await sp.groupManager.handleMembershipUpdate(update)

proc handleProofMetadata*(sp: MixRlnSpamProtection, data: seq[byte]): RlnResult[void] =
  ## Handle proof metadata received from the coordination layer.
  ## This enables network-wide spam detection.
  let broadcast = ProofMetadataBroadcast.decode(data).valueOr:
    return err("Failed to decode proof metadata: " & $error)

  let spamResult =
    try:
      sp.nullifierLog.handleNetworkMetadata(broadcast)
    except KeyError as e:
      return err("Nullifier log error: " & e.msg)

  if spamResult.isSpam:
    warn "Spam detected from network metadata",
      nullifier = broadcast.nullifier.toHex(), epoch = epochToUint64(broadcast.epoch)
    # Note: We can't recover the secret from just metadata,
    # we'd need the full proofs which are exchanged separately

  ok()

# Tree persistence

proc saveTree*(sp: MixRlnSpamProtection): RlnResult[void] =
  ## Save the current tree state to file.
  sp.groupManager.saveTreeToFile(sp.config.treePath)

proc loadTree*(sp: MixRlnSpamProtection): RlnResult[void] =
  ## Load tree state from file.
  let loadResult = sp.groupManager.loadTreeFromFile(sp.config.treePath)
  if loadResult.isOk:
    let memberCount = sp.groupManager.getMemberCount()
    debug "Tree loaded from file",
      treePath = sp.config.treePath, memberCount = memberCount
  loadResult

proc restoreCredentialsToTree*(sp: MixRlnSpamProtection): RlnResult[void] =
  ## Restore our credentials to the tree if we have an index.
  ## This should be called after tree loading (whether it succeeds or fails).
  ## If our member is already in the tree, this is a no-op.
  if sp.groupManager.membershipIndex.isSome and sp.groupManager.credentials.isSome:
    let cred = sp.groupManager.credentials.get()
    let index = sp.groupManager.membershipIndex.get()

    # Check if our member is already in the tree (tracked by idCommitment)
    if not sp.groupManager.hasMemberByIdCommitment(cred.idCommitment):
      let restoreRes =
        sp.groupManager.restoreMemberFromKeystore(cred.idCommitment, index)
      if restoreRes.isErr:
        return err("Failed to restore member from keystore: " & restoreRes.error)
      info "Restored credentials to tree", index = index

  # Always flush after tree operations to ensure Zerokit internal cache is synced
  if not flush(sp.groupManager.rlnInstance.ctx):
    return err("Failed to flush tree after restoring credentials")

  ok()

# Utility accessors

proc getCredentials*(sp: MixRlnSpamProtection): Option[IdentityCredential] =
  ## Get the node's credentials.
  sp.groupManager.credentials

proc getMembershipIndex*(sp: MixRlnSpamProtection): Option[MembershipIndex] =
  ## Get the node's membership index.
  sp.groupManager.membershipIndex

proc getMemberCount*(sp: MixRlnSpamProtection): int =
  ## Get the number of registered members.
  sp.groupManager.getMemberCount()

proc getRlnIdentifier*(sp: MixRlnSpamProtection): RlnIdentifier =
  ## Get the configured RLN identifier.
  sp.config.rlnIdentifier

proc getState*(sp: MixRlnSpamProtection): PluginState =
  ## Get the current plugin state.
  sp.state

proc getMembershipContentTopic*(sp: MixRlnSpamProtection): string =
  ## Get the configured membership content topic.
  sp.config.membershipContentTopic

proc getProofMetadataContentTopic*(sp: MixRlnSpamProtection): string =
  ## Get the configured proof metadata content topic.
  sp.config.proofMetadataContentTopic

proc getContentTopics*(sp: MixRlnSpamProtection): seq[string] =
  ## Get all content topics used by this plugin.
  @[sp.config.membershipContentTopic, sp.config.proofMetadataContentTopic]

# Note: toHex is imported from types module
