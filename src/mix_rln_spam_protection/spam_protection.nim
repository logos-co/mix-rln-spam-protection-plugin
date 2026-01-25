# Mix RLN Spam Protection Plugin
# Copyright (c) 2025 vacp2p
# Licensed under either of Apache License 2.0 or MIT license.

## Main spam protection interface implementing the nim-libp2p SpamProtectionInterface.
##
## This module provides the MixRlnSpamProtection type that can be used with
## the mix protocol for per-hop proof generation and verification.

import std/[options, strutils]
import chronos
import results
import chronicles

# Import nim-libp2p spam protection interface
import libp2p/protocols/mix/spam_protection as libp2p_spam

import ./types
import ./constants
import ./codec
import ./rln_interface
import ./group_manager
import ./nullifier_log
import ./credentials

export types, constants, codec, group_manager, nullifier_log, credentials
# Re-export nim-libp2p types for convenience
export libp2p_spam.SpamProtection
export libp2p_spam.EncodedProofData, libp2p_spam.BindingData

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

  # Main spam protection implementation - inherits from nim-libp2p interface
  MixRlnSpamProtection* = ref object of libp2p_spam.SpamProtection
    ## RLN-based spam protection for mix networks.
    ##
    ## Implements the SpamProtection interface from nim-libp2p for
    ## per-hop proof generation and verification.
    config: MixRlnConfig
    rlnInstance: RLNInstance
    groupManager: OffchainGroupManager
    nullifierLog: NullifierLog
    state: PluginState
    messageIdCounter: uint # Tracks messages within current epoch
    lastEpoch: Epoch
    publishCallback: Option[PublishCallback]
    spamHandler: Option[SpamHandler]

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

proc newMixRlnSpamProtection*(config: MixRlnConfig): RlnResult[MixRlnSpamProtection] =
  ## Create a new MixRlnSpamProtection instance.
  ##
  ## The instance must be initialized with init() before use.

  # Create RLN instance
  let rlnInstance = newRLNInstance(config.rlnResourcesPath).valueOr:
    return err("Failed to create RLN instance: " & error)

  # Create group manager with configured content topic
  let groupManager = newOffchainGroupManager(rlnInstance, config.membershipContentTopic)

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
    let (cred, maybeIndex, wasGenerated) = loadOrGenerateCredentials(
      sp.config.keystorePath, sp.config.keystorePassword
    ).valueOr:
      return err("Failed to load/generate credentials: " & error)

    sp.groupManager.credentials = some(cred)
    sp.groupManager.membershipIndex = maybeIndex

    if wasGenerated:
      info "Generated new credentials",
        commitment = cred.idCommitment[0 .. 7].toHex() & "..."
    else:
      info "Loaded existing credentials",
        commitment = cred.idCommitment[0 .. 7].toHex() & "...",
        hasIndex = maybeIndex.isSome
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

proc start*(sp: MixRlnSpamProtection): Future[RlnResult[void]] {.async.} =
  ## Start the spam protection plugin.
  ##
  ## This starts the group manager sync and nullifier log cleanup.
  ## After start() completes, the plugin is in Ready state.

  if sp.state == PluginState.Uninitialized:
    return err("Plugin not initialized")

  if sp.state == PluginState.Ready:
    return ok() # Already started

  # Start group manager
  let gmStartResult = await sp.groupManager.start()
  if gmStartResult.isErr:
    return err("Failed to start group manager: " & gmStartResult.error)

  # Start nullifier log cleanup
  sp.nullifierLog.start()

  sp.state = PluginState.Ready
  info "MixRlnSpamProtection started"
  ok()

proc stop*(sp: MixRlnSpamProtection) {.async.} =
  ## Stop the spam protection plugin.
  if sp.state == PluginState.Stopped:
    return

  await sp.groupManager.stop()
  await sp.nullifierLog.stop()

  sp.state = PluginState.Stopped
  info "MixRlnSpamProtection stopped"

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

method generateProof*(
    sp: MixRlnSpamProtection, bindingData: BindingData
): Result[EncodedProofData, string] {.gcsafe, raises: [].} =
  ## Generate an RLN proof bound to the given packet data.
  ##
  ## For per-hop generation, bindingData is the outgoing Sphinx packet.
  ## The proof is generated using the node's credentials and current epoch.

  info "MixRlnSpamProtection.generateProof called", bindingDataLen = bindingData.len

  if not sp.isReady():
    error "Spam protection not ready for proof generation"
    return err("Plugin not ready")

  let epoch = currentEpoch()

  # Reset message counter if epoch changed
  if epoch != sp.lastEpoch:
    sp.messageIdCounter = 0
    sp.lastEpoch = epoch

  # Check if we've exceeded message limit
  if sp.messageIdCounter >= uint(sp.config.userMessageLimit):
    error "Message limit exceeded",
      counter = sp.messageIdCounter, limit = sp.config.userMessageLimit
    return err("Message limit exceeded for current epoch")

  info "Calling groupManager.generateProof",
    bindingDataLen = bindingData.len,
    epochLen = epoch.len,
    rlnIdentifierLen = sp.config.rlnIdentifier.len,
    messageId = sp.messageIdCounter

  # Generate proof
  let proof = sp.groupManager.generateProof(
    seq[byte](bindingData), epoch, sp.config.rlnIdentifier, sp.messageIdCounter
  ).valueOr:
    error "GroupManager proof generation failed", error = error
    return err("Failed to generate proof: " & error)

  sp.messageIdCounter += 1

  # Serialize proof using protobuf
  let serialized = proof.toBytes()

  info "Generated RLN proof successfully",
    epoch = epochToUint64(epoch),
    messageId = sp.messageIdCounter - 1,
    proofLen = serialized.len,
    declaredProofSize = sp.proofSize,
    actualProofSize = serialized.len,
    nullifier = proof.nullifier[0 .. 7].toHex() & "..."

  # Verify the declared proofSize matches actual size
  if serialized.len != sp.proofSize:
    error "MISMATCH: Declared proofSize does not match actual protobuf-encoded size",
      declared = sp.proofSize,
      actual = serialized.len,
      difference = serialized.len - sp.proofSize

  ok(serialized)

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
    error "Failed to compute spammer commitment from secret", err = error
    return

  var idCommitment: IDCommitment
  copyMem(addr idCommitment[0], unsafeAddr spammerCommitment[0], HashByteSize)

  # Find the member index by commitment
  let memberIndex = sp.groupManager.getMemberIndex(idCommitment)

  if memberIndex.isSome:
    let index = memberIndex.get()

    info "Removing spammer from membership",
      index = index, commitment = idCommitment[0 .. 7].toHex() & "..."

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
    sp: MixRlnSpamProtection,
    encodedProofData: EncodedProofData,
    bindingData: BindingData,
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

  let curEpoch = currentEpoch()

  # Check epoch validity
  if not isEpochValid(proof.epoch, curEpoch):
    debug "Proof rejected: epoch out of range",
      proofEpoch = epochToUint64(proof.epoch),
      currentEpoch = epochToUint64(curEpoch),
      maxGap = sp.config.maxEpochGap
    return ok(false)

  # Check Merkle root validity
  let validRoots = sp.groupManager.rootTracker.getValidRoots()
  let currentRoot = sp.groupManager.rlnInstance.getMerkleRoot().valueOr:
    return err("Failed to get current Merkle root: " & error)

  if not sp.groupManager.validateRoot(proof.merkleRoot):
    error "Proof rejected: invalid Merkle root",
      proofRoot = proof.merkleRoot.toHex(),
      currentRoot = currentRoot.toHex(),
      numValidRoots = validRoots.len,
      validRootsPreview =
        if validRoots.len > 0:
          validRoots[0][0 .. 7].toHex() & "..."
        else:
          "none"
    return ok(false)

  # Verify the zkSNARK proof
  let isValid = sp.groupManager.verifyProof(
    proof, seq[byte](bindingData), sp.config.rlnIdentifier
  ).valueOr:
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
    asyncSpawn sp.publishCallback.get()(sp.config.proofMetadataContentTopic, data)

  debug "Proof verified successfully",
    epoch = epochToUint64(proof.epoch),
    nullifier = proof.nullifier[0 .. 7].toHex() & "..."

  ok(true)

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
  let result = sp.groupManager.loadTreeFromFile(sp.config.treePath)
  if result.isOk:
    let currentRoot = sp.groupManager.rlnInstance.getMerkleRoot().valueOr:
      return err("Failed to get Merkle root after loading tree: " & error)
    let memberCount = sp.groupManager.getMemberCount()
    info "Tree loaded from file",
      treePath = sp.config.treePath,
      memberCount = memberCount,
      currentRoot = currentRoot.toHex()
  result

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
