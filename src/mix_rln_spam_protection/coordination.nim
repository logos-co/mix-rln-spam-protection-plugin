# Mix RLN Spam Protection Plugin
# Copyright (c) 2025 vacp2p
# Licensed under either of Apache License 2.0 or MIT license.

## Coordination layer for RLN spam protection.
##
## This module provides utilities for integrating with logos-messaging
## to broadcast membership updates and proof metadata across the network.

import std/[options]
import chronos
import results
import chronicles

import ./types
import ./constants
import ./codec
import ./spam_protection

export types, constants, codec

logScope:
  topics = "mix-rln-coordination"

type
  # Subscription handler types
  MembershipSubscriptionHandler* = proc(update: MembershipUpdate) {.gcsafe, raises: [].}
  MetadataSubscriptionHandler* = proc(metadata: ProofMetadataBroadcast) {.gcsafe, raises: [].}

  # Coordination layer wrapper
  CoordinationLayer* = ref object
    ## Wrapper for coordinating RLN spam protection with logos-messaging.
    ##
    ## This provides a clean interface for:
    ## - Publishing membership updates and proof metadata
    ## - Subscribing to these topics and routing to the spam protection plugin
    spamProtection: MixRlnSpamProtection
    publishCallback: Option[PublishCallback]
    onMembershipUpdate: Option[MembershipSubscriptionHandler]
    onProofMetadata: Option[MetadataSubscriptionHandler]

proc newCoordinationLayer*(spamProtection: MixRlnSpamProtection): CoordinationLayer =
  ## Create a new coordination layer wrapper.
  CoordinationLayer(
    spamProtection: spamProtection,
    publishCallback: none(PublishCallback),
    onMembershipUpdate: none(MembershipSubscriptionHandler),
    onProofMetadata: none(MetadataSubscriptionHandler)
  )

proc setPublishCallback*(cl: CoordinationLayer, callback: PublishCallback) =
  ## Set the callback for publishing messages.
  ## This should be wired to logos-messaging's publish function.
  cl.publishCallback = some(callback)
  cl.spamProtection.setPublishCallback(callback)

proc setMembershipUpdateHandler*(cl: CoordinationLayer, handler: MembershipSubscriptionHandler) =
  ## Set additional handler for membership updates (for custom processing).
  cl.onMembershipUpdate = some(handler)

proc setProofMetadataHandler*(cl: CoordinationLayer, handler: MetadataSubscriptionHandler) =
  ## Set additional handler for proof metadata (for custom processing).
  cl.onProofMetadata = some(handler)

proc handleIncomingMessage*(
  cl: CoordinationLayer,
  contentTopic: string,
  data: seq[byte]
): Future[RlnResult[void]] {.async.} =
  ## Route incoming messages from logos-messaging to appropriate handlers.
  ##
  ## This should be called when messages are received on the RLN content topics.

  let membershipTopic = cl.spamProtection.getMembershipContentTopic()
  let metadataTopic = cl.spamProtection.getProofMetadataContentTopic()

  if contentTopic == membershipTopic:
    # Handle membership update
    let handleResult = await cl.spamProtection.handleMembershipUpdate(data)
    if handleResult.isErr:
      return err("Failed to handle membership update: " & handleResult.error)

    # Call additional handler if set
    if cl.onMembershipUpdate.isSome:
      let update = MembershipUpdate.decode(data).valueOr:
        return err("Failed to decode update for handler: " & $error)
      cl.onMembershipUpdate.get()(update)

  elif contentTopic == metadataTopic:
    # Handle proof metadata
    let metadataResult = cl.spamProtection.handleProofMetadata(data)
    if metadataResult.isErr:
      return err("Failed to handle proof metadata: " & metadataResult.error)

    # Call additional handler if set
    if cl.onProofMetadata.isSome:
      let metadata = ProofMetadataBroadcast.decode(data).valueOr:
        return err("Failed to decode metadata for handler: " & $error)
      cl.onProofMetadata.get()(metadata)

  else:
    return err("Unknown content topic: " & contentTopic)

  ok()

proc getContentTopics*(cl: CoordinationLayer): seq[string] =
  ## Get the list of content topics used by RLN coordination.
  cl.spamProtection.getContentTopics()

proc getDefaultContentTopics*(): seq[string] =
  ## Get the default content topics (for reference).
  @[MembershipContentTopic, ProofMetadataContentTopic]

# Helper function for building a logos-messaging subscription filter
proc buildSubscriptionFilter*(cl: CoordinationLayer): seq[tuple[contentTopic: string, handler: string]] =
  ## Build a subscription filter for logos-messaging.
  ## Returns tuples of (contentTopic, handlerName) for documentation.
  @[
    (cl.spamProtection.getMembershipContentTopic(), "handleMembershipUpdate"),
    (cl.spamProtection.getProofMetadataContentTopic(), "handleProofMetadata")
  ]

# Integration example documentation
const IntegrationExample* = """
## Integration with logos-messaging

```nim
import logos_messaging
import mix_rln_spam_protection

# Create configuration (optionally customize content topics)
var config = defaultConfig()
# config.membershipContentTopic = "/my-app/rln/membership/v1"
# config.proofMetadataContentTopic = "/my-app/rln/metadata/v1"

let spamProtection = newMixRlnSpamProtection(config).get()
await spamProtection.init()

# Create coordination layer
let coordination = newCoordinationLayer(spamProtection)

# Wire up publish callback to logos-messaging
coordination.setPublishCallback(proc(topic: string, data: seq[byte]) {.async.} =
  await logosMessaging.publish(topic, data)
)

# Subscribe to RLN topics (uses configured content topics)
for topic in coordination.getContentTopics():
  logosMessaging.subscribe(topic, proc(data: seq[byte]) {.async.} =
    discard await coordination.handleIncomingMessage(topic, data)
  )

# Start the spam protection
await spamProtection.start()

# Register self in the membership
discard await spamProtection.registerSelf()

# Use with mix protocol
let mixProto = MixProtocol.new(
  ...,
  spamProtection = spamProtection
)
```
"""

# Utility for creating a simple publish callback that logs (for testing)
proc createLoggingPublishCallback*(): PublishCallback =
  ## Create a publish callback that just logs messages (for testing).
  proc callback(contentTopic: string, data: seq[byte]): Future[void] {.async, gcsafe.} =
    debug "Would publish to coordination layer",
      topic = contentTopic,
      dataLen = data.len
  return callback

# Utility for printing membership update in human-readable form
proc formatMembershipUpdate*(update: MembershipUpdate): string =
  ## Format a membership update for logging/display.
  let actionStr = case update.action
    of MembershipAction.Add: "ADD"
    of MembershipAction.Remove: "REMOVE"

  result = actionStr & " member at index " & $update.index &
           " (commitment: " & update.idCommitment[0..7].toHex() & "...)"

# Note: toHex is imported from types module via spam_protection
