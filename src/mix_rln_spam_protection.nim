# Mix RLN Spam Protection Plugin
# Copyright (c) 2025 vacp2p
# Licensed under either of
#  * Apache License, version 2.0
#  * MIT license
# at your option.

## RLN-based spam protection plugin for libp2p mix networks.
##
## This plugin implements Rate Limiting Nullifiers (RLN) for per-hop proof
## generation and verification in mix networks. It integrates with nim-libp2p's
## SpamProtectionInterface and uses logos-messaging for membership coordination.
##
## ## Quick Start
##
## ```nim
## import mix_rln_spam_protection
##
## # Create configuration (RLN identifier is required)
## var config = defaultConfig()
## config.rlnIdentifier = myRlnIdentifier  # Must be same across all nodes
## config.keystorePassword = "my-password"
##
## # Create and initialize plugin
## let plugin = newMixRlnSpamProtection(config).get()
## await plugin.init()
##
## # Set up logos-messaging integration
## plugin.setPublishCallback(proc(topic: string, data: seq[byte]) {.async.} =
##   await logosMessaging.publish(topic, data)
## )
##
## # Start the plugin
## await plugin.start()
##
## # Register this node in the membership
## discard await plugin.registerSelf()
##
## # Use with mix protocol
## let mixProto = MixProtocol.new(
##   mixNodeInfo, pubNodeInfo, switch,
##   spamProtection = plugin,
##   spamProtectionConfig = initSpamProtectionConfig()
## )
## ```
##
## ## Architecture
##
## The plugin uses per-hop proof generation where each mix node:
## 1. Verifies the incoming proof from the previous hop
## 2. Generates a fresh proof for the next hop
## 3. Broadcasts proof metadata for network-wide spam detection
##
## Membership is managed offchain via content-topic propagation:
## - `/mix/rln/membership/v1` - membership additions/removals
## - `/mix/rln/metadata/v1` - proof metadata for spam detection
##
## ## Key Types
##
## - `MixRlnSpamProtection` - Main plugin implementing spam protection
## - `MixRlnConfig` - Configuration for the plugin
## - `OffchainGroupManager` - Membership management via content-topics
## - `NullifierLog` - Tracks proof metadata for spam detection
## - `IdentityCredential` - Node's RLN credentials
##
## ## SpamProtection Methods
##
## - `proofSize` - Field set to 288 (fixed RLN proof size)
## - `generateProof(bindingData): Result[EncodedProofData, string]` - Generate proof bound to sphinx packet
## - `verifyProof(encodedProofData, bindingData): Result[bool, string]` - Verify proof and check for spam

import
  ./mix_rln_spam_protection/[
    types,
    constants,
    protobuf,
    codec,
    rln_interface,
    group_manager,
    nullifier_log,
    spam_protection,
    coordination,
    credentials
  ]

export
  types,
  constants,
  protobuf,
  codec,
  spam_protection,
  coordination,
  credentials,
  group_manager,
  nullifier_log,
  rln_interface
