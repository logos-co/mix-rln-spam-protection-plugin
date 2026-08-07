# Mix RLN Spam Protection Plugin
# Copyright (c) 2025 vacp2p
# Licensed under either of Apache License 2.0 or MIT license.

## Nullifier log for tracking proof metadata and detecting spam (double signaling).
##
## The nullifier log maintains a cache of proof metadata per epoch to detect
## when a member sends more than their allowed messages within an epoch.

import std/[tables, options]
import chronicles

import ./types

export types

logScope:
  topics = "mix-rln-nullifier-log"

type
  # Entry in the nullifier log
  NullifierEntry* = object
    metadata*: ProofMetadata

  # Per-epoch nullifier tracking
  EpochLog* = Table[Nullifier, seq[NullifierEntry]]

  # Spam detection result
  SpamDetectionResult* = object
    isSpam*: bool
    isDuplicate*: bool
    conflictingEntry*: Option[NullifierEntry]

  NullifierLog* = ref object ## Log tracking nullifiers per epoch for spam detection.
    log: Table[Epoch, EpochLog]

proc newNullifierLog*(): NullifierLog =
  ## Create a new nullifier log.
  NullifierLog(log: initTable[Epoch, EpochLog]())

proc prune*(nl: NullifierLog, curEpoch: Epoch, maxEpochGap: int) {.raises: [].} =
  ## Remove entries whose epoch falls outside the window defined by `curEpoch`
  ## and `maxEpochGap`. Pass the same window used when verifying proofs, or
  ## entries are dropped while proofs carrying their epoch are still accepted.
  var expiredEpochs: seq[Epoch] = @[]

  # Collect first: deleting while iterating the table is unsafe
  for epoch in nl.log.keys:
    if not isEpochValid(epoch, curEpoch, maxEpochGap):
      expiredEpochs.add(epoch)

  # Remove each expired epoch and everything recorded under it
  for epoch in expiredEpochs:
    nl.log.del(epoch)

  if expiredEpochs.len > 0:
    debug "Nullifier log pruned",
      removedEpochs = expiredEpochs.len, remainingEpochs = nl.log.len

proc checkAndInsert*(
    nl: NullifierLog, metadata: ProofMetadata
): SpamDetectionResult {.raises: [KeyError].} =
  ## Check if a proof is spam or duplicate, and insert if valid.
  ##
  ## Returns:
  ##   - isSpam=true if same nullifier with different shares (double signaling)
  ##   - isDuplicate=true if exact same metadata seen before
  ##   - conflictingEntry contains the previous entry if spam detected

  result = SpamDetectionResult(
    isSpam: false, isDuplicate: false, conflictingEntry: none(NullifierEntry)
  )

  let epoch = metadata.epoch
  let nullifier = metadata.nullifier

  # Ensure epoch log exists
  if not nl.log.hasKey(epoch):
    nl.log[epoch] = initTable[Nullifier, seq[NullifierEntry]]()

  # Check if we have entries for this nullifier
  if nl.log[epoch].hasKey(nullifier):
    let existingEntries = nl.log[epoch][nullifier]

    for entry in existingEntries:
      # Check if exact duplicate (same shares)
      if entry.metadata.shareX == metadata.shareX and
          entry.metadata.shareY == metadata.shareY:
        result.isDuplicate = true
        debug "Duplicate message detected", nullifier = nullifier
        return

      # Different shares with same nullifier = spam (double signaling)
      result.isSpam = true
      result.conflictingEntry = some(entry)
      warn "Spam detected: double signaling",
        nullifier = nullifier,
        existingShareX = entry.metadata.shareX,
        existingShareY = entry.metadata.shareY,
        newShareX = metadata.shareX,
        newShareY = metadata.shareY
      return

  # Not spam or duplicate, insert the entry
  let entry = NullifierEntry(metadata: metadata)

  if not nl.log[epoch].hasKey(nullifier):
    nl.log[epoch][nullifier] = @[]

  nl.log[epoch][nullifier].add(entry)
  debug "Nullifier entry added", nullifier = nullifier

# Handle incoming proof metadata from network coordination
proc handleNetworkMetadata*(
    nl: NullifierLog, broadcast: ProofMetadataBroadcast
): SpamDetectionResult =
  ## Process proof metadata received from the network coordination layer.
  ## This enables network-wide spam detection.
  let metadata = ProofMetadata(
    nullifier: broadcast.nullifier,
    shareX: broadcast.shareX,
    shareY: broadcast.shareY,
    externalNullifier: broadcast.externalNullifier,
    epoch: broadcast.epoch,
  )

  nl.checkAndInsert(metadata)
