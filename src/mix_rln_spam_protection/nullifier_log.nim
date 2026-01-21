# Mix RLN Spam Protection Plugin
# Copyright (c) 2025 vacp2p
# Licensed under either of Apache License 2.0 or MIT license.

## Nullifier log for tracking proof metadata and detecting spam (double signaling).
##
## The nullifier log maintains a cache of proof metadata per epoch to detect
## when a member sends more than their allowed messages within an epoch.

import std/[tables, options]
import std/times as stdtimes
import chronos
import results
import chronicles

import ./types
import ./constants

export types

logScope:
  topics = "mix-rln-nullifier-log"

type
  # Entry in the nullifier log
  NullifierEntry* = object
    metadata*: ProofMetadata
    timestamp*: stdtimes.Time

  # Per-epoch nullifier tracking
  EpochLog* = Table[Nullifier, seq[NullifierEntry]]

  # Spam detection result
  SpamDetectionResult* = object
    isSpam*: bool
    isDuplicate*: bool
    conflictingEntry*: Option[NullifierEntry]

  NullifierLog* = ref object
    ## Log tracking nullifiers per epoch for spam detection.
    log: Table[ExternalNullifier, EpochLog]
    cleanupInterval: chronos.Duration
    maxEpochAgeSecs: int  # Store as seconds for easy comparison with times.Duration
    cleanupTask: Future[void]
    running: bool

proc newNullifierLog*(
  cleanupIntervalSecs: float = NullifierLogCleanupIntervalSeconds.float,
  maxEpochAgeSecs: float = (MaxEpochGap.float * EpochDurationSeconds + EpochDurationSeconds)
): NullifierLog =
  ## Create a new nullifier log.
  NullifierLog(
    log: initTable[ExternalNullifier, EpochLog](),
    cleanupInterval: chronos.seconds(int(cleanupIntervalSecs)),
    maxEpochAgeSecs: int(maxEpochAgeSecs),
    cleanupTask: nil,
    running: false
  )

proc cleanup(nl: NullifierLog) =
  ## Remove expired entries from the log.
  let now = stdtimes.getTime()
  var expiredExternalNullifiers: seq[ExternalNullifier] = @[]

  for extNullifier, epochLog in nl.log:
    var expiredNullifiers: seq[Nullifier] = @[]

    for nullifier, entries in epochLog:
      # Check if all entries for this nullifier are expired
      var allExpired = true
      for entry in entries:
        let ageSecs = (now - entry.timestamp).inSeconds
        if ageSecs < nl.maxEpochAgeSecs:
          allExpired = false
          break

      if allExpired:
        expiredNullifiers.add(nullifier)

    # Remove expired nullifiers from this epoch
    for nullifier in expiredNullifiers:
      nl.log[extNullifier].del(nullifier)

    # Check if the entire epoch log is empty
    if nl.log[extNullifier].len == 0:
      expiredExternalNullifiers.add(extNullifier)

  # Remove empty epoch logs
  for extNullifier in expiredExternalNullifiers:
    nl.log.del(extNullifier)

  if expiredExternalNullifiers.len > 0:
    debug "Nullifier log cleanup",
      removedExternalNullifiers = expiredExternalNullifiers.len,
      remainingExternalNullifiers = nl.log.len

proc cleanupLoop(nl: NullifierLog) {.async.} =
  ## Background task for periodic cleanup.
  while nl.running:
    await sleepAsync(nl.cleanupInterval)
    if nl.running:
      nl.cleanup()

proc start*(nl: NullifierLog) =
  ## Start the nullifier log cleanup task.
  if nl.running:
    return

  nl.running = true
  nl.cleanupTask = nl.cleanupLoop()
  info "Nullifier log started"

proc stop*(nl: NullifierLog) {.async.} =
  ## Stop the nullifier log cleanup task.
  if not nl.running:
    return

  nl.running = false
  if nl.cleanupTask != nil:
    await nl.cleanupTask.cancelAndWait()
    nl.cleanupTask = nil

  info "Nullifier log stopped"

proc checkAndInsert*(
  nl: NullifierLog,
  metadata: ProofMetadata
): SpamDetectionResult =
  ## Check if a proof is spam or duplicate, and insert if valid.
  ##
  ## Returns:
  ##   - isSpam=true if same nullifier with different shares (double signaling)
  ##   - isDuplicate=true if exact same metadata seen before
  ##   - conflictingEntry contains the previous entry if spam detected

  result = SpamDetectionResult(
    isSpam: false,
    isDuplicate: false,
    conflictingEntry: none(NullifierEntry)
  )

  let extNullifier = metadata.externalNullifier
  let nullifier = metadata.nullifier

  # Ensure epoch log exists
  if not nl.log.hasKey(extNullifier):
    nl.log[extNullifier] = initTable[Nullifier, seq[NullifierEntry]]()

  # Check if we have entries for this nullifier
  if nl.log[extNullifier].hasKey(nullifier):
    let existingEntries = nl.log[extNullifier][nullifier]

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
  let entry = NullifierEntry(
    metadata: metadata,
    timestamp: stdtimes.getTime()
  )

  if not nl.log[extNullifier].hasKey(nullifier):
    nl.log[extNullifier][nullifier] = @[]

  nl.log[extNullifier][nullifier].add(entry)
  debug "Nullifier entry added", nullifier = nullifier

proc hasDuplicate*(nl: NullifierLog, metadata: ProofMetadata): bool =
  ## Check if exact duplicate exists without inserting.
  let extNullifier = metadata.externalNullifier
  let nullifier = metadata.nullifier

  if not nl.log.hasKey(extNullifier):
    return false

  if not nl.log[extNullifier].hasKey(nullifier):
    return false

  for entry in nl.log[extNullifier][nullifier]:
    if entry.metadata.shareX == metadata.shareX and
       entry.metadata.shareY == metadata.shareY:
      return true

  false

proc hasNullifier*(nl: NullifierLog, extNullifier: ExternalNullifier, nullifier: Nullifier): bool =
  ## Check if any entry exists for the given nullifier.
  if not nl.log.hasKey(extNullifier):
    return false
  nl.log[extNullifier].hasKey(nullifier)

proc getEntries*(
  nl: NullifierLog,
  extNullifier: ExternalNullifier,
  nullifier: Nullifier
): seq[NullifierEntry] =
  ## Get all entries for a nullifier.
  if not nl.log.hasKey(extNullifier):
    return @[]

  if not nl.log[extNullifier].hasKey(nullifier):
    return @[]

  nl.log[extNullifier][nullifier]

proc getEntryCount*(nl: NullifierLog): int =
  ## Get total number of entries across all epochs.
  result = 0
  for extNullifier, epochLog in nl.log:
    for nullifier, entries in epochLog:
      result += entries.len

proc clear*(nl: NullifierLog) =
  ## Clear all entries from the log.
  nl.log.clear()
  debug "Nullifier log cleared"

# Handle incoming proof metadata from network coordination
proc handleNetworkMetadata*(
  nl: NullifierLog,
  broadcast: ProofMetadataBroadcast
): SpamDetectionResult =
  ## Process proof metadata received from the network coordination layer.
  ## This enables network-wide spam detection.
  let metadata = ProofMetadata(
    nullifier: broadcast.nullifier,
    shareX: broadcast.shareX,
    shareY: broadcast.shareY,
    externalNullifier: broadcast.externalNullifier
  )

  nl.checkAndInsert(metadata)
