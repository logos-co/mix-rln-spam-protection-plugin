# SPDX-License-Identifier: Apache-2.0 OR MIT

## Mix wire adapter for the shared RLN Module API. The backend owns credentials,
## membership, allocation and proof verification; this adapter owns coordination.

{.push raises: [].}

import std/[json, times, tables, sequtils, monotimes]
import chronos, results, metrics
import stew/endians2
from stew/byteutils import hexToSeqByte
import libp2p_mix/spam_protection
import ./[types, constants, codec, nullifier_log]

export spam_protection

declarePublicCounter mix_rln_metadata_publication_failures,
  "Metadata broadcasts that failed or were dropped", labels = ["reason"]
declarePublicHistogram mix_rln_module_proof_seconds,
  "Module proof call latency including transport and backend queueing",
  labels = ["operation", "outcome"],
  buckets = [0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1.0, 2.5, 5.0, 10.0, 30.0, 80.0]

type
  RlnModuleCall* = proc(
    methodName: string, args: JsonNode
  ): Future[Result[JsonNode, string]] {.async: (raises: [CancelledError]).}

  ModuleRlnConfig* = object
    registryId*: string
    rlnIdentifierHex*: string
    epochSeconds*: uint64
    maxEpochGap*: uint64
    metadataTopic*: string

  ModuleRlnProtection* = ref object of SpamProtection
    config*: ModuleRlnConfig
    call: RlnModuleCall
    publish: PublishCallback
    metadataLog: NullifierLog
    epochLoop: Future[void]
    running: bool
    pendingBroadcasts: seq[Future[void]]

proc decodeField[N: static int](
    obj: JsonNode, key: string
): Result[array[N, byte], string] =
  if obj.isNil or obj.kind != JObject or not obj.hasKey(key) or
      obj.getOrDefault(key).kind != JString:
    return err("Missing RLN field: " & key)
  try:
    let bytes = hexToSeqByte(obj.getOrDefault(key).getStr())
    if bytes.len != N:
      return err("Invalid RLN field size: " & key)
    var field: array[N, byte]
    for i in 0 ..< N:
      field[i] = bytes[i]
    return ok(field)
  except ValueError:
    return err("Invalid RLN field hex: " & key)

proc parseModuleReply*(reply: JsonNode): Result[JsonNode, string] =
  ## Both RLN method families, including the SDK's JSON-string envelope.
  var value = reply
  try:
    for i in 0 ..< 3:
      if value.isNil or value.kind != JString:
        break
      value = parseJson(value.getStr())
    if value.isNil or value.kind != JObject:
      return err("RLN response must be an object")
    if value.hasKey("success"):
      if value["success"].kind != JBool or not value["success"].getBool():
        return err("RLN request failed: " & $value.getOrDefault("error"))
      value = value.getOrDefault("value")
      if not value.isNil and value.kind == JString:
        value = parseJson(value.getStr())
    if value.isNil or value.kind != JObject:
      return err("RLN response value must be an object")
    if value.hasKey("error"):
      return err("RLN request failed: " & $value["error"])
    return ok(value)
  except JsonParsingError, ValueError, KeyError, IOError, OSError:
    return err("Malformed RLN response")

proc scopedCall*(
    sp: ModuleRlnProtection, methodName: string, tail: JsonNode = newJArray()
): Future[Result[JsonNode, string]] {.async: (raises: [CancelledError]).} =
  var args = %*[sp.config.registryId, sp.config.rlnIdentifierHex]
  for item in tail:
    args.add(item)
  let started = getMonoTime()
  var outcome = "cancelled"
  defer:
    if methodName in ["generate_proof", "validate_proof"]:
      mix_rln_module_proof_seconds.observe(
        float((getMonoTime() - started).inNanoseconds) / 1e9,
        labelValues = [methodName, outcome],
      )
  let reply = await sp.call(methodName, args)
  outcome = "error"
  if reply.isErr:
    return err(reply.error)
  let parsed = parseModuleReply(reply.get())
  if parsed.isOk:
    outcome = "success"
  return parsed

proc new*(
    T: type ModuleRlnProtection, config: ModuleRlnConfig, call: RlnModuleCall
): Result[T, string] =
  if config.registryId.len == 0 or call.isNil:
    return err("RLN module scope and transport are required")
  discard ?decodeField[32](%*{"id": config.rlnIdentifierHex}, "id")
  if config.epochSeconds == 0 or config.epochSeconds > uint64(high(int64)) or
      config.maxEpochGap >= uint64(high(int64)):
    return err("Invalid RLN epoch parameters")
  if config.metadataTopic.len == 0:
    return err("RLN coordination topic is required")
  return ok(
    T(
      config: config,
      call: call,
      proofSize: RateLimitProofByteSize,
      metadataLog: newNullifierLog(
        maxEpochAgeSecs = float(config.epochSeconds) * float(config.maxEpochGap + 1)
      ),
    )
  )

proc setPublishCallback*(sp: ModuleRlnProtection, publish: PublishCallback) =
  sp.publish = publish

proc epochNow(sp: ModuleRlnProtection): uint64 =
  uint64(times.getTime().toUnix()) div sp.config.epochSeconds

proc epochNotifications(sp: ModuleRlnProtection) {.async: (raises: [CancelledError]).} =
  var epoch = sp.epochNow()
  sp.notifyEpochChange(epoch)
  while sp.running:
    await sleepAsync(chronos.milliseconds(100))
    let current = sp.epochNow()
    if current != epoch:
      epoch = current
      sp.notifyEpochChange(epoch)

proc start*(
    sp: ModuleRlnProtection
): Future[Result[void, string]] {.async: (raises: [CancelledError]).} =
  if sp.running:
    return ok()
  let params = (await sp.scopedCall("get_registry_parameters")).valueOr:
    return err(error)
  if params.getOrDefault("epoch_size_sec").getBiggestInt(0) !=
      int64(sp.config.epochSeconds):
    return err("RLN module epoch does not match the Mix profile")
  let gap = params.getOrDefault("max_epoch_gap")
  if gap.isNil or gap.kind != JInt or
      gap.getBiggestInt(-1) != int64(sp.config.maxEpochGap):
    return err("RLN module max_epoch_gap is missing or does not match the Mix profile")
  if sp.publish.isNil:
    return err("RLN coordination publisher is required")
  sp.running = true
  sp.metadataLog.start()
  sp.epochLoop = sp.epochNotifications()
  return ok()

proc stop*(sp: ModuleRlnProtection) {.async: (raises: []).} =
  sp.running = false
  if not sp.epochLoop.isNil:
    await sp.epochLoop.cancelAndWait()
  for broadcast in sp.pendingBroadcasts:
    await broadcast.cancelAndWait()
  sp.pendingBroadcasts.setLen(0)
  await sp.metadataLog.stop()

method generateProofAsync*(
    sp: ModuleRlnProtection, bindingData: seq[byte]
): Future[Result[ProofResult, string]] {.async: (raises: [CancelledError]).} =
  if not sp.running:
    return err("RLN module adapter is not started")
  let timestamp = uint64(times.getTime().toUnix())
  let response = (
    await sp.scopedCall("generate_proof", %*[bindingData.toHex(), $timestamp])
  ).valueOr:
    return err(error)
  let proof = RateLimitProof(
    proof: ?decodeField[128](response, "proof"),
    merkleRoot: ?decodeField[32](response, "root"),
    epoch: ?decodeField[32](response, "epoch"),
    shareX: ?decodeField[32](response, "share_x"),
    shareY: ?decodeField[32](response, "share_y"),
    nullifier: ?decodeField[32](response, "nullifier"),
  )
  if uint64.fromBytesLE(proof.epoch.toOpenArray(0, 7)) !=
      timestamp div sp.config.epochSeconds:
    return err("RLN backend returned a proof for a different epoch")
  let encoded = proof.toBytes()
  discard RateLimitProof.decode(encoded).valueOr:
    return err("RLN backend returned a malformed proof: " & $error)
  # Allocations are durable in the backend. Discarding cover never reuses one.
  return ok(ProofResult(proof: encoded, token: @(proof.epoch)))

method precomputeCoverProofs*(sp: ModuleRlnProtection): bool {.gcsafe, raises: [].} =
  false

method isProofTokenValid*(
    sp: ModuleRlnProtection, token: seq[byte]
): bool {.gcsafe, raises: [].} =
  token.len == 0 or
    (token.len == 32 and uint64.fromBytesLE(token.toOpenArray(0, 7)) == sp.epochNow())

proc broadcastMetadata(
    sp: ModuleRlnProtection, data: seq[byte]
) {.async: (raises: []).} =
  try:
    if (await sp.publish(sp.config.metadataTopic, data)).isErr:
      mix_rln_metadata_publication_failures.inc(labelValues = ["publish"])
  except CancelledError:
    mix_rln_metadata_publication_failures.inc(labelValues = ["cancelled"])
  except CatchableError:
    mix_rln_metadata_publication_failures.inc(labelValues = ["publish"])

method verifyProofAsync*(
    sp: ModuleRlnProtection, encodedProofData, bindingData: seq[byte]
): Future[Result[bool, string]] {.async: (raises: [CancelledError]).} =
  if not sp.running:
    return err("RLN module adapter is not started")
  let proof = RateLimitProof.decode(encodedProofData).valueOr:
    return ok(false)
  let epoch = uint64.fromBytesLE(proof.epoch.toOpenArray(0, 7))
  if epoch > high(uint64) div sp.config.epochSeconds:
    return ok(false)
  let wireProof = %*{
    "proof": proof.proof.toHex(),
    "root": proof.merkleRoot.toHex(),
    "epoch": proof.epoch.toHex(),
    "share_x": proof.shareX.toHex(),
    "share_y": proof.shareY.toHex(),
    "nullifier": proof.nullifier.toHex(),
  }
  let response = (
    await sp.scopedCall(
      "validate_proof",
      %*[bindingData.toHex(), $(epoch * sp.config.epochSeconds), $wireProof],
    )
  ).valueOr:
    return err(error)
  if not sp.running:
    return err("RLN module adapter stopped during verification")
  if response.getOrDefault("verdict").getStr() != "valid":
    return ok(false)
  let ext = ?decodeField[32](response, "external_nullifier")
  try:
    let seen = sp.metadataLog.checkAndInsert(
      ProofMetadata(
        nullifier: proof.nullifier,
        shareX: proof.shareX,
        shareY: proof.shareY,
        externalNullifier: ext,
      )
    )
    if seen.isSpam or seen.isDuplicate:
      return ok(false)
  except KeyError:
    return err("RLN coordination cache failure")
  let frame = ProofMetadataBroadcast(
    nullifier: proof.nullifier,
    shareX: proof.shareX,
    shareY: proof.shareY,
    externalNullifier: ext,
    epoch: proof.epoch,
  )
  sp.pendingBroadcasts.keepItIf(not it.finished)
  if sp.pendingBroadcasts.len >= 64:
    mix_rln_metadata_publication_failures.inc(labelValues = ["capacity"])
  else:
    sp.pendingBroadcasts.add(sp.broadcastMetadata(frame.toBytes()))
  return ok(true)

proc handleProofMetadata*(
    sp: ModuleRlnProtection, data: seq[byte]
): Result[void, string] =
  let frame = ProofMetadataBroadcast.decode(data).valueOr:
    return err("Invalid RLN metadata: " & $error)
  let epoch = uint64.fromBytesLE(frame.epoch.toOpenArray(0, 7))
  let current = sp.epochNow()
  let gap =
    if current > epoch:
      current - epoch
    else:
      epoch - current
  if gap > sp.config.maxEpochGap:
    return err("RLN metadata epoch out of range")
  try:
    discard sp.metadataLog.handleNetworkMetadata(frame)
    return ok()
  except KeyError:
    return err("RLN coordination cache failure")
