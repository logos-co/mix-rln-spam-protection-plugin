import std/[json, strutils]
import chronos, results, unittest2, metrics
import stew/endians2
import
  ../src/mix_rln_spam_protection/[module_api, module_transport, types, codec, protobuf]

var testNow: int64

proc testClock(): int64 {.gcsafe, raises: [].} =
  testNow

proc checkAdapter() {.async.} =
  let config = ModuleRlnConfig(
    registryId: "logos:local:" & "ab".repeat(32),
    rlnIdentifierHex: "cd".repeat(32),
    epochSeconds: 10,
    maxEpochGap: 3,
    metadataTopic: "/mix/1/metadata/proto",
  )
  var generated, verified, published: int
  var generatedTimestamp: uint64
  var verdict = "valid"
  var failure = false
  var returnedEpoch: Epoch
  let call = proc(
      methodName: string, args: JsonNode
  ): Future[Result[JsonNode, string]] {.async: (raises: [CancelledError]).} =
    check args[0].getStr() == config.registryId
    check args[1].getStr() == config.rlnIdentifierHex
    await sleepAsync(chronos.milliseconds(1))
    case methodName
    of "get_registry_parameters":
      return ok(%*{"epoch_size_sec": 10, "max_epoch_gap": 3})
    of "generate_proof":
      inc generated
      if failure:
        return ok(%*{"success": false, "error": "budget_exhausted"})
      try:
        generatedTimestamp = uint64(parseUInt(args[3].getStr()))
      except ValueError:
        check false
        return err("Invalid timestamp")
      let epochBytes = toBytesLE(generatedTimestamp div config.epochSeconds)
      for i in 0 ..< 8:
        returnedEpoch[i] = epochBytes[i]
      return ok(
        %*{
          "success": true,
          "value": {
            "proof": "00".repeat(128),
            "root": "01".repeat(32),
            "epoch": returnedEpoch.toHex(),
            "share_x": "02".repeat(32),
            "share_y": "03".repeat(32),
            "nullifier": "04".repeat(32),
          },
        }
      )
    of "validate_proof":
      inc verified
      check args[2].getStr() == "010203"
      check args[4].getStr().contains("share_x")
      return ok(
        %*{
          "success": true,
          "value": {"verdict": verdict, "external_nullifier": "05".repeat(32)},
        }
      )
    else:
      return err("Unexpected method: " & methodName)
  let sp = ModuleRlnProtection.new(config, call).tryGet()
  check (await sp.generateProofAsync(@[1.byte, 2, 3])).isErr
  sp.setPublishCallback(
    proc(topic: string, payload: seq[byte]): Future[Result[void, string]] {.async.} =
      check topic == config.metadataTopic
      let decoded = decodeMetadata(payload).tryGet()
      check decoded.malformed == 0
      check decoded.entries.len == 1
      inc published
      return ok()
  )
  check (await sp.start()).isOk
  defer:
    await sp.stop()
  check not sp.precomputeCoverProofs()
  check sp.isProofTokenValid(@[])
  let pending = sp.generateProofAsync(@[1.byte, 2, 3])
  check not pending.finished
  let proof = (await pending).tryGet()
  check proof.proof.len == 301
  check sp.isProofTokenValid(proof.token)
  let base: SpamProtection = sp
  let selectedEpoch = 42'u64
  let explicitProof =
    (await base.generateProofAsync(@[1.byte, 2, 3], selectedEpoch)).tryGet()
  check uint64.fromBytesLE(explicitProof.token.toOpenArray(0, 7)) == selectedEpoch
  check generatedTimestamp == selectedEpoch * config.epochSeconds
  check (await base.generateProofAsync(@[], high(uint64))).isErr
  check generated == 2

  verdict = "invalid"
  check not (await sp.verifyProofAsync(proof.proof, @[1.byte, 2, 3])).tryGet()
  check published == 0

  let decoded = RateLimitProof.decode(proof.proof).tryGet()
  var frame = ProofMetadataBroadcast(
    nullifier: decoded.nullifier,
    shareX: decoded.shareX,
    shareY: decoded.shareY,
    epoch: decoded.epoch,
  )
  inc frame.shareX[0]
  check sp.handleProofMetadata(MessagingMetadata(entries: @[frame]).toBytes()).isOk
  verdict = "valid"
  check not (await sp.verifyProofAsync(proof.proof, @[1.byte, 2, 3])).tryGet()
  check published == 0

  var accepted = decoded
  inc accepted.nullifier[0]
  check (await sp.verifyProofAsync(accepted.toBytes(), @[1.byte, 2, 3])).tryGet()
  check published == 0
  check not (await sp.verifyProofAsync(accepted.toBytes(), @[1.byte, 2, 3])).tryGet()
  check not (await sp.verifyProofAsync(@[0.byte], @[1.byte, 2, 3])).tryGet()
  check verified == 4
  failure = true
  check (await sp.generateProofAsync(@[1.byte])).isErr
  check generated == 3

proc checkTransport() {.async.} =
  var id: int64
  let requests = RlnRequests.new(
    proc(requestId: int64, methodName, args: string) {.gcsafe, raises: [].} =
      id = requestId
  )
  let first = requests.request("validate_proof", newJArray())
  check not first.finished
  check requests.respond(id, "{\"verdict\":\"valid\"}").isOk
  check requests.respond(id, "{}").isErr
  check (await first).isOk
  check requests.respond(id, "{}").isErr
  let cancelled = requests.request("generate_proof", newJArray())
  await cancelled.cancelAndWait()
  check requests.respond(id, "{}").isErr
  let stopped = requests.request("generate_proof", newJArray())
  requests.cancel()
  check (await stopped).isErr

proc epochField(n: uint64): Epoch =
  let raw = toBytesLE(n)
  for i in 0 ..< raw.len:
    result[i] = raw[i]

proc moduleConfig(): ModuleRlnConfig =
  ModuleRlnConfig(
    registryId: "registry",
    rlnIdentifierHex: "cd".repeat(32),
    epochSeconds: 10,
    maxEpochGap: 3,
    metadataTopic: "metadata",
  )

type Hold = ref object
  on: bool

proc registryCall(
    hold: Hold
): proc(methodName: string, args: JsonNode): Future[Result[JsonNode, string]] {.
  async: (raises: [CancelledError])
.} =
  result = proc(
      methodName: string, args: JsonNode
  ): Future[Result[JsonNode, string]] {.async: (raises: [CancelledError]).} =
    if methodName == "get_registry_parameters":
      return ok(%*{"epoch_size_sec": 10, "max_epoch_gap": 3})
    if hold.on:
      await sleepAsync(chronos.milliseconds(5))
    return ok(%*{"verdict": "valid", "external_nullifier": "05".repeat(32)})

template waitUntil(cond: untyped) =
  for _ in 0 ..< 30:
    if cond:
      break
    await sleepAsync(chronos.milliseconds(50))
  check cond

proc checkImmediatePublish() {.async.} =
  check not moduleConfig().disableMetadataBatch
  testNow = 1_700_000_000
  let epoch = uint64(testNow) div 10
  var config = moduleConfig()
  config.disableMetadataBatch = true
  let sp = ModuleRlnProtection.new(config, registryCall(Hold(on: false))).tryGet()
  sp.setNowUnix(testClock)
  var payloads: seq[seq[byte]]
  sp.setPublishCallback(
    proc(topic: string, payload: seq[byte]): Future[Result[void, string]] {.async.} =
      payloads.add(payload)
      return ok()
  )
  check (await sp.start()).isOk
  defer:
    await sp.stop()
  for i in 0 ..< 2:
    var proof: RateLimitProof
    proof.nullifier[0] = byte(i + 1)
    proof.epoch = epochField(epoch)
    check (await sp.verifyProofAsync(proof.toBytes(), @[])).tryGet()
    waitUntil(payloads.len == i + 1)
    check ProofMetadataBroadcast.decode(payloads[i]).isErr
    let decoded = decodeMetadata(payloads[i]).tryGet()
    check decoded.malformed == 0
    check decoded.entries.len == 1
    check decoded.entries[0].nullifier[0] == byte(i + 1)
  testNow += 10
  await sleepAsync(chronos.milliseconds(250))
  check payloads.len == 2

proc checkEpochBatch() {.async.} =
  testNow = 1_700_000_000
  let epoch = uint64(testNow) div 10
  let sp =
    ModuleRlnProtection.new(moduleConfig(), registryCall(Hold(on: false))).tryGet()
  sp.setNowUnix(testClock)
  var payloads: seq[seq[byte]]
  sp.setPublishCallback(
    proc(topic: string, payload: seq[byte]): Future[Result[void, string]] {.async.} =
      payloads.add(payload)
      return ok()
  )
  check (await sp.start()).isOk
  defer:
    await sp.stop()
  for i in 0 ..< 3:
    var proof: RateLimitProof
    proof.nullifier[0] = byte(i + 1)
    proof.epoch = epochField(epoch)
    check (await sp.verifyProofAsync(proof.toBytes(), @[])).tryGet()
  check payloads.len == 0

  mix_rln_metadata_batch_entries.observe(0)
  let batchesBefore = mix_rln_metadata_batch_entries.valueByName(
    "mix_rln_metadata_batch_entries_count", []
  )
  let entriesBefore =
    mix_rln_metadata_batch_entries.valueByName("mix_rln_metadata_batch_entries_sum", [])
  testNow += 10
  waitUntil(payloads.len == 1)
  check payloads.len == 1
  let decoded = decodeMetadata(payloads[0]).tryGet()
  check decoded.malformed == 0
  check decoded.entries.len == 3
  check decoded.entries[0].nullifier[0] == 1
  check decoded.entries[2].nullifier[0] == 3
  when defined(metrics):
    check mix_rln_metadata_batch_entries.valueByName(
      "mix_rln_metadata_batch_entries_count", []
    ) == batchesBefore + 1
    check mix_rln_metadata_batch_entries.valueByName(
      "mix_rln_metadata_batch_entries_sum", []
    ) == entriesBefore + 3

  # The next epoch has nothing to send.
  testNow += 10
  await sleepAsync(chronos.milliseconds(250))
  check payloads.len == 1

proc checkPublishFailure() {.async.} =
  testNow = 1_700_000_000
  let epoch = uint64(testNow) div 10
  let hold = Hold(on: false)
  let sp = ModuleRlnProtection.new(moduleConfig(), registryCall(hold)).tryGet()
  sp.setNowUnix(testClock)
  var calls = 0
  var mode = "error"
  sp.setPublishCallback(
    proc(topic: string, payload: seq[byte]): Future[Result[void, string]] {.async.} =
      inc calls
      await sleepAsync(chronos.milliseconds(1))
      if mode == "error":
        return err("publisher unavailable")
      raise newException(IOError, "publisher exception")
  )
  check (await sp.start()).isOk
  defer:
    await sp.stop()
  mix_rln_metadata_publication_failures.inc(0, labelValues = ["publish"])
  let failuresBefore = mix_rln_metadata_publication_failures.value(["publish"])
  for i, failureMode in ["error", "exception"]:
    mode = failureMode
    var proof: RateLimitProof
    proof.nullifier[0] = byte(i + 1)
    proof.epoch = epochField(epoch + uint64(i))
    check (await sp.verifyProofAsync(proof.toBytes(), @[])).tryGet()
    testNow += 10
    waitUntil(calls == i + 1)
    await sleepAsync(chronos.milliseconds(50))
  when defined(metrics):
    check mix_rln_metadata_publication_failures.value(["publish"]) == failuresBefore + 2

proc checkStopFlushes() {.async.} =
  testNow = 1_700_000_000
  let epoch = uint64(testNow) div 10
  let hold = Hold(on: false)
  let sp = ModuleRlnProtection.new(moduleConfig(), registryCall(hold)).tryGet()
  sp.setNowUnix(testClock)
  var payloads: seq[seq[byte]]
  sp.setPublishCallback(
    proc(topic: string, payload: seq[byte]): Future[Result[void, string]] {.async.} =
      payloads.add(payload)
      return ok()
  )
  check (await sp.start()).isOk
  for i in 0 ..< 2:
    var proof: RateLimitProof
    proof.nullifier[0] = byte(i + 1)
    proof.epoch = epochField(epoch)
    check (await sp.verifyProofAsync(proof.toBytes(), @[])).tryGet()
  check payloads.len == 0
  await sp.stop()
  check payloads.len == 1
  check decodeMetadata(payloads[0]).tryGet().entries.len == 2

  check (await sp.start()).isOk
  defer:
    await sp.stop()
  hold.on = true
  var lateProof: RateLimitProof
  lateProof.nullifier[0] = 99
  lateProof.epoch = epochField(epoch)
  let late = sp.verifyProofAsync(lateProof.toBytes(), @[])
  await sp.stop()
  check (await late).isErr
  check payloads.len == 1

proc checkBatchSpam() {.async.} =
  testNow = 1_700_000_000
  let epoch = uint64(testNow) div 10
  let call = registryCall(Hold(on: false))
  let config = moduleConfig()
  let a = ModuleRlnProtection.new(config, call).tryGet()
  let b = ModuleRlnProtection.new(config, call).tryGet()
  a.setNowUnix(testClock)
  b.setNowUnix(testClock)
  var aPayloads, bPayloads: seq[seq[byte]]
  a.setPublishCallback(
    proc(topic: string, payload: seq[byte]): Future[Result[void, string]] {.async.} =
      aPayloads.add(payload)
      return ok()
  )
  b.setPublishCallback(
    proc(topic: string, payload: seq[byte]): Future[Result[void, string]] {.async.} =
      bPayloads.add(payload)
      return ok()
  )
  check (await a.start()).isOk
  check (await b.start()).isOk
  defer:
    await a.stop()
    await b.stop()

  var proofA, proofB: RateLimitProof
  proofA.epoch = epochField(epoch)
  proofB.epoch = proofA.epoch
  proofA.nullifier[0] = 7
  proofB.nullifier[0] = 7
  proofA.shareX[0] = 1
  proofB.shareX[0] = 2
  check (await a.verifyProofAsync(proofA.toBytes(), @[])).tryGet()
  check (await b.verifyProofAsync(proofB.toBytes(), @[])).tryGet()
  check aPayloads.len == 0
  check bPayloads.len == 0

  testNow += 10
  waitUntil(aPayloads.len == 1)
  waitUntil(bPayloads.len == 1)
  check aPayloads.len == 1
  check bPayloads.len == 1
  check decodeMetadata(aPayloads[0]).tryGet().entries[0].shareX[0] == 1
  check decodeMetadata(bPayloads[0]).tryGet().entries[0].shareX[0] == 2

  let conflictsBefore = mix_rln_metadata_conflicts_total.value()
  check b.handleProofMetadata(aPayloads[0]).isOk
  check a.handleProofMetadata(bPayloads[0]).isOk
  when defined(metrics):
    check mix_rln_metadata_conflicts_total.value() == conflictsBefore + 2

proc checkBatchSkips() {.async.} =
  testNow = 1_700_000_000
  let epoch = uint64(testNow) div 10
  let sp =
    ModuleRlnProtection.new(moduleConfig(), registryCall(Hold(on: false))).tryGet()
  sp.setNowUnix(testClock)
  sp.setPublishCallback(
    proc(topic: string, payload: seq[byte]): Future[Result[void, string]] {.async.} =
      return ok()
  )
  check (await sp.start()).isOk
  defer:
    await sp.stop()

  var fresh, stale: ProofMetadataBroadcast
  fresh.nullifier[0] = 11
  fresh.epoch = epochField(epoch)
  fresh.shareX[0] = 1
  stale.nullifier[0] = 12
  stale.epoch = epochField(epoch + 100)
  stale.shareX[0] = 1
  var buf = initProtoBuffer()
  buf.write3(1, fresh.toBytes())
  buf.write3(1, @[byte 1, 2, 3])
  buf.write3(1, stale.toBytes())
  buf.finish3()

  mix_rln_metadata_entries_skipped.inc(0, labelValues = ["malformed"])
  mix_rln_metadata_entries_skipped.inc(0, labelValues = ["epoch_gap"])
  let malformedBefore = mix_rln_metadata_entries_skipped.value(["malformed"])
  let gapBefore = mix_rln_metadata_entries_skipped.value(["epoch_gap"])
  check sp.handleProofMetadata(buf.buffer).isOk
  when defined(metrics):
    check mix_rln_metadata_entries_skipped.value(["malformed"]) == malformedBefore + 1
    check mix_rln_metadata_entries_skipped.value(["epoch_gap"]) == gapBefore + 1

  var conflict, unseen: RateLimitProof
  conflict.nullifier[0] = 11
  conflict.epoch = fresh.epoch
  conflict.shareX[0] = 9
  unseen.nullifier[0] = 12
  unseen.epoch = stale.epoch
  unseen.shareX[0] = 9
  check not (await sp.verifyProofAsync(conflict.toBytes(), @[])).tryGet()
  check (await sp.verifyProofAsync(unseen.toBytes(), @[])).tryGet()

proc checkParameters() {.async.} =
  let config = ModuleRlnConfig(
    registryId: "registry",
    rlnIdentifierHex: "cd".repeat(32),
    epochSeconds: 10,
    maxEpochGap: 3,
    metadataTopic: "metadata",
  )
  var calls = 0
  let countedCall = proc(
      methodName: string, args: JsonNode
  ): Future[Result[JsonNode, string]] {.async: (raises: [CancelledError]).} =
    inc calls
    return ok(%*{"epoch_size_sec": 10, "max_epoch_gap": 3})
  let noPublisher = ModuleRlnProtection.new(config, countedCall).tryGet()
  check (await noPublisher.start()).isErr
  check calls == 0

  for params in [
    %*{"epoch_size_sec": 11, "max_epoch_gap": 3},
    %*{"epoch_size_sec": 10},
    %*{"epoch_size_sec": 10, "max_epoch_gap": 2},
    %*{"epoch_size_sec": 10, "max_epoch_gap": "3"},
    %*{"epoch_size_sec": 10, "max_epoch_gap": -1},
  ]:
    let reply = params
    let call = proc(
        methodName: string, args: JsonNode
    ): Future[Result[JsonNode, string]] {.async: (raises: [CancelledError]).} =
      return ok(reply)
    let sp = ModuleRlnProtection.new(config, call).tryGet()
    sp.setPublishCallback(
      proc(topic: string, payload: seq[byte]): Future[Result[void, string]] {.async.} =
        return ok()
    )
    check (await sp.start()).isErr
    check (await sp.generateProofAsync(@[])).isErr
    await sp.stop()

proc checkSaturation() {.async.} =
  let requests = RlnRequests.new(
    proc(id: int64, methodName, args: string) {.gcsafe, raises: [].} =
      discard
  )
  let before = mix_rln_module_request_limit_rejections.value()
  var validations, generations: seq[Future[Result[JsonNode, string]]]
  for i in 0 ..< 32:
    validations.add(requests.request("validate_proof", newJArray()))
  check (await requests.request("validate_proof", newJArray())).isErr
  for i in 0 ..< 32:
    generations.add(requests.request("generate_proof", newJArray()))
  check (await requests.request("generate_proof", newJArray())).isErr
  when defined(metrics):
    check mix_rln_module_request_limit_rejections.value() == before + 2
  check requests.respond(1, "{}").isOk
  check (await validations[0]).isOk
  let next = requests.request("validate_proof", newJArray())
  check not next.finished
  check requests.respond(33, "{}").isOk
  check (await generations[0]).isOk
  let nextGeneration = requests.request("generate_proof", newJArray())
  check not nextGeneration.finished
  requests.cancel()
  for i in 1 ..< validations.len:
    check (await validations[i]).isErr
  for i in 1 ..< generations.len:
    check (await generations[i]).isErr
  check (await next).isErr
  check (await nextGeneration).isErr

proc checkLatency() {.async.} =
  let config = ModuleRlnConfig(
    registryId: "registry",
    rlnIdentifierHex: "cd".repeat(32),
    epochSeconds: 10,
    maxEpochGap: 3,
    metadataTopic: "metadata",
  )
  var mode = "success"
  let call = proc(
      methodName: string, args: JsonNode
  ): Future[Result[JsonNode, string]] {.async: (raises: [CancelledError]).} =
    await sleepAsync(chronos.milliseconds(5))
    if mode == "error":
      return err("backend unavailable")
    if mode == "envelope":
      return ok(%*{"success": false, "error": "quota"})
    return ok(%*{"verdict": "valid"})
  let sp = ModuleRlnProtection.new(config, call).tryGet()
  for operation in ["generate_proof", "validate_proof"]:
    for outcome in ["success", "error", "cancelled"]:
      mode = outcome
      mix_rln_module_proof_seconds.observe(0, labelValues = [operation, outcome])
      let before = mix_rln_module_proof_seconds.valueByName(
        "mix_rln_module_proof_seconds_count", [operation, outcome]
      )
      let pending = sp.scopedCall(operation)
      if outcome == "cancelled":
        await pending.cancelAndWait()
      else:
        discard await pending
      when defined(metrics):
        check mix_rln_module_proof_seconds.valueByName(
          "mix_rln_module_proof_seconds_count", [operation, outcome]
        ) == before + 1
    mode = "envelope"
    check (await sp.scopedCall(operation)).isErr

suite "Shared RLN module adapter":
  test "metadata batch roundtrip rejects a bare entry":
    var entry: ProofMetadataBroadcast
    entry.nullifier[0] = 1
    entry.shareX[0] = 2
    entry.shareY[0] = 3
    entry.externalNullifier[0] = 4
    entry.epoch[0] = 5
    var second = entry
    second.nullifier[0] = 8
    let batch = MessagingMetadata(entries: @[entry, second])
    check ProofMetadataBroadcast.decode(batch.toBytes()).isErr
    let decoded = decodeMetadata(batch.toBytes()).tryGet()
    check decoded.malformed == 0
    check decoded.entries.len == 2
    check decoded.entries[0].nullifier == entry.nullifier
    check decoded.entries[1].shareX == second.shareX
    check decodeMetadata(entry.toBytes()).isErr
    let one = decodeMetadata(MessagingMetadata(entries: @[entry]).toBytes()).tryGet()
    check one.malformed == 0
    check one.entries.len == 1
    check one.entries[0].nullifier == entry.nullifier
    check decodeMetadata(@[1.byte, 2, 3]).isErr
    var broken = initProtoBuffer()
    broken.write3(1, @[1.byte])
    broken.write3(2, @[2.byte])
    broken.finish3()
    check decodeMetadata(broken.buffer).isErr

  test "one epoch of proofs publishes one batch after the epoch ends":
    waitFor checkEpochBatch()
  test "disableMetadataBatch publishes each proof immediately":
    waitFor checkImmediatePublish()
  test "a failed batch publish is counted and dropped":
    waitFor checkPublishFailure()
  test "stop flushes the open batch and does not publish a late verify":
    waitFor checkStopFlushes()
  test "both nodes flag a nullifier carried in the other node's batch":
    waitFor checkBatchSpam()
  test "a bad batch entry is skipped and the rest is applied":
    waitFor checkBatchSkips()
  test "startup rejects missing and mismatched epoch parameters":
    waitFor checkParameters()
  test "request saturation is counted and capacity is recovered":
    waitFor checkSaturation()
  test "proof call latency records successes, errors, and cancellation":
    waitFor checkLatency()
  test "asynchronous scoped proofs, quota failure and coordination":
    waitFor checkAdapter()
  test "transport rejects duplicate and late replies, and cancels pending work":
    waitFor checkTransport()
  test "reply envelopes fail closed":
    check parseModuleReply(nil).isErr
    check parseModuleReply(%*{"success": true}).isErr
    check parseModuleReply(%*{"success": false, "error": "not_ready"}).isErr
    check parseModuleReply(%*{"success": true, "value": false}).isErr
    check parseModuleReply(%"not json").isErr
    check parseModuleReply(%*{"error": {"class": "permanent"}}).isErr
    check parseModuleReply(%($(%*{"success": true, "value": {"verdict": "valid"}}))).isOk
