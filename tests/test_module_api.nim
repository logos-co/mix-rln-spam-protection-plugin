import std/[json, strutils, times]
import chronos, results, unittest2, metrics
import stew/endians2
import ../src/mix_rln_spam_protection/[module_api, module_transport, types, codec]

proc checkAdapter() {.async.} =
  let config = ModuleRlnConfig(
    registryId: "logos:local:" & "ab".repeat(32),
    rlnIdentifierHex: "cd".repeat(32),
    epochSeconds: 10,
    maxEpochGap: 3,
    metadataTopic: "/mix/1/metadata/proto",
  )
  var generated, verified, published: int
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
      let epochBytes = toBytesLE(uint64(times.getTime().toUnix()) div 10)
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
      check ProofMetadataBroadcast.decode(payload).isOk
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
  verdict = "invalid"
  check not (await sp.verifyProofAsync(proof.proof, @[1.byte, 2, 3])).tryGet()
  check published == 0
  verdict = "valid"
  check (await sp.verifyProofAsync(proof.proof, @[1.byte, 2, 3])).tryGet()
  check published == 1
  # Coordination metadata suppresses a duplicate even if a backend says valid.
  check not (await sp.verifyProofAsync(proof.proof, @[1.byte, 2, 3])).tryGet()
  check published == 1
  check not (await sp.verifyProofAsync(@[0.byte], @[1.byte, 2, 3])).tryGet()
  check verified == 3
  failure = true
  check (await sp.generateProofAsync(@[1.byte])).isErr
  check generated == 2

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

proc checkPublication() {.async.} =
  let config = ModuleRlnConfig(
    registryId: "registry",
    rlnIdentifierHex: "cd".repeat(32),
    epochSeconds: 10,
    maxEpochGap: 3,
    metadataTopic: "metadata",
  )
  var holdValidation = false
  let call = proc(
      methodName: string, args: JsonNode
  ): Future[Result[JsonNode, string]] {.async: (raises: [CancelledError]).} =
    if methodName == "get_registry_parameters":
      return ok(%*{"epoch_size_sec": 10, "max_epoch_gap": 3})
    if holdValidation:
      await sleepAsync(chronos.milliseconds(5))
    return ok(%*{"verdict": "valid", "external_nullifier": "05".repeat(32)})
  let sp = ModuleRlnProtection.new(config, call).tryGet()
  var calls, cancelled: int
  var mode = "blocked"
  sp.setPublishCallback(
    proc(topic: string, payload: seq[byte]): Future[Result[void, string]] {.async.} =
      inc calls
      case mode
      of "error":
        return err("publisher unavailable")
      of "exception":
        raise newException(IOError, "publisher exception")
      else:
        try:
          await sleepAsync(chronos.hours(1))
        except CancelledError as exc:
          inc cancelled
          raise exc
        return ok()
  )
  check (await sp.start()).isOk
  defer:
    await sp.stop()
  mix_rln_metadata_publication_failures.inc(0, labelValues = ["capacity"])
  let capacityBefore = mix_rln_metadata_publication_failures.value(["capacity"])
  for i in 0 ..< 65:
    var proof: RateLimitProof
    proof.nullifier[0] = byte(i)
    let verified = sp.verifyProofAsync(proof.toBytes(), @[])
    check verified.finished
    check (await verified).tryGet()
  check calls == 64
  when defined(metrics):
    check mix_rln_metadata_publication_failures.value(["capacity"]) == capacityBefore + 1
  await sp.stop()
  check cancelled == 64
  check (await sp.start()).isOk
  mix_rln_metadata_publication_failures.inc(0, labelValues = ["publish"])
  let failuresBefore = mix_rln_metadata_publication_failures.value(["publish"])
  for i, failureMode in ["error", "exception"]:
    mode = failureMode
    var proof: RateLimitProof
    proof.nullifier[0] = byte(65 + i)
    check (await sp.verifyProofAsync(proof.toBytes(), @[])).tryGet()
    check not (await sp.verifyProofAsync(proof.toBytes(), @[])).tryGet()
  check calls == 66
  when defined(metrics):
    check mix_rln_metadata_publication_failures.value(["publish"]) == failuresBefore + 2

  holdValidation = true
  var lateProof: RateLimitProof
  lateProof.nullifier[0] = 99
  let late = sp.verifyProofAsync(lateProof.toBytes(), @[])
  await sp.stop()
  check (await late).isErr
  check calls == 66

proc checkParameters() {.async.} =
  let config = ModuleRlnConfig(
    registryId: "registry",
    rlnIdentifierHex: "cd".repeat(32),
    epochSeconds: 10,
    maxEpochGap: 3,
    metadataTopic: "metadata",
  )
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
  var pending: seq[Future[Result[JsonNode, string]]]
  for i in 0 ..< 64:
    pending.add(
      requests.request(
        if i mod 2 == 0: "generate_proof" else: "validate_proof", newJArray()
      )
    )
  check (await requests.request("validate_proof", newJArray())).isErr
  when defined(metrics):
    check mix_rln_module_request_limit_rejections.value() == before + 1
  check requests.respond(1, "{}").isOk
  check (await pending[0]).isOk
  let next = requests.request("validate_proof", newJArray())
  check not next.finished
  requests.cancel()
  for i in 1 ..< pending.len:
    check (await pending[i]).isErr
  check (await next).isErr

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
  test "publication is bounded, best effort, and cancelled on shutdown":
    waitFor checkPublication()
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
