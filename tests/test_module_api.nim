import std/[json, strutils, times]
import chronos, results, unittest2
import stew/endians2
import ../src/mix_rln_spam_protection/[module_api, module_transport, types, codec]

proc checkAdapter() {.async.} =
  let config = ModuleRlnConfig(
    registryId: "logos:local:" & "ab".repeat(32),
    rlnIdentifierHex: "cd".repeat(32),
    epochSeconds: 10,
    maxEpochGap: 3,
    messageLimit: 100,
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
      return ok(%*{"epoch_size_sec": 10})
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

suite "Shared RLN module adapter":
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
