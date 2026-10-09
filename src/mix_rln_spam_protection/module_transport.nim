# SPDX-License-Identifier: Apache-2.0 OR MIT

## Correlates asynchronous host replies on the owning Nim event loop.

{.push raises: [].}
import std/[json, tables]
import chronos, results, metrics

declarePublicCounter mix_rln_module_request_limit_rejections,
  "Module requests rejected because a pending request limit was reached"

const MaxPendingRequestsPerKind = 32

type
  RlnRequestEmitter* =
    proc(id: int64, methodName, argsJson: string) {.gcsafe, raises: [].}
  RlnRequests* = ref object
    pending: Table[int64, Future[Result[string, string]]]
    pendingValidations: int
    pendingLocalRequests: int
    nextId: int64
    emit*: RlnRequestEmitter

proc new*(T: type RlnRequests, emit: RlnRequestEmitter): T =
  T(emit: emit)

proc request*(
    r: RlnRequests, methodName: string, args: JsonNode
): Future[Result[JsonNode, string]] {.async: (raises: [CancelledError]).} =
  let isValidation = methodName == "validate_proof"
  let pendingCount = if isValidation: r.pendingValidations else: r.pendingLocalRequests
  if pendingCount >= MaxPendingRequestsPerKind:
    mix_rln_module_request_limit_rejections.inc()
    return err("RLN request limit reached")
  if r.emit.isNil:
    return err("RLN module transport is unavailable")
  inc r.nextId
  let id = r.nextId
  let response = newFuture[Result[string, string]]("RLN module response")
  r.pending[id] = response
  if isValidation:
    inc r.pendingValidations
  else:
    inc r.pendingLocalRequests
  defer:
    r.pending.del(id)
    if isValidation:
      dec r.pendingValidations
    else:
      dec r.pendingLocalRequests
  r.emit(id, methodName, $args)
  let timeout =
    # Registry-backed calls and proof generation may use a 90-second backend budget.
    if methodName in [
      "generate_proof", "get_membership_state", "get_registry_parameters",
      "register_membership",
    ]: 100.seconds else: 10.seconds
  try:
    let raw = (await response.wait(timeout)).valueOr:
      return err(error)
    if raw.len > 65536:
      return err("RLN response exceeds size limit")
    return ok(parseJson(raw))
  except CancelledError as exc:
    raise exc
  except CatchableError as exc:
    return err("RLN module response failed: " & exc.msg)

proc respond*(r: RlnRequests, id: int64, reply: string): Result[void, string] =
  r.pending.withValue(id, response):
    if response[].finished:
      return err("RLN request already completed")
    response[].complete(Result[string, string].ok(reply))
    return ok()
  return err("Unknown or expired RLN request")

proc cancel*(r: RlnRequests) =
  for response in r.pending.values:
    if not response.finished:
      response.complete(Result[string, string].err("RLN context stopped"))
