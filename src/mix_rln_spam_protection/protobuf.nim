# Mix RLN Spam Protection Plugin
# Copyright (c) 2025 vacp2p
# Licensed under either of Apache License 2.0 or MIT license.

## Protobuf support for the codec: re-exports nim-protobuf-serialization and
## defines the codec's error type.

{.push raises: [].}

import protobuf_serialization except ProtobufError
import protobuf_serialization/pkg/results as pb_results
export protobuf_serialization except ProtobufError
export pb_results

type
  ProtobufErrorKind* {.pure.} = enum
    DecodeFailure
    MissingRequiredField
    InvalidLengthField

  ProtobufError* = object
    case kind*: ProtobufErrorKind
    of DecodeFailure:
      error*: string
    of MissingRequiredField, InvalidLengthField:
      field*: string

  ProtobufResult*[T] = Result[T, ProtobufError]

proc decodeFailure*(T: type ProtobufError, error: string): T =
  ProtobufError(kind: ProtobufErrorKind.DecodeFailure, error: error)

proc missingRequiredField*(T: type ProtobufError, field: string): T =
  ProtobufError(kind: ProtobufErrorKind.MissingRequiredField, field: field)

proc invalidLengthField*(T: type ProtobufError, field: string): T =
  ProtobufError(kind: ProtobufErrorKind.InvalidLengthField, field: field)

proc `$`*(err: ProtobufError): string =
  case err.kind
  of DecodeFailure:
    return $err.error
  of MissingRequiredField:
    return "MissingRequiredField " & err.field
  of InvalidLengthField:
    return "InvalidLengthField " & err.field