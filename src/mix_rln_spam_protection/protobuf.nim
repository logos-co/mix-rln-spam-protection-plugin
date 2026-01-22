# Mix RLN Spam Protection Plugin
# Copyright (c) 2025 vacp2p
# Licensed under either of Apache License 2.0 or MIT license.

## Extensions for libp2p's protobuf library implementation.
## Based on logos-messaging-nim patterns.

{.push raises: [].}

import std/options
import libp2p/protobuf/minprotobuf
import libp2p/varint

export minprotobuf, varint

type
  ProtobufErrorKind* {.pure.} = enum
    DecodeFailure
    MissingRequiredField
    InvalidLengthField

  ProtobufError* = object
    case kind*: ProtobufErrorKind
    of DecodeFailure:
      error*: minprotobuf.ProtoError
    of MissingRequiredField, InvalidLengthField:
      field*: string

  ProtobufResult*[T] = Result[T, ProtobufError]

converter toProtobufError*(err: minprotobuf.ProtoError): ProtobufError =
  case err
  of minprotobuf.ProtoError.RequiredFieldMissing:
    ProtobufError(kind: ProtobufErrorKind.MissingRequiredField, field: "unknown")
  else:
    ProtobufError(kind: ProtobufErrorKind.DecodeFailure, error: err)

proc missingRequiredField*(T: type ProtobufError, field: string): T =
  ProtobufError(kind: ProtobufErrorKind.MissingRequiredField, field: field)

proc invalidLengthField*(T: type ProtobufError, field: string): T =
  ProtobufError(kind: ProtobufErrorKind.InvalidLengthField, field: field)

proc write3*(proto: var ProtoBuffer, field: int, value: auto) =
  when value is Option:
    if value.isSome():
      proto.write(field, value.get())
  else:
    proto.write(field, value)

proc finish3*(proto: var ProtoBuffer) =
  if proto.buffer.len > 0:
    proto.finish()
  else:
    proto.offset = 0

proc `$`*(err: ProtobufError): string =
  case err.kind
  of DecodeFailure:
    return $err.error
  of MissingRequiredField:
    return "MissingRequiredField " & err.field
  of InvalidLengthField:
    return "InvalidLengthField " & err.field
