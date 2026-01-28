# Mix RLN Spam Protection Plugin
# Copyright (c) 2025 vacp2p
# Licensed under either of Apache License 2.0 or MIT license.

## Byte manipulation utilities for serialization/deserialization.
##
## This module provides consistent, readable helpers for:
## - Little-endian uint64 encoding/decoding
## - Safe memory copying with bounds checking
## - Hex preview formatting for logging

{.push raises: [].}

import results

export results

type
  BytesError* = object of CatchableError

# =============================================================================
# Little-Endian uint64 Encoding/Decoding
# =============================================================================
#
# These functions handle conversion between uint64 and byte arrays in
# little-endian format (least significant byte first).
#
# Example: uint64(0x0102030405060708) becomes [0x08, 0x07, 0x06, 0x05, 0x04, 0x03, 0x02, 0x01]

const Uint64ByteSize* = 8

proc toBytes*(value: uint64): array[8, byte] =
  ## Convert a uint64 to an 8-byte little-endian array.
  result[0] = byte(value and 0xFF)
  result[1] = byte((value shr 8) and 0xFF)
  result[2] = byte((value shr 16) and 0xFF)
  result[3] = byte((value shr 24) and 0xFF)
  result[4] = byte((value shr 32) and 0xFF)
  result[5] = byte((value shr 40) and 0xFF)
  result[6] = byte((value shr 48) and 0xFF)
  result[7] = byte((value shr 56) and 0xFF)

proc toBytesLE*(value: uint64): array[8, byte] {.inline.} =
  ## Alias for toBytes - explicit little-endian naming.
  toBytes(value)

proc writeUint64LE*(dest: var openArray[byte], offset: int, value: uint64) =
  ## Write a uint64 in little-endian format at the given offset.
  ## Raises IndexDefect if offset + 8 exceeds dest length.
  dest[offset + 0] = byte(value and 0xFF)
  dest[offset + 1] = byte((value shr 8) and 0xFF)
  dest[offset + 2] = byte((value shr 16) and 0xFF)
  dest[offset + 3] = byte((value shr 24) and 0xFF)
  dest[offset + 4] = byte((value shr 32) and 0xFF)
  dest[offset + 5] = byte((value shr 40) and 0xFF)
  dest[offset + 6] = byte((value shr 48) and 0xFF)
  dest[offset + 7] = byte((value shr 56) and 0xFF)

proc fromBytesLE*(data: openArray[byte]): uint64 =
  ## Read a uint64 from the first 8 bytes in little-endian format.
  ## Raises IndexDefect if data has fewer than 8 bytes.
  result =
    uint64(data[0]) or
    (uint64(data[1]) shl 8) or
    (uint64(data[2]) shl 16) or
    (uint64(data[3]) shl 24) or
    (uint64(data[4]) shl 32) or
    (uint64(data[5]) shl 40) or
    (uint64(data[6]) shl 48) or
    (uint64(data[7]) shl 56)

proc readUint64LE*(src: openArray[byte], offset: int): uint64 =
  ## Read a uint64 in little-endian format from the given offset.
  ## Raises IndexDefect if offset + 8 exceeds src length.
  result =
    uint64(src[offset + 0]) or
    (uint64(src[offset + 1]) shl 8) or
    (uint64(src[offset + 2]) shl 16) or
    (uint64(src[offset + 3]) shl 24) or
    (uint64(src[offset + 4]) shl 32) or
    (uint64(src[offset + 5]) shl 40) or
    (uint64(src[offset + 6]) shl 48) or
    (uint64(src[offset + 7]) shl 56)

# =============================================================================
# Hex Formatting Utilities
# =============================================================================

proc bytesToHex*(data: openArray[byte]): string =
  ## Convert bytes to lowercase hex string.
  result = newStringOfCap(data.len * 2)
  const hexChars = "0123456789abcdef"
  for b in data:
    result.add(hexChars[int(b shr 4)])
    result.add(hexChars[int(b and 0x0F)])

proc hexPreview*(data: openArray[byte], previewLen: int = 8): string =
  ## Format bytes as a hex string with optional truncation for logging.
  ## Shows first `previewLen` bytes followed by "..." if truncated.
  ##
  ## Example: hexPreview([0x01, 0x02, ..., 0x20], 4) => "01020304..."
  if data.len == 0:
    return "<empty>"
  if data.len <= previewLen:
    return bytesToHex(data)
  else:
    return bytesToHex(data[0 ..< previewLen]) & "..."

# =============================================================================
# Safe Memory Operations
# =============================================================================

proc copyTo*[N: static int](src: openArray[byte], dest: var array[N, byte]): Result[void, string] =
  ## Safely copy bytes from a sequence to a fixed-size array.
  ## Returns error if source length doesn't match destination size.
  if src.len != N:
    return err("Size mismatch: expected " & $N & " bytes, got " & $src.len)
  for i in 0 ..< N:
    dest[i] = src[i]
  ok()

proc copyTo*(src: openArray[byte], dest: var openArray[byte], destOffset: int = 0): Result[void, string] =
  ## Safely copy bytes with bounds checking.
  ## Returns error if copy would exceed destination bounds.
  if destOffset < 0:
    return err("Invalid negative offset: " & $destOffset)
  if destOffset + src.len > dest.len:
    return err("Copy would exceed bounds: offset=" & $destOffset &
               ", srcLen=" & $src.len & ", destLen=" & $dest.len)
  for i in 0 ..< src.len:
    dest[destOffset + i] = src[i]
  ok()

proc extractBytes*(src: openArray[byte], offset: int, length: int): Result[seq[byte], string] =
  ## Extract a slice of bytes with bounds checking.
  if offset < 0:
    return err("Invalid negative offset: " & $offset)
  if offset + length > src.len:
    return err("Read would exceed bounds: offset=" & $offset &
               ", length=" & $length & ", srcLen=" & $src.len)
  var extracted = newSeq[byte](length)
  for i in 0 ..< length:
    extracted[i] = src[offset + i]
  ok(extracted)

proc extractArray*[N: static int](src: openArray[byte], offset: int): Result[array[N, byte], string] =
  ## Extract a fixed-size array from bytes with bounds checking.
  if offset < 0:
    return err("Invalid negative offset: " & $offset)
  if offset + N > src.len:
    return err("Read would exceed bounds: offset=" & $offset &
               ", size=" & $N & ", srcLen=" & $src.len)
  var arr: array[N, byte]
  for i in 0 ..< N:
    arr[i] = src[offset + i]
  ok(arr)
