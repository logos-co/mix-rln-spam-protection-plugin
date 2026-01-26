# Mix RLN Spam Protection Plugin
# Copyright (c) 2025 vacp2p
# Licensed under either of Apache License 2.0 or MIT license.

## Credential management for RLN membership.
## Supports generating new credentials and loading from keystore files.

import std/[json, os, options, strutils]
import results
import chronicles
import nimcrypto/[pbkdf2, rijndael, bcmode, sha2, sysrand]

import ./types
import ./constants
import ./rln_interface

export types

logScope:
  topics = "mix-rln-credentials"

const
  # Keystore encryption parameters
  KeystoreVersion = 1
  Pbkdf2Iterations = 100000
  SaltSize = 32
  IvSize = 16
  KeySize = 32

type
  # Keystore entry for a credential
  KeystoreEntry = object
    version: int
    salt: seq[byte]
    iv: seq[byte]
    ciphertext: seq[byte] # Encrypted IdentityCredential
    membershipIndex: Option[MembershipIndex]

  # Keystore containing multiple credentials
  Keystore* = object
    entries: seq[KeystoreEntry]

proc generateCredentials*(): RlnResult[IdentityCredential] =
  ## Generate new random credentials.
  generateMembershipKey()

proc generateCredentialsFromSeed*(
    seed: openArray[byte]
): RlnResult[IdentityCredential] =
  ## Generate deterministic credentials from a seed.
  generateMembershipKey(seed)

proc serializeCredential(cred: IdentityCredential): seq[byte] =
  ## Serialize credential to bytes.
  result = newSeq[byte](128)
  copyMem(addr result[0], unsafeAddr cred.idTrapdoor[0], HashByteSize)
  copyMem(addr result[32], unsafeAddr cred.idNullifier[0], HashByteSize)
  copyMem(addr result[64], unsafeAddr cred.idSecretHash[0], HashByteSize)
  copyMem(addr result[96], unsafeAddr cred.idCommitment[0], HashByteSize)

proc deserializeCredential(data: seq[byte]): RlnResult[IdentityCredential] =
  ## Deserialize credential from bytes.
  if data.len != 128:
    return err("Invalid credential data size")

  var cred: IdentityCredential
  copyMem(addr cred.idTrapdoor[0], unsafeAddr data[0], HashByteSize)
  copyMem(addr cred.idNullifier[0], unsafeAddr data[32], HashByteSize)
  copyMem(addr cred.idSecretHash[0], unsafeAddr data[64], HashByteSize)
  copyMem(addr cred.idCommitment[0], unsafeAddr data[96], HashByteSize)
  ok(cred)

proc deriveKey(password: string, salt: seq[byte]): array[KeySize, byte] =
  ## Derive encryption key from password using PBKDF2.
  let keySeq = pbkdf2(sha2.sha256, password, salt, Pbkdf2Iterations, KeySize)
  copyMem(addr result[0], unsafeAddr keySeq[0], KeySize)

proc encryptCredential(
    cred: IdentityCredential, password: string
): RlnResult[KeystoreEntry] =
  ## Encrypt a credential with a password.
  var salt = newSeq[byte](SaltSize)
  var iv = newSeq[byte](IvSize)

  if randomBytes(addr salt[0], SaltSize) != SaltSize:
    return err("Failed to generate random salt")

  if randomBytes(addr iv[0], IvSize) != IvSize:
    return err("Failed to generate random IV")

  let key = deriveKey(password, salt)
  let plaintext = serializeCredential(cred)

  # Pad to block size (16 bytes for AES) using PKCS7 padding
  # IMPORTANT: PKCS7 always adds padding, even if data is block-aligned
  # If data is N blocks, add a full block of padding (16 bytes of value 0x10)
  let blockSize = 16
  let padLen = blockSize - (plaintext.len mod blockSize)
  let paddedLen = plaintext.len + padLen
  var paddedPlaintext = newSeq[byte](paddedLen)
  copyMem(addr paddedPlaintext[0], unsafeAddr plaintext[0], plaintext.len)
  # Fill padding bytes with padding length value (PKCS7)
  for i in plaintext.len ..< paddedLen:
    paddedPlaintext[i] = byte(padLen)

  # Encrypt using AES-256-CBC
  var ciphertext = newSeq[byte](paddedPlaintext.len)
  var ctx: CBC[aes256]
  ctx.init(key, iv)
  ctx.encrypt(paddedPlaintext, ciphertext)
  ctx.clear()

  ok(
    KeystoreEntry(
      version: KeystoreVersion,
      salt: salt,
      iv: iv,
      ciphertext: ciphertext,
      membershipIndex: none(MembershipIndex),
    )
  )

proc decryptCredential(
    entry: KeystoreEntry, password: string
): RlnResult[IdentityCredential] =
  ## Decrypt a credential from a keystore entry.
  if entry.version != KeystoreVersion:
    return err("Unsupported keystore version: " & $entry.version)

  let key = deriveKey(password, entry.salt)

  # Decrypt using AES-256-CBC
  var plaintext = newSeq[byte](entry.ciphertext.len)
  var ctx: CBC[aes256]
  ctx.init(key, entry.iv)
  ctx.decrypt(entry.ciphertext, plaintext)
  ctx.clear()

  # Remove PKCS7 padding
  if plaintext.len == 0:
    return err("Empty plaintext after decryption")

  let padLen = int(plaintext[^1])
  if padLen > plaintext.len or padLen > 16:
    return err("Invalid padding")

  # Verify padding
  for i in plaintext.len - padLen ..< plaintext.len:
    if plaintext[i] != byte(padLen):
      return err("Invalid padding bytes")

  let unpaddedLen = plaintext.len - padLen
  if unpaddedLen != 128:
    return err("Invalid credential data after decryption")

  deserializeCredential(plaintext[0 ..< 128])

# Note: toHex and fromHex are imported from types module

proc entryToJson(entry: KeystoreEntry): JsonNode =
  ## Convert keystore entry to JSON.
  var node =
    %*{
      "version": entry.version,
      "salt": entry.salt.toHex(),
      "iv": entry.iv.toHex(),
      "ciphertext": entry.ciphertext.toHex(),
    }

  if entry.membershipIndex.isSome:
    node["membershipIndex"] = %entry.membershipIndex.get()

  node

proc entryFromJson(node: JsonNode): RlnResult[KeystoreEntry] =
  ## Parse keystore entry from JSON.
  if not node.hasKey("version") or not node.hasKey("salt") or not node.hasKey("iv") or
      not node.hasKey("ciphertext"):
    return err("Missing required keystore fields")

  let version = node["version"].getInt()
  let salt = types.fromHex(node["salt"].getStr())
  let iv = types.fromHex(node["iv"].getStr())
  let ciphertext = types.fromHex(node["ciphertext"].getStr())

  if salt.len == 0 or iv.len == 0 or ciphertext.len == 0:
    return err("Invalid hex data in keystore")

  var entry = KeystoreEntry(
    version: version,
    salt: salt,
    iv: iv,
    ciphertext: ciphertext,
    membershipIndex: none(MembershipIndex),
  )

  if node.hasKey("membershipIndex"):
    entry.membershipIndex =
      some(MembershipIndex(node["membershipIndex"].getBiggestInt()))

  ok(entry)

proc saveKeystore*(
    cred: IdentityCredential,
    password: string,
    path: string,
    membershipIndex: Option[MembershipIndex] = none(MembershipIndex),
): RlnResult[void] =
  ## Save a credential to a keystore file.
  var entry = encryptCredential(cred, password).valueOr:
    return err("Failed to encrypt credential: " & error)

  entry.membershipIndex = membershipIndex

  var entriesJson = newJArray()
  entriesJson.add(entryToJson(entry))

  let json = %*{"keystore": entriesJson}

  try:
    writeFile(path, $json)
    debug "Saved keystore", path = path
    ok()
  except IOError as e:
    err("Failed to write keystore: " & e.msg)

proc loadKeystore*(
    path: string, password: string
): RlnResult[(IdentityCredential, Option[MembershipIndex])] =
  ## Load a credential from a keystore file.
  if not fileExists(path):
    return err("Keystore file not found: " & path)

  let content =
    try:
      readFile(path)
    except IOError as e:
      return err("Failed to read keystore: " & e.msg)

  let json =
    try:
      parseJson(content)
    except JsonParsingError as e:
      return err("Failed to parse keystore JSON: " & e.msg)

  if not json.hasKey("keystore"):
    return err("Invalid keystore format: missing 'keystore' key")

  let entries = json["keystore"]
  if entries.kind != JArray or entries.len == 0:
    return err("Invalid keystore format: empty entries")

  # Load first entry
  let entry = entryFromJson(entries[0]).valueOr:
    return err("Failed to parse keystore entry: " & error)

  let cred = decryptCredential(entry, password).valueOr:
    return err("Failed to decrypt credential: " & error)

  debug "Loaded keystore", path = path, hasIndex = entry.membershipIndex.isSome
  ok((cred, entry.membershipIndex))

proc loadOrGenerateCredentials*(
    keystorePath: string, password: string
): RlnResult[(IdentityCredential, Option[MembershipIndex], bool)] =
  ## Load credentials from keystore if it exists, otherwise generate new ones.
  ## Returns (credential, membershipIndex, wasGenerated).

  if fileExists(keystorePath):
    let (cred, index) = loadKeystore(keystorePath, password).valueOr:
      return err("Failed to load keystore: " & error)
    debug "Loaded existing credentials"
    ok((cred, index, false))
  else:
    let cred = generateCredentials().valueOr:
      return err("Failed to generate credentials: " & error)

    # Save to keystore
    let saveResult = saveKeystore(cred, password, keystorePath)
    if saveResult.isErr:
      warn "Failed to save generated credentials", error = saveResult.error

    debug "Generated new credentials"
    ok((cred, none(MembershipIndex), true))
