# Package
version = "0.1.0"
author = "vacp2p"
description = "RLN-based spam protection plugin for libp2p mix networks"
license = "MIT OR Apache-2.0"
srcDir = "src"

# Dependencies
requires "nim >= 2.2.4"
requires "results >= 0.4.0"
requires "stew >= 0.4.2"
requires "chronicles >= 0.11.0"
requires "chronos >= 4.2.2"
requires "nimcrypto >= 0.6.0"
requires "secp256k1 >= 0.5.0"
requires "json_serialization >= 0.2.0"

# nim-libp2p — used directly for protobuf/minprotobuf and varint. Pinned to
# the same commit nim-libp2p-mix uses so the diamond dep resolves to a single
# libp2p source. c43199378 is the release/v2.0.0 tip (3 patch commits past
# the v2.0.0 bump). SHA-pinned because vacp2p/nim-libp2p has not yet
# published a v2.0.0 git tag.
requires "https://github.com/vacp2p/nim-libp2p.git#c43199378f46d0aaf61be1cad1ee1d63e8f665d6"

# libp2p_mix — extracted into its own repo; previously libp2p/protocols/mix.
# Tip of chore/bump-libp2p-v2.0.0 (sink overrides on the three mix Connection
# subclasses + AddressConfidence.Infinite on pool entries, to align with
# libp2p v2.0.0's LPStream.write signature and AddressBook auto-prune).
requires "https://github.com/logos-co/nim-libp2p-mix.git#a32af1a4b89d343c22df74699818de2cb12b8138"

# Tasks
task test, "Run tests":
  # Requires librln.a in current directory or set LIBRLN_PATH env var
  let librlnPath = getEnv("LIBRLN_PATH", "librln.a")
  exec "nim c -r --passL:" & librlnPath & " --passL:-lm tests/test_all.nim"

task docs, "Generate documentation":
  exec "nim doc --project --index:on --outdir:docs src/mix_rln_spam_protection.nim"
