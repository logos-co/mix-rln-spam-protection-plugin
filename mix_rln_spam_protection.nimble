# Package
version = "0.1.0"
author = "vacp2p"
description = "RLN-based spam protection plugin for libp2p mix networks"
license = "MIT OR Apache-2.0"
srcDir = "src"

# Dependencies
requires "nim >= 2.0.0"
requires "results >= 0.4.0"
requires "stew >= 0.4.2"
requires "chronicles >= 0.11.0"
requires "chronos >= 4.2.2"
requires "nimcrypto >= 0.6.0"
requires "secp256k1 >= 0.5.0"
requires "json_serialization >= 0.2.0"

# nim-libp2p — used directly for protobuf/minprotobuf and varint.
# Pinned to the same commit libp2p_mix master uses, so downstream consumers
# (waku) don't end up with two conflicting libp2p pins via this plugin.
requires "https://github.com/vacp2p/nim-libp2p.git#d4cd68b91b82f34a0ede3766ab1ca8119d5015f8"

# libp2p_mix — extracted into its own repo; previously libp2p/protocols/mix.
# Bumped to libp2p_mix master so downstream consumers (waku) don't have to
# carry a transitive #f24cd25a pin alongside their own libp2p_mix master pin.
requires "https://github.com/logos-co/nim-libp2p-mix.git#7cb7556d9a228573fc5622af7ffb2dd11741e043"

# Tasks
task test, "Run tests":
  # Requires librln.a in current directory or set LIBRLN_PATH env var
  let librlnPath = getEnv("LIBRLN_PATH", "librln.a")
  exec "nim c -r --passL:" & librlnPath & " --passL:-lm tests/test_all.nim"

task docs, "Generate documentation":
  exec "nim doc --project --index:on --outdir:docs src/mix_rln_spam_protection.nim"
