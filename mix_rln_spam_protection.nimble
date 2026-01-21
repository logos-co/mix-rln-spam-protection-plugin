# Package
version       = "0.1.0"
author        = "vacp2p"
description   = "RLN-based spam protection plugin for libp2p mix networks"
license       = "MIT OR Apache-2.0"
srcDir        = "src"

# Dependencies
requires "nim >= 2.0.0"
requires "results >= 0.4.0"
requires "stew >= 0.1.0"
requires "chronicles >= 0.10.0"
requires "chronos >= 4.0.0"
requires "nimcrypto >= 0.6.0"
requires "secp256k1 >= 0.5.0"
requires "json_serialization >= 0.2.0"

# nim-libp2p for SpamProtectionInterface
# Use the mix-spam-protection branch until PR #2037 is merged
requires "libp2p#mix-spam-protection"

# Tasks
task test, "Run tests":
  exec "nim c -r tests/test_all.nim"

task docs, "Generate documentation":
  exec "nim doc --project --index:on --outdir:docs src/mix_rln_spam_protection.nim"
