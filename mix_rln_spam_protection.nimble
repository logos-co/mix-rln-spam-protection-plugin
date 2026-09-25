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
requires "metrics >= 0.2.2"
requires "nimcrypto >= 0.6.0"
requires "https://github.com/status-im/nim-secp256k1#d8f1288b7c72f00be5fc2c5ea72bf5cae1eafb15"
requires "json_serialization >= 0.2.0"

# Keep the plugin and standalone Mix facade on compatible libp2p/Mix APIs.
requires "libp2p == 2.3.1"
requires "https://github.com/richard-ramos/nim-libp2p-mix#29eaaf1d6adb57fa95e70d0c577cf6c4855598d9"

# Tasks
task test, "Run tests":
  # Requires librln.a in current directory or set LIBRLN_PATH env var
  let librlnPath = getEnv("LIBRLN_PATH", "librln.a")
  exec "nim c -r --passL:" & librlnPath & " --passL:-lm tests/test_all.nim"

task docs, "Generate documentation":
  exec "nim doc --project --index:on --outdir:docs src/mix_rln_spam_protection.nim"
