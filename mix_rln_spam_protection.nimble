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
# Delivery currently resolves secp256k1 from this commit because upstream has no tag.
requires "https://github.com/status-im/nim-secp256k1#d8f1288b7c72f00be5fc2c5ea72bf5cae1eafb15"
requires "json_serialization >= 0.2.0"

# Keep the plugin and standalone Mix facade on compatible libp2p/Mix APIs.
requires "libp2p >= 2.3.1"
requires "https://github.com/richard-ramos/nim-libp2p-mix#d4aeff5f032563fc0f9b042a1c8c049d9fa69fba"

# Tasks
task test, "Run tests that do not require librln":
  exec "nim c -r -d:metrics -d:metricsTest tests/test_module_api.nim"

task testRLN, "Run tests that require librln":
  # Requires librln.a in current directory or set LIBRLN_PATH env var
  # -d:metrics enables live metric collectors so the metrics suite runs;
  # -d:metricsTest silences deprecation warnings on nim-metrics test helpers
  let librlnPath = getEnv("LIBRLN_PATH", "librln.a")
  exec "nim c -r -d:metrics -d:metricsTest --passL:" & librlnPath &
    " --passL:-lm tests/test_all.nim"

task docs, "Generate documentation":
  exec "nim doc --project --index:on --outdir:docs src/mix_rln_spam_protection.nim"
