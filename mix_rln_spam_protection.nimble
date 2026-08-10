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
requires "metrics >= 0.1.0"
requires "chronos >= 4.2.2"
requires "nimcrypto >= 0.6.0"
requires "secp256k1 >= 0.5.0"
requires "json_serialization >= 0.2.0"

# nim-libp2p — used directly for protobuf/minprotobuf and varint. Pinned to
# the v2.1.4 release tag, matching the `libp2p == 2.1.4` requirement in
# nim-libp2p-mix so the diamond dep resolves to a single libp2p source.
# Now that vacp2p/nim-libp2p publishes release tags, this is a version
# requirement rather than a SHA pin (see issue #8).
requires "libp2p == 2.1.4"

# libp2p_mix — extracted into its own repo; previously libp2p/protocols/mix.
# Pinned to master tip, which carries the libp2p v2.1.4 bump (#23) and the
# LIONESS wide-block payload encryption (#30, LIP-183). Master requires
# `libp2p == 2.1.4`, keeping the diamond dep collapsed to one libp2p source;
# waku.nimble should pin the same SHA.
requires "https://github.com/logos-co/nim-libp2p-mix.git#c387ca67cf477dc53ec6228027c45d8eda067917"

# Tasks
task test, "Run tests":
  # Requires librln.a in current directory or set LIBRLN_PATH env var
  # -d:metrics enables live metric collectors so the metrics suite runs;
  # -d:metricsTest silences deprecation warnings on nim-metrics test helpers
  let librlnPath = getEnv("LIBRLN_PATH", "librln.a")
  exec "nim c -r -d:metrics -d:metricsTest --passL:" & librlnPath &
    " --passL:-lm tests/test_all.nim"

task docs, "Generate documentation":
  exec "nim doc --project --index:on --outdir:docs src/mix_rln_spam_protection.nim"
