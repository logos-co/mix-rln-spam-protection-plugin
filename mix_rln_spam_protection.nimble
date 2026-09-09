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

# nim-libp2p — used only for protobuf/minprotobuf and varint, a surface that
# has been stable for years. A range, not an exact pin: as a library this
# should state the loosest constraint it actually needs and let the consuming
# application pin the exact version. An exact pin here is what previously
# froze the plugin at 2.1.4 while logos-delivery moved on, making the two
# unsatisfiable together. Lower bound matches libp2p_mix's own requirement.
requires "libp2p >= 2.2.0"

# libp2p_mix — extracted into its own repo; previously libp2p/protocols/mix.
# Pinned to the same SHA logos-delivery master pins, which relaxes its own
# libp2p requirement to >= 2.2.0. Only `libp2p_mix/spam_protection` is used
# here, and it is unchanged from the previous #c387ca67 pin.
requires "https://github.com/logos-co/nim-libp2p-mix#39d2ac78da7b7f33562eb7cd95d6280ca9fa0e94"

# Tasks
task test, "Run tests":
  # Requires librln.a in current directory or set LIBRLN_PATH env var
  let librlnPath = getEnv("LIBRLN_PATH", "librln.a")
  exec "nim c -r --passL:" & librlnPath & " --passL:-lm tests/test_all.nim"

task docs, "Generate documentation":
  exec "nim doc --project --index:on --outdir:docs src/mix_rln_spam_protection.nim"
