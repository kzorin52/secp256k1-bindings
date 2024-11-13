# secp256k1-bindings

[![Test](https://github.com/kzorin52/secp256k1-bindings/actions/workflows/test.yml/badge.svg)](https://github.com/kzorin52/secp256k1-bindings/actions/workflows/test.yml)
[![Temnij.Crypto.SecP256k1](https://img.shields.io/nuget/v/Temnij.Crypto.SecP256k1)](https://www.nuget.org/packages/Temnij.Crypto.SecP256k1)

C# bindings for the Bitcoin Core [libsecp256k1](https://github.com/bitcoin-core/secp256k1) library.

### Build

Files in the `src/Temnij.Crypto.SecP256k1/runtimes` directory are pre-built.
Before building the project, these files should be replaced with the self-built libsecp256k1 binaries.
