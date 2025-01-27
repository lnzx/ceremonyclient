# Ed448-Rust

[![Ci](https://github.com/lolo32/ed448-rust/actions/workflows/ci.yml/badge.svg)](https://github.com/lolo32/ed448-rust/actions/workflows/ci.yml)
[![Security audit](https://github.com/lolo32/ed448-rust/actions/workflows/audit.yml/badge.svg)](https://github.com/lolo32/ed448-rust/actions/workflows/audit.yml)
[![codecov](https://codecov.io/gh/lolo32/ed448-rust/branch/main/graph/badge.svg?token=V206OZ48AA)](https://codecov.io/gh/lolo32/ed448-rust)
[![License](https://img.shields.io/badge/License-Apache%202.0-blue.svg)](https://opensource.org/licenses/Apache-2.0)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Docs.rs](https://docs.rs/ed448-rust/badge.svg)](https://docs.rs/ed448-rust/)
[![Crates.io](https://img.shields.io/crates/v/ed448-rust)](https://crates.io/crates/ed448-rust)

This is an implementation of Edwards-Curve Digital Signature Algorithm (EdDSA)
from the [RFC8032](https://tools.ietf.org/html/rfc8032) in pure Rust,
but only the ed448 support is implemented.

It's a EdDSA for ed448 signing/verifying.

_This is direct port of the Python code in the RFC, so it's the same warning
as it:_

> _**Note: This code is not intended for production.  Although it should**_
> _**produce correct results for every input, it is slow and makes no**_
> _**attempt to avoid side-channel attacks.**_

## Usage

```rust
use core::convert::TryFrom;
use rand_core::OsRng;
use ed448_rust::{PrivateKey, PublicKey};

fn main () {
    // Generate a new random private key
    let private_key = PrivateKey::new(&mut OsRng);

    // Store the key
    let pkey_stored = private_key.as_bytes();

    // Load a stored key before using it, or generating the public key
    let private_key = PrivateKey::try_from(pkey_stored).unwrap();

    // Extract associated public key
    let public_key = PublicKey::from(&private_key);

    // Store the public key
    let pubkey_stored = public_key.as_byte();

    // Sign a message without context
    let signature = private_key.sign(b"Message to sign", None).unwrap();
    // Sign a message with a context
    let signature_ctx = private_key.sign(b"Message to sign", Some(&[0x01, 0xA6])).unwrap();
    // Sign a pre-hashed message without context
    let signature_ph = private_key.sign_ph(b"Message to sign", None).unwrap();

    // Verify the signature without context
    assert!(public_key.verify(b"Message to sign", &signature, None).is_ok());
    // Verify the signature with context
    assert!(public_key.verify(b"Message to sign", &signature_ctx, Some(&[0x01, 0xA6])).is_ok());
    // Verify the signature with the pre-hash and without context
    assert!(public_key.verify_ph(b"Message to sign", &signature_ph, None).is_ok());
}
```

## License

This code is licensed under [MIT] / [Apache2.0]

[MIT]: LICENSE_MIT.txt
[Apache2.0]: LICENSE_APACHE2.txt
