// Copyright 2021 Lolo_32
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//   http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

/// Errors of this crate
#[derive(Debug, Copy, Clone, Eq, PartialEq)]
pub enum Ed448Error {
    /// The provided array is not in the correct length for the private key.
    ///
    /// It must be [`crate::KEY_LENGTH`].
    ///
    /// See [PrivateKey::from](crate::PrivateKey::from).
    WrongKeyLength,
    /// The provided array is not in the correct length for the public key.
    ///
    /// It must be [`crate::KEY_LENGTH`].
    ///
    /// See [PublicKey::from](crate::PublicKey::from).
    WrongPublicKeyLength,
    /// The provided array is not in the correct length for the signature.
    ///
    /// It must be [`SIG_LENGTH`](crate::SIG_LENGTH).
    ///
    /// See [PublicKey::verify](crate::PublicKey::verify).
    WrongSignatureLength,
    /// The computed point is not valid (maybe forged/altered public key or signature).
    InvalidPoint,
    /// Signature verification failed.
    ///
    /// See [PublicKey::verify](crate::PublicKey::verify).
    InvalidSignature,
    /// The provided context byte array is too long.
    ///
    /// It must not be more than 256 byte.
    ContextTooLong,
}
