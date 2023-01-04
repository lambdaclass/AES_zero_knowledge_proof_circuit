# AES Encryption circuit

ZK-Snark circuit to prove that a given ciphertext is the correct `AES-128` encryption using a certain secret key.

This first iteration uses ECB as the mode of operation and `Marlin` as the proving system for the circuit. In the future we will support CBC and GCM as alternative modes and `Plonk` as an alternative proving system.

## Circuit Inputs

### Private

- `message`: The message to encrypt. 
- `secret_key`: The secret key used for the AES encryption.

### Public
- `ciphertext`: The encrypted message. This is public as the entire point of the circuit is for a verifier to be assured that the ciphertext they were given is the correct one.

## Usage
You can find an example usage under the `main.rs` module. Below is an explanation of it.

First, the proving and verifying keys must be generated. You can generate ones for testing by calling

```rust
let (proving_key, verifying_key) = synthesize_keys(message_length)?;
```

where `message_length` is the length of the message to be encrypted. Underneath, this is generating some universal SRS and then deriving the keys from it. In a real world scenario, the SRS should be generated in a secure manner through some setup using MPC.

With the proving key in hand, a prover calls

```rust
let message = [1_u8; 16];
let secret_key = [0_u8; 16];

let proof = encrypt(&message, &secret_key, &primitive_ciphertext, proving_key)?;
```

where `primitive_ciphertext` is a byte slice with the result of the `AES` encryption (under the example there's a helper function for it, but you can use any standard `AES` implementation).

The prover then hands the resulting proof along with the ciphertext to the verifier, who calls

```rust
let result = verify_encryption(
    verifying_key,
    &proof,
    &primitive_ciphertext
)?;

assert!(result);
```

## AES Flow

`AES-128` consists of 11 rounds. The secret key is used to derive 11 round keys, one for each round. 

Each AES round then takes a message as input and performs the following steps:
- `Add Round Key`
- `Sub Bytes`
- `Shift Rows`
- `Mix Columns`

## Building Blocks Required
Given the above, the building blocks required at the circuit level are the following:

| Building Blocks | Required Primitives |
| --------------- | ------------------- |
| AddRoundKey     | `xor`               |
| SubBytes        | conditional select  |
| ShiftRows       | Row shifting        |
| MixColumns      | `addmany`           |
| KeyDerivation   | All of the above    |

### Add RoundKey
This is just an xor of the input against the current round key.

### Sub Bytes
This is the so called [Rijndael S-Box](https://en.wikipedia.org/wiki/Rijndael_S-box), a lookup table that has a pretty complicated calculation involving [Rijndael's finite field](https://cryptohack.gitbook.io/cryptobook/symmetric-cryptography/aes/rijndael-finite-field). 

Inside the circuit, we implement it by instantiating the precomputed table as 256 constants and then using a conditional select operation to do the lookup.

###  Shift Rows
This step simply writes the input as a byte matrix and then rotates each row.

### Mix Columns
`Mix Columns` is essentially multiplying the input by a matrix, only the multiplication is once again performed in [Rijndael's finite field](https://cryptohack.gitbook.io/cryptobook/symmetric-cryptography/aes/rijndael-finite-field).

### Key Derivation
The key derivation is the most complex step, but it's ultimately just a combination of all the basic operations used in the four steps for every round.

## Missing constraints

There are currently two basic operations that are not properly implemented inside our circuit, as they do not generate constraints. They are:

- Left shift, i.e., doing `a << n` for some `a` and `n`.
- Left byte rotation. Given a `u32`, divide into 4 bytes and rotate them left a certain amount.
