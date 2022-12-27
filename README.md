# AES Encryption circuit

## Circuit Inputs

- `message`: The message to encrypt
- `secret_key`: The secret key used for the AES encryption

## Circuit Outputs

- `ciphertext`: The encrypted message

## AES Flow

Each AES round takes a message as input and performs the following steps:
- `Add Round Key`
- `Sub Bytes`
- `Shift Rows`
- `Mix Columns`

## Building Blocks Required


| Building Blocks | Required Primitives |
| --------------- | ------------------- |
| AddRoundKey     | `xor` (already implemented)               |
| SubBytes        | Lookup table        |
| ShiftRows       | Row shifting                   |
| MixColumns      | `addmany` (already implemented)           |

TODO: Explain the following in more depth.
### Add RoundKey

- The first addition is an XOR of the plaintext and the secret key.
- At the end of the round the round key should be added using an XOR to the output of MixColumns.

### Sub Bytes

- Lookup table.

###  Shift Rows

- Byte-shifting method for the `UInt32` gadget.

### Mix Columns

- Multiply columns by a matrix. The primitives for this are already there.
