use crate::helpers::traits::ToAnyhow;
use anyhow::{Context, Result};
use ark_r1cs_std::{alloc::AllocVar, uint128::UInt128, uint8::UInt8, R1CSVar, ToBytesGadget};
use ark_relations::r1cs::ConstraintSystemRef;
use collect_slice::CollectSlice;
use simpleworks::gadgets::ConstraintF;
use std::iter::zip;

// Reference: https://www.gfuzz.de/AES_2.html
// From what I understand, this is vulnerable to timing attacks,
// so it is usally done on runtime, but this will do for us for now.
const SUBSTITUTION_TABLE: [[u8; 16]; 16] = [
    // 0x0,  0x1,  0x2,  0x3,  0x4,  0x5,  0x6,  0x7,  0x8,  0x9,  0xA,  0xB,  0xC,  0xD,  0xE,  0xF,
    [
        0x63, 0x7C, 0x77, 0x7B, 0xF2, 0x6B, 0x6F, 0xC5, 0x30, 0x01, 0x67, 0x2B, 0xFE, 0xD7, 0xAB,
        0x76,
    ], // 0x0
    [
        0xCA, 0x82, 0xC9, 0x7D, 0xFA, 0x59, 0x47, 0xF0, 0xAD, 0xD4, 0xA2, 0xAF, 0x9C, 0xA4, 0x72,
        0xC0,
    ], // 0x1
    [
        0xB7, 0xFD, 0x93, 0x26, 0x36, 0x3F, 0xF7, 0xCC, 0x34, 0xA5, 0xE5, 0xF1, 0x71, 0xD8, 0x31,
        0x15,
    ], // 0x2
    [
        0x04, 0xC7, 0x23, 0xC3, 0x18, 0x96, 0x05, 0x9A, 0x07, 0x12, 0x80, 0xE2, 0xEB, 0x27, 0xB2,
        0x75,
    ], // 0x3
    [
        0x09, 0x83, 0x2C, 0x1A, 0x1B, 0x6E, 0x5A, 0xA0, 0x52, 0x3B, 0xD6, 0xB3, 0x29, 0xE3, 0x2F,
        0x84,
    ], // 0x4
    [
        0x53, 0xD1, 0x00, 0xED, 0x20, 0xFC, 0xB1, 0x5B, 0x6A, 0xCB, 0xBE, 0x39, 0x4A, 0x4C, 0x58,
        0xCF,
    ], // 0x5
    [
        0xD0, 0xEF, 0xAA, 0xFB, 0x43, 0x4D, 0x33, 0x85, 0x45, 0xF9, 0x02, 0x7F, 0x50, 0x3C, 0x9F,
        0xA8,
    ], // 0x6
    [
        0x51, 0xA3, 0x40, 0x8F, 0x92, 0x9D, 0x38, 0xF5, 0xBC, 0xB6, 0xDA, 0x21, 0x10, 0xFF, 0xF3,
        0xD2,
    ], // 0x7
    [
        0xCD, 0x0C, 0x13, 0xEC, 0x5F, 0x97, 0x44, 0x17, 0xC4, 0xA7, 0x7E, 0x3D, 0x64, 0x5D, 0x19,
        0x73,
    ], // 0x8
    [
        0x60, 0x81, 0x4F, 0xDC, 0x22, 0x2A, 0x90, 0x88, 0x46, 0xEE, 0xB8, 0x14, 0xDE, 0x5E, 0x0B,
        0xDB,
    ], // 0x9
    [
        0xE0, 0x32, 0x3A, 0x0A, 0x49, 0x06, 0x24, 0x5C, 0xC2, 0xD3, 0xAC, 0x62, 0x91, 0x95, 0xE4,
        0x79,
    ], // 0xA
    [
        0xE7, 0xC8, 0x37, 0x6D, 0x8D, 0xD5, 0x4E, 0xA9, 0x6C, 0x56, 0xF4, 0xEA, 0x65, 0x7A, 0xAE,
        0x08,
    ], // 0xB
    [
        0xBA, 0x78, 0x25, 0x2E, 0x1C, 0xA6, 0xB4, 0xC6, 0xE8, 0xDD, 0x74, 0x1F, 0x4B, 0xBD, 0x8B,
        0x8A,
    ], // 0xC
    [
        0x70, 0x3E, 0xB5, 0x66, 0x48, 0x03, 0xF6, 0x0E, 0x61, 0x35, 0x57, 0xB9, 0x86, 0xC1, 0x1D,
        0x9E,
    ], // 0xD
    [
        0xE1, 0xF8, 0x98, 0x11, 0x69, 0xD9, 0x8E, 0x94, 0x9B, 0x1E, 0x87, 0xE9, 0xCE, 0x55, 0x28,
        0xDF,
    ], // 0xE
    [
        0x8C, 0xA1, 0x89, 0x0D, 0xBF, 0xE6, 0x42, 0x68, 0x41, 0x99, 0x2D, 0x0F, 0xB0, 0x54, 0xBB,
        0x16,
    ], // 0xF
];

/// Performs the xor bit by bit between the `input_text` and the key
pub fn add_round_key(input_text: &[u8], key: &[u8; 16]) -> [u8; 16] {
    let mut ret = [0_u8; 16];

    let _ = zip(input_text, key)
        .map(|(cell_i, key_i)| cell_i ^ key_i)
        .collect_slice(&mut ret[..]);

    ret
}

pub fn substitute_byte(byte: u8) -> Result<u8> {
    let value_1: usize = (byte >> 4_i32).try_into()?;
    let value_2: usize = (byte & 0x0F_u8).try_into()?;
    Ok(*SUBSTITUTION_TABLE
        .get(value_1)
        .to_anyhow("Error getting value of the substitution table")?
        .get(value_2)
        .to_anyhow("Error getting value of the substitution table")?)
}

pub fn substitute_bytes(
    bytes: &[u8; 16],
    cs: &ConstraintSystemRef<ConstraintF>,
) -> Result<[u8; 16]> {
    let num_witness =
        UInt128::new_witness(ark_relations::ns!(cs, "substition_box_witness"), || {
            Ok(u128::from_le_bytes(*bytes))
        })?;

    let mut substituted_bytes = [0_u8; 16];
    for (new_byte, byte) in substituted_bytes.iter_mut().zip(num_witness.to_bytes()?) {
        *new_byte = substitute_byte(byte.value()?)?;
    }

    Ok(substituted_bytes)
}

// num is a 128 bit number, represented
// as 4 u32 numbers.
pub fn shift_rows(bytes: &[u8; 16], cs: &ConstraintSystemRef<ConstraintF>) -> Result<[u8; 16]> {
    // Add each number to the constrain system.
    for byte in bytes {
        UInt8::new_witness(ark_relations::ns!(cs, "shift_rows_witness"), || Ok(byte))?;
    }

    // Turn the bytes into the 4x4 AES state matrix.
    // The matrix is represented by a 2D array,
    // where each array is a row.
    // That is, let's suppose that the flattened_bytes variable
    // is formed by the bytes
    // [b0, ..., b15]
    // Then the AES state matrix will look like this:
    // b0, b4, b8, b12,
    // b1, b5, b9, b13,
    // b2, b6, b10, b14,
    // b3, b7, b11, b15
    // And our array will look like this:
    //[
    //  [b0, b4, b8, b12],
    //  [b1, b5, b9, b13],
    //  [b2, b6, b10,b14],
    //  [b3, b7, b11,b15]
    //]
    let mut state_matrix = [[0_u8; 4]; 4];
    for (i, state) in state_matrix.iter_mut().enumerate() {
        *state = [
            *(bytes.get(i).context("Out of bounds"))?,
            *(bytes.get(i + 4).context("Out of bounds")?),
            *(bytes.get(i + 8).context("Out of bounds")?),
            *(bytes.get(i + 12).context("Out ouf bounds")?),
        ];
    }

    // Rotate every state matrix row (u8 array) like specified by
    // the AES cipher algorithm.
    for (rotations, bytes) in state_matrix.iter_mut().enumerate() {
        // For the moment this operation does not generate constraints in the
        // circuit, but it should in the future.
        bytes.rotate_left(rotations);
    }

    // Turn the rotated arrays into a flattened
    // 16 byte array, ordered by column.
    let mut flattened_matrix = [0_u8; 16];
    for i in 0..4 {
        for j in 0..4 {
            *flattened_matrix
                .get_mut((i * 4) + j)
                .to_anyhow("Error getting element of flattened_matrix slice")? = *state_matrix
                .get(j)
                .to_anyhow("Error getting element of state_matrix")?
                .get(i)
                .to_anyhow("Error getting element of state_matrix")?;
        }
    }
    Ok(flattened_matrix)
}

fn gmix_column(input: &[u8; 4]) -> Option<[u8; 4]> {
    let mut b: [u8; 4] = [0; 4];
    /* The array 'a' is simply a copy of the input array 'r'
     * The array 'b' is each element of the array 'a' multiplied by 2
     * in Rijndael's Galois field
     * a[n] ^ b[n] is element n multiplied by 3 in Rijndael's Galois field */

    for (i, c) in input.iter().enumerate() {
        let h = (c >> 7_usize) & 1; /* arithmetic right shift, thus shifting in either zeros or ones */
        *b.get_mut(i)? = (c << 1_usize) ^ (h * 0x1B); /* implicitly removes high bit because b[c] is an 8-bit char, so we xor by 0x1b and not 0x11b in the next line */
        /* Rijndael's Galois field */
    }

    Some([
        b.first()? ^ input.get(3)? ^ input.get(2)? ^ b.get(1)? ^ input.get(1)?,
        b.get(1)? ^ input.first()? ^ input.get(3)? ^ b.get(2)? ^ input.get(2)?,
        b.get(2)? ^ input.get(1)? ^ input.first()? ^ b.get(3)? ^ input.get(3)?,
        b.get(3)? ^ input.get(2)? ^ input.get(1)? ^ b.first()? ^ input.first()?,
    ])
}

pub fn mix_columns(input: &[u8; 16]) -> Option<[u8; 16]> {
    let mut ret = [0_u8; 16];

    for (pos, column) in input.chunks(4).enumerate() {
        let column_aux = [
            *column.first()?,
            *column.get(1)?,
            *column.get(2)?,
            *column.get(3)?,
        ];
        let column_ret = gmix_column(&column_aux)?;

        // put column_ret in ret:
        *ret.get_mut(pos * 4)? = *column_ret.first()?;
        *ret.get_mut(pos * 4 + 1)? = *column_ret.get(1)?;
        *ret.get_mut(pos * 4 + 2)? = *column_ret.get(2)?;
        *ret.get_mut(pos * 4 + 3)? = *column_ret.get(3)?;
    }

    Some(ret)
}

/// This function returns the derived keys from the secret key.
/// Because AES 128 consists of 11 rounds, the result are 11 128-bit keys,
/// which we represent as 4 32-bit words, so we compute 44 32-bit elements
/// W_0, W_1, ..., W_43. The first four constitute the first round key, the
/// second four the second one, and so on.
pub fn derive_keys(secret_key: &[u8; 16]) -> Result<[[u8; 16]; 11]> {
    const ROUND_CONSTANTS: [u32; 10] = [
        u32::from_be_bytes([0x01, 0x00, 0x00, 0x00]),
        u32::from_be_bytes([0x02, 0x00, 0x00, 0x00]),
        u32::from_be_bytes([0x04, 0x00, 0x00, 0x00]),
        u32::from_be_bytes([0x08, 0x00, 0x00, 0x00]),
        u32::from_be_bytes([0x10, 0x00, 0x00, 0x00]),
        u32::from_be_bytes([0x20, 0x00, 0x00, 0x00]),
        u32::from_be_bytes([0x40, 0x00, 0x00, 0x00]),
        u32::from_be_bytes([0x80, 0x00, 0x00, 0x00]),
        u32::from_be_bytes([0x1B, 0x00, 0x00, 0x00]),
        u32::from_be_bytes([0x36, 0x00, 0x00, 0x00]),
    ];

    let mut result = [0_u32; 44];

    result[0] = to_u32(&secret_key[..4]).to_anyhow("Error converting to u32")?;
    result[1] = to_u32(&secret_key[4..8]).to_anyhow("Error converting to u32")?;
    result[2] = to_u32(&secret_key[8..12]).to_anyhow("Error converting to u32")?;
    result[3] = to_u32(&secret_key[12..16]).to_anyhow("Error converting to u32")?;

    for i in 4..44 {
        if i % 4 == 0 {
            let substituted_and_rotated = to_u32(&crate::substitute_word(&rotate_word(
                *result.get(i - 1).to_anyhow("Error converting to u32")?,
            ))?)
            .to_anyhow("Error converting to u32")?;

            *result.get_mut(i).to_anyhow("Error getting elem")? =
                (result.get(i - 4).to_anyhow("Error getting elem")? ^ (substituted_and_rotated))
                    ^ ROUND_CONSTANTS
                        .get(i / 4 - 1)
                        .to_anyhow("Error getting elem")?;
        } else {
            *result.get_mut(i).to_anyhow("Error getting elem")? =
                result.get(i - 4).to_anyhow("Error getting elem")?
                    ^ result.get(i - 1).to_anyhow("Error getting elem")?;
        }
    }

    let mut ret = [[0_u8; 16]; 11];

    for (i, elem) in result.chunks(4).enumerate() {
        elem.iter()
            .flat_map(|e| e.to_be_bytes())
            .collect_slice(&mut ret.get_mut(i).to_anyhow("Error getting elem")?[..]);
    }

    Ok(ret)
}

fn to_u32(value: &[u8]) -> Option<u32> {
    let array_aux: [u8; 4] = [
        *value.first()?,
        *value.get(1)?,
        *value.get(2)?,
        *value.get(3)?,
    ];
    Some(u32::from_be_bytes(array_aux))
}

fn rotate_word(input: u32) -> [u8; 4] {
    let bytes: [u8; 4] = input.to_be_bytes();
    [
        *bytes.get(1).unwrap_or(&0),
        *bytes.get(2).unwrap_or(&0),
        *bytes.get(3).unwrap_or(&0),
        *bytes.first().unwrap_or(&0),
    ]
}

#[cfg(test)]
mod test {
    use super::*;
    use ark_relations::r1cs::ConstraintSystem;

    #[test]
    fn test_substitution() {
        let num = 0x1000_u128.to_le_bytes();
        let mut expected = num;
        expected
            .iter_mut()
            .for_each(|e| *e = substitute_byte(*e).unwrap());
        let cs = ConstraintSystem::<ConstraintF>::new_ref();
        let result = substitute_bytes(&num, &cs).unwrap();
        assert_eq!(expected, result);
    }
    #[rustfmt::skip]
    #[test]
    fn test_shift() {
        let cs = ConstraintSystem::<ConstraintF>::new_ref();
        // Generate random 16 bytes, and then check
        // that the AES shifting works like expected.
        let value_to_shift: [u8; 16] = rand::random();
        let expected: [u8; 16] = [
            value_to_shift[0], value_to_shift[5], value_to_shift[10], value_to_shift[15],
            value_to_shift[4], value_to_shift[9], value_to_shift[14], value_to_shift[3],
            value_to_shift[8], value_to_shift[13], value_to_shift[2], value_to_shift[7],
            value_to_shift[12], value_to_shift[1], value_to_shift[6], value_to_shift[11],
        ];

        let res = shift_rows(&value_to_shift, &cs);
        assert_eq!(res.unwrap(), expected);
        assert!(cs.is_satisfied().unwrap());
        // TODO: Uncomment this using simpleworks
        // let (index_vk, proof) = crate::prover::prove(cs);
        // let mut rng = rand_chacha::ChaCha20Rng::from_seed(seed());
        // assert!(crate::prover::MarlinInst::verify(&index_vk, &[], &proof, &mut rng).unwrap());
    }

    #[test]
    fn test_gcolumn_mix() {
        let input: [u8; 4] = [0xdb, 0x13, 0x53, 0x45];
        let ret = gmix_column(&input);
        println!("{ret:?}");

        let input2: [u8; 4] = [0xd4, 0xbf, 0x5d, 0x30];
        let ret2 = gmix_column(&input2);
        println!("{ret2:?}");

        let input3: [u8; 4] = [0xe0, 0xb4, 0x52, 0xae];
        let ret3 = gmix_column(&input3);
        println!("{ret3:?}");
    }

    // cn = [u8; 4] -> u32 -> [u8; 4];
    // [2, 1, 1, 3] [c0] = [2c0 + c1 + c2 + 3c3]
    // [3, 2, 1, 1] [c1] = [3c0 + 2c1 + c2 + c3]
    // [1, 3, 2, 1] [c2] = [c0 + 3c1 + 2c2 + c3]
    // [1, 1, 3, 2] [c3] = [c0 + c1 + 3c2 + 2c3]
    #[test]
    fn test_one_round_column_mix() {
        let value_to_mix: [u8; 16] = [
            0xd4, 0xbf, 0x5d, 0x30, 0xe0, 0xb4, 0x52, 0xae, 0xb8, 0x41, 0x11, 0xf1, 0x1e, 0x27,
            0x98, 0xe5,
        ];
        let expected_mixed_value: [u8; 16] = [
            0x04, 0x66, 0x81, 0xe5, 0xe0, 0xcb, 0x19, 0x9a, 0x48, 0xf8, 0xd3, 0x7a, 0x28, 0x06,
            0x26, 0x4c,
        ];

        let mixed_column_vector = mix_columns(&value_to_mix).unwrap();

        assert_eq!(expected_mixed_value, mixed_column_vector);
    }

    #[test]
    fn key_expansion() {
        let secret_key = [
            0x2b, 0x7e, 0x15, 0x16, 0x28, 0xae, 0xd2, 0xa6, 0xab, 0xf7, 0x15, 0x88, 0x09, 0xcf,
            0x4f, 0x3c,
        ];
        let result = derive_keys(&secret_key).unwrap();

        assert_eq!(
            result[10],
            [
                0xd0, 0x14, 0xf9, 0xa8, 0xc9, 0xee, 0x25, 0x89, 0xe1, 0x3f, 0x0c, 0xc8, 0xb6, 0x63,
                0x0c, 0xa6,
            ]
        );

        println!("{:x?}", result);
    }
}
