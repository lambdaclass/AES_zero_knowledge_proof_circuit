use crate::helpers::ToAnyhow;
use anyhow::Result;
use ark_ed_on_bls12_381::Fq;
use ark_r1cs_std::{alloc::AllocVar, uint128::UInt128, R1CSVar, ToBytesGadget};
use ark_relations::r1cs::ConstraintSystemRef;
// Reference: https://www.gfuzz.de/AES_2.html
// From what I understand, this is vulnerable to timing attacks,
// so it is usally done on runtime, but this will do for us for now.
const AES_LOOKUP_TABLE: [[u8; 16]; 16] = [
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
pub fn substitute_byte(byte: u8) -> Result<u8> {
    Ok(*AES_LOOKUP_TABLE
        .get((byte >> 4_i32) as usize)
        .to_anyhow("Error getting value of the lookup table")?
        .get((byte & 0x0F_u8) as usize)
        .to_anyhow("Error getting value of the lookup table")?)
}
pub fn substitute_16_bytes(
    num: u128,
    cs: ConstraintSystemRef<Fq>,
) -> Result<(u128, ConstraintSystemRef<Fq>)> {
    let num_witness =
        UInt128::new_witness(ark_relations::ns!(cs, "substition_box_witness"), || Ok(num))?;
    let mut new_bytes = [0_u8; 16];

    for (new_byte, byte) in new_bytes.iter_mut().zip(num_witness.to_bytes()?) {
        *new_byte = substitute_byte(byte.value()?)?;
    }
    Ok((u128::from_le_bytes(new_bytes), cs))
}

pub fn shift_rows(num: u128, cs: &ConstraintSystemRef<Fq>) -> Result<u128> {
    let num_witness = UInt128::new_witness(ark_relations::ns!(cs, "shift_witness"), || Ok(num))?;

    // Turn the 128 bit witness into
    // its actual value, in the form of a
    // vector of little endian bytes.
    let witness_as_bytes = num_witness
        .to_bytes()?
        .into_iter()
        .map(|byte| Ok(byte.value()?))
        .collect::<Result<Vec<u8>>>()?;
    // Turn the bytes into the 4x4 AES state matrix.
    // The matrix is represented by a 2D array,
    // where each array is a row.
    // That is, let's suppose that witness_
    // as_bytes is formed by the bytes
    // b0, b1,..., b15.
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
    let mut state_matrix = [[0u8; 4]; 4];
    for i in 0..4 {
        state_matrix[i] = [
            witness_as_bytes[i + 0],
            witness_as_bytes[i + 4],
            witness_as_bytes[i + 8],
            witness_as_bytes[i + 12],
        ]
    }
    // Rotate every state matrix row (u8 array) like specified by
    // the AES cipher algorithm.
    for (rotations, bytes) in state_matrix.iter_mut().enumerate() {
        bytes.rotate_left(rotations);
    }
    // Turn the rotated arrays into a flattened
    // 16 byte array, this is because the u128::from_le_bytes function
    // only accepts 16 byte arrays.
    let mut flattened_bytes = [0u8; 16];
    for i in 0..4 {
        for j in 0..4 {
            flattened_bytes[(i * 4) + j] = state_matrix[j][i];
        }
    }
    Ok(u128::from_le_bytes(flattened_bytes))
}
#[cfg(test)]
mod test {
    use super::*;
    use crate::aes::{substitute_16_bytes, substitute_byte};
    use ark_ed_on_bls12_381::Fq;
    use ark_relations::r1cs::ConstraintSystem;

    // Uncomment to use with proofs.
    // use ark_std::rand::SeedableRng;
    // fn seed() -> [u8; 32] {
    //     [
    //         1, 0, 52, 0, 0, 0, 0, 0, 1, 0, 10, 0, 22, 32, 0, 0, 2, 0, 55, 49, 0, 11, 0, 0, 3, 0, 0,
    //         0, 0, 0, 2, 92,
    //     ]
    // }

    #[test]
    fn test_substitution() {
        let num = 0x1000_u128;
        let mut expected = num.to_le_bytes();
        expected
            .iter_mut()
            .for_each(|e| *e = substitute_byte(*e).unwrap());
        let cs = ConstraintSystem::<Fq>::new_ref();
        let result = substitute_16_bytes(num, cs).unwrap();
        assert_eq!(u128::from_le_bytes(expected), result.0);
    }
    #[rustfmt::skip]
    #[test]
    fn test_shift() {
        let cs = ConstraintSystem::<Fq>::new_ref();
        // Generate random 16 bytes, and then check
        // that the AES shifting works like expected.
        let value_to_shift: [u8; 16] = rand::random();
        let expected: [u8; 16] = [
            value_to_shift[0], value_to_shift[5], value_to_shift[10], value_to_shift[15],
            value_to_shift[4], value_to_shift[9], value_to_shift[14], value_to_shift[3],
            value_to_shift[8], value_to_shift[13], value_to_shift[2], value_to_shift[7],
            value_to_shift[12], value_to_shift[1], value_to_shift[6], value_to_shift[11],
        ];
        let res = shift_rows(u128::from_le_bytes(value_to_shift), &cs);
        assert_eq!(res.unwrap(), u128::from_le_bytes(expected));
        assert!(cs.is_satisfied().unwrap());
        // TODO: Uncomment this using simpleworks
        // let (index_vk, proof) = crate::prover::prove(cs);
        // let mut rng = rand_chacha::ChaCha20Rng::from_seed(seed());
        // assert!(crate::prover::MarlinInst::verify(&index_vk, &[], &proof, &mut rng).unwrap());
    }
}
