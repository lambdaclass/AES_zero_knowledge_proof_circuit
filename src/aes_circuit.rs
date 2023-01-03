use crate::helpers::traits::ToAnyhow;
use anyhow::{ensure, Result};
use ark_r1cs_std::{prelude::AllocVar, R1CSVar};
use simpleworks::gadgets::{UInt32Gadget, UInt8Gadget};

/// This function returns the derived keys from the secret key.
/// Because AES 128 consists of 11 rounds, the result are 11 128-bit keys,
/// which we represent as 4 32-bit words, so we compute 44 32-bit elements
/// W_0, W_1, ..., W_43. The first four constitute the first round key, the
/// second four the second one, and so on.
pub fn derive_keys(secret_key: &[UInt8Gadget]) -> Result<Vec<Vec<UInt8Gadget>>> {
    // TODO: We should just pass around the constraint system explicitly instead of
    // doing this everywhere.
    let constraint_system = secret_key
        .first()
        .to_anyhow("Error getting the first byte of the secret key")?
        .cs();

    let round_constants: [UInt32Gadget; 10] = [
        UInt32Gadget::new_constant(
            constraint_system.clone(),
            u32::from_be_bytes([0x01, 0x00, 0x00, 0x00]),
        )?,
        UInt32Gadget::new_constant(
            constraint_system.clone(),
            u32::from_be_bytes([0x02, 0x00, 0x00, 0x00]),
        )?,
        UInt32Gadget::new_constant(
            constraint_system.clone(),
            u32::from_be_bytes([0x04, 0x00, 0x00, 0x00]),
        )?,
        UInt32Gadget::new_constant(
            constraint_system.clone(),
            u32::from_be_bytes([0x08, 0x00, 0x00, 0x00]),
        )?,
        UInt32Gadget::new_constant(
            constraint_system.clone(),
            u32::from_be_bytes([0x10, 0x00, 0x00, 0x00]),
        )?,
        UInt32Gadget::new_constant(
            constraint_system.clone(),
            u32::from_be_bytes([0x20, 0x00, 0x00, 0x00]),
        )?,
        UInt32Gadget::new_constant(
            constraint_system.clone(),
            u32::from_be_bytes([0x40, 0x00, 0x00, 0x00]),
        )?,
        UInt32Gadget::new_constant(
            constraint_system.clone(),
            u32::from_be_bytes([0x80, 0x00, 0x00, 0x00]),
        )?,
        UInt32Gadget::new_constant(
            constraint_system.clone(),
            u32::from_be_bytes([0x1B, 0x00, 0x00, 0x00]),
        )?,
        UInt32Gadget::new_constant(
            constraint_system,
            u32::from_be_bytes([0x36, 0x00, 0x00, 0x00]),
        )?,
    ];

    let mut result: Vec<UInt32Gadget> = Vec::with_capacity(44);

    result.push(to_u32(&secret_key[..4])?);
    result.push(to_u32(&secret_key[4..8])?);
    result.push(to_u32(&secret_key[8..12])?);
    result.push(to_u32(&secret_key[12..16])?);

    for i in 4..44 {
        if i % 4 == 0 {
            let substituted_and_rotated = to_u32(&substitute_word(&rotate_word(
                result.get(i - 1).to_anyhow("Error converting to u32")?,
            )?)?)?;

            let mut res = (result
                .get(i - 4)
                .to_anyhow("Error getting elem")?
                .xor(&substituted_and_rotated))?;

            res = res.xor(
                round_constants
                    .get(i / 4 - 1)
                    .to_anyhow("Error getting elem")?,
            )?;

            result.push(res);
        } else {
            let res = result
                .get(i - 4)
                .to_anyhow("Error getting elem")?
                .xor(result.get(i - 1).to_anyhow("Error getting elem")?)?;

            result.push(res);
        }
    }

    let mut ret: Vec<Vec<UInt8Gadget>> = vec![];

    for elem in result.chunks_mut(4) {
        let mut round_key = vec![];
        for u32_value in elem {
            let bytes = to_bytes_be(u32_value)?;
            for byte in bytes {
                round_key.push(byte);
            }
        }
        ret.push(round_key);
    }

    Ok(ret)
}

fn substitute_word(input: &[UInt8Gadget]) -> Result<Vec<UInt8Gadget>> {
    let mut result = vec![];
    result.push(substitute_byte(&input[0])?);
    result.push(substitute_byte(&input[1])?);
    result.push(substitute_byte(&input[2])?);
    result.push(substitute_byte(&input[3])?);

    Ok(result)
}

fn rotate_word(input: &UInt32Gadget) -> Result<Vec<UInt8Gadget>> {
    let value = input.value()?;
    let bytes: [u8; 4] = value.to_be_bytes();
    let constraint_system = input.cs();

    let mut ret = vec![];
    ret.push(UInt8Gadget::new_witness(constraint_system.clone(), || {
        Ok(*bytes.get(1).unwrap_or(&0))
    })?);
    ret.push(UInt8Gadget::new_witness(constraint_system.clone(), || {
        Ok(*bytes.get(2).unwrap_or(&0))
    })?);
    ret.push(UInt8Gadget::new_witness(constraint_system.clone(), || {
        Ok(*bytes.get(3).unwrap_or(&0))
    })?);
    ret.push(UInt8Gadget::new_witness(constraint_system.clone(), || {
        Ok(*bytes.first().unwrap_or(&0))
    })?);

    Ok(ret)
}

// It's either this or forking `r1cs-std`.
fn to_bytes_be(input: &mut UInt32Gadget) -> Result<Vec<UInt8Gadget>> {
    let mut bits = input.to_bits_le();
    bits.reverse();

    Ok(bits
        .chunks_mut(8)
        .map(|chunk| {
            chunk.reverse();
            UInt8Gadget::from_bits_le(chunk)
        })
        .collect())
}

fn to_u32(value: &[UInt8Gadget]) -> Result<UInt32Gadget> {
    let first_element = value
        .first()
        .to_anyhow("Error retrieving byte from UInt8 slice")?;

    let constraint_system = first_element.cs();
    let native_u32_value: [u8; 4] = [
        first_element.value()?,
        value
            .get(1)
            .to_anyhow("Error retrieving byte from UInt8 slice")?
            .value()?,
        value
            .get(2)
            .to_anyhow("Error retrieving byte from UInt8 slice")?
            .value()?,
        value
            .get(3)
            .to_anyhow("Error retrieving byte from UInt8 slice")?
            .value()?,
    ];

    let value = u32::from_be_bytes(native_u32_value);

    Ok(UInt32Gadget::new_witness(constraint_system, || Ok(value))?)
}

pub fn add_round_key(input: &[UInt8Gadget], round_key: &[UInt8Gadget]) -> Result<Vec<UInt8Gadget>> {
    ensure!(
        input.len() == 16,
        "Input must be 16 bytes length when adding round key"
    );
    ensure!(
        round_key.len() == 16,
        "Round key must be 16 bytes length when adding round key"
    );

    let output = input
        .iter()
        .zip(round_key)
        .filter_map(|(input_text_byte, round_key_byte)| {
            input_text_byte
                .xor(round_key_byte)
                .to_anyhow("Error adding round key")
                .ok()
        })
        .collect::<Vec<UInt8Gadget>>();

    ensure!(output.len() == 16, "Error adding round key");

    Ok(output)
}

// TODO: Some operations are not generating constraints.
fn rotate_left(byte: &UInt8Gadget, n: u8) -> Result<UInt8Gadget> {
    let cs = byte.cs();
    let left_shifted = UInt8Gadget::new_witness(cs.clone(), || Ok(byte.value()? << n))?;
    let right_shifted = UInt8Gadget::new_witness(cs, || Ok(byte.value()? >> (8 - n)))?;

    let left_operand_bits = ark_r1cs_std::ToBitsGadget::to_bits_le(&left_shifted)?;
    let right_operand_bits = ark_r1cs_std::ToBitsGadget::to_bits_le(&right_shifted)?;

    let or_result = left_operand_bits
        .iter()
        .zip(right_operand_bits)
        .map(|(left, right)| left.or(&right))
        .collect::<Result<Vec<_>, _>>()?;

    Ok(UInt8Gadget::from_bits_le(&or_result))
}

// TODO: Some operations are not generating constraints.
fn substitute_byte(byte: &UInt8Gadget) -> Result<UInt8Gadget> {
    let cs = byte.cs();

    let mut p = UInt8Gadget::new_witness(cs.clone(), || Ok(1_u8))?;
    let mut q = UInt8Gadget::new_witness(cs.clone(), || Ok(1_u8))?;
    let mut sbox = UInt8Gadget::constant_vec(&[0_u8; 256]);

    /* loop invariant: p * q == 1 in the Galois field */
    loop {
        /* multiply p by 3 */
        let p_times_2 = UInt8Gadget::new_witness(cs.clone(), || Ok(p.value()? << 1_u8))?;
        let adjustment =
            UInt8Gadget::new_witness(cs.clone(), || Ok(((p.value()? >> 7_u8) & 1) * 0x1B))?;
        p = p.xor(&p_times_2)?.xor(&adjustment)?;

        /* divide q by 3 (equals multiplication by 0xf6) */
        q = q.xor(&UInt8Gadget::new_witness(cs.clone(), || {
            Ok(q.value()? << 1_u8)
        })?)?;
        q = q.xor(&UInt8Gadget::new_witness(cs.clone(), || {
            Ok(q.value()? << 2_u8)
        })?)?;
        q = q.xor(&UInt8Gadget::new_witness(cs.clone(), || {
            Ok(q.value()? << 4_u8)
        })?)?;
        q = q.xor(&UInt8Gadget::new_witness(cs.clone(), || {
            Ok(((q.value()? >> 7_u8) & 1) * 0x09)
        })?)?;

        /* compute the affine transformation */
        let xformed = q
            .xor(&rotate_left(&q, 1)?)?
            .xor(&rotate_left(&q, 2)?)?
            .xor(&rotate_left(&q, 3)?)?
            .xor(&rotate_left(&q, 4)?)?;

        let p_as_usize: usize = p.value()?.try_into()?;
        *sbox
            .get_mut(p_as_usize)
            .to_anyhow("Error saving substitution box value")? =
            xformed.xor(&UInt8Gadget::new_witness(cs.clone(), || Ok(0x63))?)?;

        if p.value()? == 1 {
            break;
        }
    }
    *sbox
        .get_mut(0)
        .to_anyhow("Error getting the first element of the substitution box")? =
        UInt8Gadget::new_witness(cs, || Ok(0x63_u8))?;

    let byte_index: usize = byte.value()?.try_into()?;
    Ok(sbox
        .get(byte_index)
        .to_anyhow("Error getting substitution box value")?
        .clone())
}

pub fn substitute_bytes(bytes: &[UInt8Gadget]) -> Result<Vec<UInt8Gadget>> {
    ensure!(
        bytes.len() == 16,
        "Input must be 16 bytes length when substituting bytes"
    );

    let substituted_bytes = bytes
        .iter()
        .map(substitute_byte)
        .collect::<Result<Vec<_>, _>>()?;

    ensure!(substituted_bytes.len() == 16, "Error substituting bytes");
    Ok(substituted_bytes)
}

pub fn shift_rows(bytes: &[UInt8Gadget]) -> Option<Vec<UInt8Gadget>> {
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
    // We shift each row, then return back the result as the flattened version.

    let first_row = [
        bytes.get(0)?.clone(),
        bytes.get(4)?.clone(),
        bytes.get(8)?.clone(),
        bytes.get(12)?.clone(),
    ];
    let mut second_row = [
        bytes.get(1)?.clone(),
        bytes.get(5)?.clone(),
        bytes.get(9)?.clone(),
        bytes.get(13)?.clone(),
    ];
    let mut third_row = [
        bytes.get(2)?.clone(),
        bytes.get(6)?.clone(),
        bytes.get(10)?.clone(),
        bytes.get(14)?.clone(),
    ];
    let mut fourth_row = [
        bytes.get(3)?.clone(),
        bytes.get(7)?.clone(),
        bytes.get(11)?.clone(),
        bytes.get(15)?.clone(),
    ];

    // TODO: this does not generate constraints, fix it.
    second_row.rotate_left(1);
    third_row.rotate_left(2);
    fourth_row.rotate_left(3);

    let result = vec![
        first_row.get(0)?.clone(),
        second_row.get(0)?.clone(),
        third_row.get(0)?.clone(),
        fourth_row.get(0)?.clone(),
        first_row.get(1)?.clone(),
        second_row.get(1)?.clone(),
        third_row.get(1)?.clone(),
        fourth_row.get(1)?.clone(),
        first_row.get(2)?.clone(),
        second_row.get(2)?.clone(),
        third_row.get(2)?.clone(),
        fourth_row.get(2)?.clone(),
        first_row.get(3)?.clone(),
        second_row.get(3)?.clone(),
        third_row.get(3)?.clone(),
        fourth_row.get(3)?.clone(),
    ];

    Some(result)
}

pub fn mix_columns(input: &[UInt8Gadget]) -> Option<Vec<UInt8Gadget>> {
    let mut mixed_input = UInt8Gadget::constant_vec(&[0_u8; 16]);
    for (i, column) in input.chunks(4).enumerate() {
        let column_aux = [
            column.first()?.clone(),
            column.get(1)?.clone(),
            column.get(2)?.clone(),
            column.get(3)?.clone(),
        ];
        let column_ret = gmix_column(&column_aux)?;

        *mixed_input.get_mut(i * 4)? = column_ret.first()?.clone();
        *mixed_input.get_mut(i * 4 + 1)? = column_ret.get(1)?.clone();
        *mixed_input.get_mut(i * 4 + 2)? = column_ret.get(2)?.clone();
        *mixed_input.get_mut(i * 4 + 3)? = column_ret.get(3)?.clone();
    }

    Some(mixed_input)
}

fn gmix_column(input: &[UInt8Gadget; 4]) -> Option<[UInt8Gadget; 4]> {
    let mut b: Vec<UInt8Gadget> = Vec::new();

    // TODO: Generate constraints for bit shifting.
    for c in input.iter() {
        let cs = c.cs();

        let primitive_c = c.value().ok()?;
        let primitive_h = (primitive_c >> 7_usize) & 1; // arithmetic right shift, thus shifting in either zeros or ones.
        let primitive_b_byte = (primitive_c << 1_usize) ^ (primitive_h * 0x1B); // implicitly removes high bit because b[c] is an 8-bit char, so we xor by 0x1b and not 0x11b in the next line.

        b.push(UInt8Gadget::new_witness(cs, || Ok(primitive_b_byte)).ok()?);
    }

    Some([
        b.first()?
            .xor(input.get(3)?)
            .ok()?
            .xor(input.get(2)?)
            .ok()?
            .xor(b.get(1)?)
            .ok()?
            .xor(input.get(1)?)
            .ok()?,
        b.get(1)?
            .xor(input.first()?)
            .ok()?
            .xor(input.get(3)?)
            .ok()?
            .xor(b.get(2)?)
            .ok()?
            .xor(input.get(2)?)
            .ok()?,
        b.get(2)?
            .xor(input.get(1)?)
            .ok()?
            .xor(input.first()?)
            .ok()?
            .xor(b.get(3)?)
            .ok()?
            .xor(input.get(3)?)
            .ok()?,
        b.get(3)?
            .xor(input.get(2)?)
            .ok()?
            .xor(input.get(1)?)
            .ok()?
            .xor(b.first()?)
            .ok()?
            .xor(input.first()?)
            .ok()?,
    ])
}
#[cfg(test)]
mod tests {
    use crate::aes_circuit;
    use ark_r1cs_std::{prelude::AllocVar, R1CSVar};
    use ark_relations::r1cs::ConstraintSystem;
    use simpleworks::gadgets::{ConstraintF, UInt8Gadget};

    #[test]
    fn test_one_round_add_round_key_circuit() {
        let cs = ConstraintSystem::<ConstraintF>::new_ref();
        let plaintext = UInt8Gadget::new_witness_vec(
            ark_relations::ns!(cs, "plaintext"),
            &[
                0x32, 0x43, 0xf6, 0xa8, 0x88, 0x5a, 0x30, 0x8d, 0x31, 0x31, 0x98, 0xa2, 0xe0, 0x37,
                0x07, 0x34,
            ],
        )
        .unwrap();
        let secret_key = UInt8Gadget::new_witness_vec(
            ark_relations::ns!(cs, "secret_key"),
            &[
                0x2b, 0x7e, 0x15, 0x16, 0x28, 0xae, 0xd2, 0xa6, 0xab, 0xf7, 0x15, 0x88, 0x09, 0xcf,
                0x4f, 0x3c,
            ],
        )
        .unwrap();
        let expected_primitive_result = [
            0x19, 0x3d, 0xe3, 0xbe, 0xa0, 0xf4, 0xe2, 0x2b, 0x9a, 0xc6, 0x8d, 0x2a, 0xe9, 0xf8,
            0x48, 0x08,
        ];

        let after_add_round_key = aes_circuit::add_round_key(&plaintext, &secret_key).unwrap();

        assert_eq!(
            after_add_round_key.value().unwrap(),
            expected_primitive_result
        );
        assert!(cs.is_satisfied().unwrap());
    }

    #[test]
    fn test_one_round_column_mix_circuit() {
        let cs = ConstraintSystem::<ConstraintF>::new_ref();
        let value_to_mix = UInt8Gadget::new_witness_vec(
            ark_relations::ns!(cs, "value_to_mix"),
            &[
                0xd4, 0xbf, 0x5d, 0x30, 0xe0, 0xb4, 0x52, 0xae, 0xb8, 0x41, 0x11, 0xf1, 0x1e, 0x27,
                0x98, 0xe5,
            ],
        )
        .unwrap();
        let expected_primitive_mixed_value: [u8; 16] = [
            0x04, 0x66, 0x81, 0xe5, 0xe0, 0xcb, 0x19, 0x9a, 0x48, 0xf8, 0xd3, 0x7a, 0x28, 0x06,
            0x26, 0x4c,
        ];

        let mixed_column_vector = aes_circuit::mix_columns(&value_to_mix).unwrap();

        assert_eq!(
            mixed_column_vector.value().unwrap(),
            expected_primitive_mixed_value
        );
        assert!(cs.is_satisfied().unwrap());
    }

    #[test]
    fn test_shift_rows() {
        let cs = ConstraintSystem::<ConstraintF>::new_ref();
        // Generate random 16 bytes, and then check
        // that the AES shifting works like expected.
        let mut value_to_shift = vec![];
        for _i in 0_i32..16_i32 {
            value_to_shift
                .push(UInt8Gadget::new_witness(cs.clone(), || Ok(rand::random::<u8>())).unwrap());
        }

        let expected: Vec<&UInt8Gadget> = vec![
            value_to_shift.get(0).unwrap(),
            value_to_shift.get(5).unwrap(),
            value_to_shift.get(10).unwrap(),
            value_to_shift.get(15).unwrap(),
            value_to_shift.get(4).unwrap(),
            value_to_shift.get(9).unwrap(),
            value_to_shift.get(14).unwrap(),
            value_to_shift.get(3).unwrap(),
            value_to_shift.get(8).unwrap(),
            value_to_shift.get(13).unwrap(),
            value_to_shift.get(2).unwrap(),
            value_to_shift.get(7).unwrap(),
            value_to_shift.get(12).unwrap(),
            value_to_shift.get(1).unwrap(),
            value_to_shift.get(6).unwrap(),
            value_to_shift.get(11).unwrap(),
        ];

        let res = aes_circuit::shift_rows(&value_to_shift);
        for (index, byte) in res.unwrap().iter().enumerate() {
            assert_eq!(byte.value(), expected.get(index).unwrap().value());
        }
        assert!(cs.is_satisfied().unwrap());
    }

    #[test]
    fn test_one_round_sub_bytes_circuit() {
        let cs = ConstraintSystem::<ConstraintF>::new_ref();
        let value_to_substitute = UInt8Gadget::new_witness_vec(
            ark_relations::ns!(cs, "value_to_mix"),
            &[
                0x19, 0x3d, 0xe3, 0xbe, 0xa0, 0xf4, 0xe2, 0x2b, 0x9a, 0xc6, 0x8d, 0x2a, 0xe9, 0xf8,
                0x48, 0x08,
            ],
        )
        .unwrap();

        let expected_primitive_substituted_value: [u8; 16] = [
            0xd4, 0x27, 0x11, 0xae, 0xe0, 0xbf, 0x98, 0xf1, 0xb8, 0xb4, 0x5d, 0xe5, 0x1e, 0x41,
            0x52, 0x30,
        ];

        let substituted_value = aes_circuit::substitute_bytes(&value_to_substitute).unwrap();

        assert_eq!(
            substituted_value.value().unwrap(),
            expected_primitive_substituted_value
        );
    }

    #[test]
    fn key_expansion() {
        let cs = ConstraintSystem::<ConstraintF>::new_ref();
        let secret_key = UInt8Gadget::new_witness_vec(
            cs,
            &[
                0x2b, 0x7e, 0x15, 0x16, 0x28, 0xae, 0xd2, 0xa6, 0xab, 0xf7, 0x15, 0x88, 0x09, 0xcf,
                0x4f, 0x3c,
            ],
        )
        .unwrap();
        let result = aes_circuit::derive_keys(&secret_key).unwrap();

        assert_eq!(
            result[10].value().unwrap(),
            [
                0xd0, 0x14, 0xf9, 0xa8, 0xc9, 0xee, 0x25, 0x89, 0xe1, 0x3f, 0x0c, 0xc8, 0xb6, 0x63,
                0x0c, 0xa6,
            ]
        );
    }
}
