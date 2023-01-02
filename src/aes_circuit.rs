use crate::helpers::traits::ToAnyhow;
use anyhow::{ensure, Result};
use ark_r1cs_std::{prelude::AllocVar, R1CSVar};
use simpleworks::gadgets::UInt8Gadget;

pub fn derive_keys(secret_key: &[UInt8Gadget]) -> Result<[&[UInt8Gadget]; 11]> {
    // TODO: implement this
    let ret = [
        secret_key, secret_key, secret_key, secret_key, secret_key, secret_key, secret_key,
        secret_key, secret_key, secret_key, secret_key,
    ];

    Ok(ret)
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
fn rotate_left(byte: UInt8Gadget, n: u8) -> Result<UInt8Gadget> {
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
fn substitute_byte(byte: UInt8Gadget) -> Result<UInt8Gadget> {
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
            .xor(&rotate_left(q.clone(), 1)?)?
            .xor(&rotate_left(q.clone(), 2)?)?
            .xor(&rotate_left(q.clone(), 3)?)?
            .xor(&rotate_left(q.clone(), 4)?)?;

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

pub fn substitute_bytes(bytes: &[UInt8Gadget]) -> Result<&[UInt8Gadget]> {
    ensure!(
        bytes.len() == 16,
        "Input must be 16 bytes length when substituting bytes"
    );

    let substituted_bytes = bytes
        .iter()
        .map(|byte| substitute_byte(byte.clone()))
        .collect::<Result<Vec<_>, _>>()?;

    ensure!(substituted_bytes.len() == 16, "Error substituting bytes");
    Ok(bytes)
}

pub fn shift_rows(bytes: &[UInt8Gadget]) -> Result<&[UInt8Gadget]> {
    // TODO: implement this
    Ok(bytes)
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
    use ark_r1cs_std::R1CSVar;
    use ark_relations::r1cs::ConstraintSystem;
    use simpleworks::gadgets::{ConstraintF, UInt8Gadget};

    #[test]
    fn test_add_round_key_circuit() {
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
}
