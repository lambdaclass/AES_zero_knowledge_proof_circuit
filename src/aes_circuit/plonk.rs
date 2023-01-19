use crate::helpers;
use dusk_plonk::prelude::{BlsScalar, Circuit, Constraint, Witness};
use log::debug;

type PlonkError = dusk_plonk::prelude::Error;

/// This circuit shows that `ciphertext` is the result of encrypting `message` using AES with `secret_key` as the encryption key.
pub struct AESEncryptionCircuit {
    message: Vec<u8>,
    secret_key: [u8; 16],
    ciphertext: Vec<u8>,
}

/// R^2 = 2^512 mod q
const R2: BlsScalar = BlsScalar([
    0xc999e990f3f29c6d,
    0x2b6cedcb87925c23,
    0x05d314967254398f,
    0x0748d9d99f59ff11,
]);

fn bls_scalar_from_16_bytes(bytes: &[u8; 16]) -> Result<BlsScalar, PlonkError> {
    let mut new_bytes = [0_u64; 4];

    for (old_chunks, new_chunks) in bytes.chunks(8).zip(new_bytes.iter_mut()) {
        *new_chunks = u64::from_le_bytes(
            old_chunks
                .try_into()
                .map_err(|_e| PlonkError::BlsScalarMalformed)?,
        );
    }

    Ok(BlsScalar(new_bytes) * R2)
}

impl Circuit for AESEncryptionCircuit {
    fn circuit<C>(&self, composer: &mut C) -> Result<(), PlonkError>
    where
        C: dusk_plonk::prelude::Composer,
    {
        let message_bytes = self
            .message
            .iter()
            .map(|byte| composer.append_witness(BlsScalar::from(*byte as u64)))
            .collect::<Vec<_>>();
        let secret_key_bytes = self
            .secret_key
            .iter()
            .map(|byte| composer.append_witness(BlsScalar::from(*byte as u64)))
            .collect::<Vec<_>>();
        let ciphertext_bytes = self
            .ciphertext
            .iter()
            .map(|byte| composer.append_public(BlsScalar::from(*byte as u64)))
            .collect::<Vec<_>>();

        // Lookup table

        // Key derivation
        let round_keys: [[Witness; 16]; 11] = Self::derive_keys(&secret_key_bytes, composer)?;

        //TODO: At the moment we are doing one block encryption. We should do multiple blocks.
        // Add round 0 key
        let mut after_add_round_key =
            Self::add_round_key(&message_bytes, &round_keys[0], composer)?;
        // 10-round AES encryption (we skip the first one because we already added in round 0)
        for (round_number, round_key) in round_keys.iter().enumerate().skip(1) {
            // SubBytes
            let after_sub_bytes = Self::sub_bytes(&after_add_round_key, composer)?;

            // ShiftRows
            let after_shift_rows = Self::shift_rows(&after_sub_bytes, composer)?;

            // MixColumns
            let condition = composer.append_witness(BlsScalar::from(
                (round_number == 10).try_into().unwrap_or(0_u64),
            ));
            // FIXME: Do we need to enforce this?
            composer.component_boolean(condition);
            let true_value = after_shift_rows.clone();
            let false_value = Self::mix_columns(&after_shift_rows, composer)?;
            let after_mix_columns = true_value
                .into_iter()
                .zip(false_value)
                .map(|(true_value_byte, false_value_byte)| {
                    composer.component_select(condition, true_value_byte, false_value_byte)
                })
                .collect::<Vec<Witness>>();

            // AddRoundKey
            after_add_round_key = Self::add_round_key(&after_mix_columns, round_key, composer)?;
        }

        let computed_ciphertext = after_add_round_key;
        // Enforce that the ciphertext is the result of the encryption
        ciphertext_bytes.iter().zip(computed_ciphertext).for_each(
            |(ciphertext_byte, computed_ciphertext_byte)| {
                composer.assert_equal(*ciphertext_byte, computed_ciphertext_byte);
            },
        );

        Ok(())
    }
}

impl Default for AESEncryptionCircuit {
    fn default() -> Self {
        let mut message = [0_u8; 64];
        message.copy_from_slice(&helpers::sample_message(64));

        let key: [u8; 16] = rand::random();

        let mut ciphertext = [0_u8; 64];
        ciphertext.copy_from_slice(&helpers::primitive_encrypt(&message, &key));

        Self {
            message: message.to_vec(),
            secret_key: key,
            ciphertext: ciphertext.to_vec(),
        }
    }
}

impl AESEncryptionCircuit {
    fn add_round_key<C>(
        input: &[Witness],
        round_key: &[Witness],
        composer: &mut C,
    ) -> Result<Vec<Witness>, PlonkError>
    where
        C: dusk_plonk::prelude::Composer,
    {
        Ok(input
            .iter()
            .zip(round_key)
            .map(|(input_byte, round_key_byte)| {
                composer.append_logic_xor(*input_byte, *round_key_byte, 8)
            })
            .collect::<Vec<Witness>>())
    }

    fn sub_bytes<C>(input: &[Witness], composer: &mut C) -> Result<Vec<Witness>, PlonkError>
    where
        C: dusk_plonk::prelude::Composer,
    {
        let output: Vec<Witness>;
        todo!()
    }

    fn shift_rows<C>(input: &[Witness], composer: &mut C) -> Result<Vec<Witness>, PlonkError>
    where
        C: dusk_plonk::prelude::Composer,
    {
        debug!(
            "Constraints before shifting rows {}",
            composer.constraints()
        );

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

        let first_row = [input[0], input[4], input[8], input[12]];
        let second_row = [input[1], input[5], input[9], input[13]];
        let third_row = [input[2], input[6], input[10], input[14]];
        let fourth_row = [input[3], input[7], input[11], input[15]];

        let rotated_second_row = rotate_left(&second_row, 1, composer);
        let rotated_third_row = rotate_left(&third_row, 2, composer);
        let rotated_fourth_row = rotate_left(&fourth_row, 3, composer);

        let output = vec![
            first_row[0],
            rotated_second_row[0],
            rotated_third_row[0],
            rotated_fourth_row[0],
            first_row[1],
            rotated_second_row[1],
            rotated_third_row[1],
            rotated_fourth_row[1],
            first_row[2],
            rotated_second_row[2],
            rotated_third_row[2],
            rotated_fourth_row[2],
            first_row[3],
            rotated_second_row[3],
            rotated_third_row[3],
            rotated_fourth_row[3],
        ];

        debug!("Constraints after shifting rows {}", composer.constraints());

        Ok(output)
    }

    fn mix_columns<C>(input: &[Witness], composer: &mut C) -> Result<Vec<Witness>, PlonkError>
    where
        C: dusk_plonk::prelude::Composer,
    {
        debug!(
            "Constraints before mixing columns {}",
            composer.constraints()
        );

        let mut mixed_input: Vec<Witness> = (0..input.len())
            .into_iter()
            .map(|_| composer.append_constant(BlsScalar::zero()))
            .collect();
        for (i, column) in input.chunks(4).enumerate() {
            let column_ret = Self::gmix_column(column, composer)?;

            mixed_input[i * 4] = column_ret[0];
            mixed_input[i * 4 + 1] = column_ret[1];
            mixed_input[i * 4 + 2] = column_ret[2];
            mixed_input[i * 4 + 3] = column_ret[3];
        }

        debug!(
            "Constraints after mixing columns {}",
            composer.constraints()
        );

        Ok(mixed_input)
    }

    fn gmix_column<C>(input: &[Witness], composer: &mut C) -> Result<Vec<Witness>, PlonkError>
    where
        C: dusk_plonk::prelude::Composer,
    {
        let mut b: Vec<Witness> = Vec::with_capacity(input.len());
        /* The array 'a' is simply a copy of the input array 'r'
         * The array 'b' is each element of the array 'a' multiplied by 2
         * in Rijndael's Galois field
         * a[n] ^ b[n] is element n multiplied by 3 in Rijndael's Galois field */

        let a_hundred_and_twenty_eight = composer.append_constant(BlsScalar::from(0x80_u8 as u64));
        let two = composer.append_constant(BlsScalar::from(0x02_u8 as u64));
        let galois_adjustment = composer.append_constant(BlsScalar::from(0x1B_u8 as u64));
        for c in input.iter() {
            // c & 0x80
            let overflowed = composer.append_logic_and(*c, a_hundred_and_twenty_eight, 8); /* arithmetic right shift, thus shifting in either zeros or ones */
            // (c & 0x80) * 0x1B
            let galois_adjustment_to_apply =
                composer.gate_mul(Constraint::new().mult(1).a(overflowed).b(galois_adjustment));
            // c * 0x02
            let c_times_two = composer.gate_mul(Constraint::new().mult(1).a(*c).b(two));
            // (c & 0x80) * 0x1B ^ c * 0x02
            let b_i = composer.append_logic_xor(galois_adjustment_to_apply, c_times_two, 8);
            b.push(b_i); /* implicitly removes high bit because b[c] is an 8-bit char, so we xor by 0x1b and not 0x11b in the next line */
            /* Rijndael's Galois field */
        }

        Ok(vec![
            kary_xor(&[b[0], input[3], input[2], b[1], input[1]], composer)?,
            kary_xor(&[b[1], input[0], input[3], b[2], input[2]], composer)?,
            kary_xor(&[b[2], input[1], input[0], b[3], input[3]], composer)?,
            kary_xor(&[b[3], input[2], input[1], b[0], input[0]], composer)?,
        ])
    }

    fn derive_keys<C>(
        secret_key: &[Witness],
        composer: &mut C,
    ) -> Result<[[Witness; 16]; 11], PlonkError>
    where
        C: dusk_plonk::prelude::Composer,
    {
        let keys: [[Witness; 16]; 11];
        todo!()
    }
}

fn rotate_left<C>(input: &[Witness], positions: usize, composer: &mut C) -> Vec<Witness>
where
    C: dusk_plonk::prelude::Composer,
{
    let input_len = input.len();
    let mut output = input.to_vec();
    output.rotate_left(positions);

    for i in 0..input_len {
        composer.assert_equal(input[i], output[(i + positions) % input_len])
    }

    output.to_vec()
}

fn kary_xor<C>(input: &[Witness], composer: &mut C) -> Result<Witness, PlonkError>
where
    C: dusk_plonk::prelude::Composer,
{
    let mut output = composer.append_constant(BlsScalar::zero());
    for i in 0..input.len() {
        output = composer.append_logic_xor(output, input[i], 8);
    }

    Ok(output)
}

#[cfg(test)]
mod tests {
    use dusk_plonk::prelude::{BlsScalar, Builder, Composer, Witness};

    use super::AESEncryptionCircuit;

    fn to_witness_vec<C>(input: &[u8], composer: &mut C) -> Vec<Witness>
    where
        C: dusk_plonk::prelude::Composer,
    {
        input
            .iter()
            .map(|byte| composer.append_witness(BlsScalar::from(*byte as u64)))
            .collect()
    }

    fn from_witness_vec<C>(input: &[Witness], composer: &mut C) -> Vec<BlsScalar>
    where
        C: dusk_plonk::prelude::Composer,
    {
        input.into_iter().map(|w| composer[*w]).collect()
    }

    #[test]
    fn test_add_round_key() {
        let mut composer = Builder::uninitialized(100);

        let message: Vec<Witness> = to_witness_vec(
            &[
                0x32, 0x43, 0xf6, 0xa8, 0x88, 0x5a, 0x30, 0x8d, 0x31, 0x31, 0x98, 0xa2, 0xe0, 0x37,
                0x07, 0x34,
            ],
            &mut composer,
        );

        let expected_after_add_round_key = to_witness_vec(
            &[
                0x19, 0x3d, 0xe3, 0xbe, 0xa0, 0xf4, 0xe2, 0x2b, 0x9a, 0xc6, 0x8d, 0x2a, 0xe9, 0xf8,
                0x48, 0x08,
            ],
            &mut composer,
        );

        let round_key: Vec<Witness> = to_witness_vec(
            &[
                0x2b, 0x7e, 0x15, 0x16, 0x28, 0xae, 0xd2, 0xa6, 0xab, 0xf7, 0x15, 0x88, 0x09, 0xcf,
                0x4f, 0x3c,
            ],
            &mut composer,
        );

        let after_add_round_key =
            AESEncryptionCircuit::add_round_key(&message, &round_key, &mut composer).unwrap();

        assert_eq!(
            from_witness_vec(&after_add_round_key, &mut composer),
            from_witness_vec(&expected_after_add_round_key, &mut composer)
        );
    }

    #[test]
    #[ignore = "unimplemented"]
    fn test_substitute_bytes() {
        let mut composer = Builder::uninitialized(100);

        let message = to_witness_vec(
            &[
                0x19, 0x3d, 0xe3, 0xbe, 0xa0, 0xf4, 0xe2, 0x2b, 0x9a, 0xc6, 0x8d, 0x2a, 0xe9, 0xf8,
                0x48, 0x08,
            ],
            &mut composer,
        );

        let expected_after_substitute_bytes = to_witness_vec(
            &[
                0xd4, 0x27, 0x11, 0xae, 0xe0, 0xbf, 0x98, 0xf1, 0xb8, 0xb4, 0x5d, 0xe5, 0x1e, 0x41,
                0x52, 0x30,
            ],
            &mut composer,
        );

        let after_substitute_bytes =
            AESEncryptionCircuit::sub_bytes(&message, &mut composer).unwrap();

        assert_eq!(
            from_witness_vec(&after_substitute_bytes, &mut composer),
            from_witness_vec(&expected_after_substitute_bytes, &mut composer)
        );
    }

    #[test]
    fn test_shift_rows() {
        let mut composer = Builder::uninitialized(100);

        let message: Vec<Witness> = to_witness_vec(
            &[
                0xd4, 0x27, 0x11, 0xae, 0xe0, 0xbf, 0x98, 0xf1, 0xb8, 0xb4, 0x5d, 0xe5, 0x1e, 0x41,
                0x52, 0x30,
            ],
            &mut composer,
        );

        let expected_after_shift_rows = to_witness_vec(
            &[
                0xd4, 0xbf, 0x5d, 0x30, 0xe0, 0xb4, 0x52, 0xae, 0xb8, 0x41, 0x11, 0xf1, 0x1e, 0x27,
                0x98, 0xe5,
            ],
            &mut composer,
        );

        let after_shift_rows = AESEncryptionCircuit::shift_rows(&message, &mut composer).unwrap();

        assert_eq!(
            from_witness_vec(&after_shift_rows, &mut composer),
            from_witness_vec(&expected_after_shift_rows, &mut composer)
        );
    }

    #[test]
    fn test_mix_columns() {
        let mut composer = Builder::uninitialized(100);

        let message: Vec<Witness> = to_witness_vec(
            &[
                0xd4, 0xbf, 0x5d, 0x30, 0xe0, 0xb4, 0x52, 0xae, 0xb8, 0x41, 0x11, 0xf1, 0x1e, 0x27,
                0x98, 0xe5,
            ],
            &mut composer,
        );

        let expected_after_mix_columns: Vec<Witness> = to_witness_vec(
            &[
                0x04, 0x66, 0x81, 0xe5, 0xe0, 0xcb, 0x19, 0x9a, 0x48, 0xf8, 0xd3, 0x7a, 0x28, 0x06,
                0x26, 0x4c,
            ],
            &mut composer,
        );

        let mixed_columns = AESEncryptionCircuit::mix_columns(&message, &mut composer).unwrap();

        assert_eq!(
            from_witness_vec(&mixed_columns, &mut composer),
            from_witness_vec(&expected_after_mix_columns, &mut composer),
        );
    }
}
