use crate::helpers;
use anyhow::Result;
use dusk_plonk::prelude::{BlsScalar, Circuit, Constraint, Witness};
use log::debug;

type PlonkError = dusk_plonk::prelude::Error;

/// This circuit shows that `ciphertext` is the result of encrypting `message` using AES with `secret_key` as the encryption key.
pub struct AESEncryptionCircuit {
    message: Vec<u8>,
    secret_key: [u8; 16],
    ciphertext: Vec<u8>,
}

impl Circuit for AESEncryptionCircuit {
    fn circuit<C>(&self, composer: &mut C) -> Result<(), PlonkError>
    where
        C: dusk_plonk::prelude::Composer,
    {
        let message_bytes = to_witness_vec(&self.message, composer);
        let secret_key_bytes = to_witness_vec(&self.secret_key, composer);
        let ciphertext_bytes = to_public_vec(&self.ciphertext, composer);

        // Lookup table
        let substitution_table = Self::substitution_table(composer);

        // Key derivation
        let round_keys: [[Witness; 16]; 11] =
            Self::key_expansion(&secret_key_bytes, &substitution_table, composer)?;


        let mut computed_ciphertext: Vec<Witness> = Vec::new();
        for block in message_bytes.chunks(16) {
            let mut after_add_round_key = Self::add_round_key(block, &round_keys[0], composer);
            // 10-round AES encryption (we skip the first one because we already added in round 0)
            for (round_number, round_key) in round_keys.iter().enumerate().skip(1) {
                // SubBytes
                let after_sub_bytes =
                    Self::sub_bytes(&after_add_round_key, &substitution_table, composer)?;

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
                after_add_round_key = Self::add_round_key(&after_mix_columns, round_key, composer);

                computed_ciphertext.extend_from_slice(&after_add_round_key);
            }
        }
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
    fn add_round_key<C>(input: &[Witness], round_key: &[Witness], composer: &mut C) -> Vec<Witness>
    where
        C: dusk_plonk::prelude::Composer,
    {
        input
            .iter()
            .zip(round_key)
            .map(|(input_byte, round_key_byte)| {
                composer.append_logic_xor(*input_byte, *round_key_byte, 8)
            })
            .collect::<Vec<Witness>>()
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

        let first_row = [
            *input.get(0).ok_or(PlonkError::NotEnoughBytes)?,
            *input.get(4).ok_or(PlonkError::NotEnoughBytes)?,
            *input.get(8).ok_or(PlonkError::NotEnoughBytes)?,
            *input.get(12).ok_or(PlonkError::NotEnoughBytes)?,
        ];
        let second_row = [
            *input.get(1).ok_or(PlonkError::NotEnoughBytes)?,
            *input.get(5).ok_or(PlonkError::NotEnoughBytes)?,
            *input.get(9).ok_or(PlonkError::NotEnoughBytes)?,
            *input.get(13).ok_or(PlonkError::NotEnoughBytes)?,
        ];
        let third_row = [
            *input.get(2).ok_or(PlonkError::NotEnoughBytes)?,
            *input.get(6).ok_or(PlonkError::NotEnoughBytes)?,
            *input.get(10).ok_or(PlonkError::NotEnoughBytes)?,
            *input.get(14).ok_or(PlonkError::NotEnoughBytes)?,
        ];
        let fourth_row = [
            *input.get(3).ok_or(PlonkError::NotEnoughBytes)?,
            *input.get(7).ok_or(PlonkError::NotEnoughBytes)?,
            *input.get(11).ok_or(PlonkError::NotEnoughBytes)?,
            *input.get(15).ok_or(PlonkError::NotEnoughBytes)?,
        ];

        let rotated_second_row = rotate_left(&second_row, 1, composer)?;
        let rotated_third_row = rotate_left(&third_row, 2, composer)?;
        let rotated_fourth_row = rotate_left(&fourth_row, 3, composer)?;

        let output = vec![
            *first_row.get(0).ok_or(PlonkError::NotEnoughBytes)?,
            *rotated_second_row
                .get(0)
                .ok_or(PlonkError::NotEnoughBytes)?,
            *rotated_third_row.get(0).ok_or(PlonkError::NotEnoughBytes)?,
            *rotated_fourth_row
                .get(0)
                .ok_or(PlonkError::NotEnoughBytes)?,
            *first_row.get(1).ok_or(PlonkError::NotEnoughBytes)?,
            *rotated_second_row
                .get(1)
                .ok_or(PlonkError::NotEnoughBytes)?,
            *rotated_third_row.get(1).ok_or(PlonkError::NotEnoughBytes)?,
            *rotated_fourth_row
                .get(1)
                .ok_or(PlonkError::NotEnoughBytes)?,
            *first_row.get(2).ok_or(PlonkError::NotEnoughBytes)?,
            *rotated_second_row
                .get(2)
                .ok_or(PlonkError::NotEnoughBytes)?,
            *rotated_third_row.get(2).ok_or(PlonkError::NotEnoughBytes)?,
            *rotated_fourth_row
                .get(2)
                .ok_or(PlonkError::NotEnoughBytes)?,
            *first_row.get(3).ok_or(PlonkError::NotEnoughBytes)?,
            *rotated_second_row
                .get(3)
                .ok_or(PlonkError::NotEnoughBytes)?,
            *rotated_third_row.get(3).ok_or(PlonkError::NotEnoughBytes)?,
            *rotated_fourth_row
                .get(3)
                .ok_or(PlonkError::NotEnoughBytes)?,
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

            *mixed_input
                .get_mut(i * 4)
                .ok_or(PlonkError::NotEnoughBytes)? =
                *column_ret.get(0).ok_or(PlonkError::NotEnoughBytes)?;
            *mixed_input
                .get_mut(i * 4 + 1)
                .ok_or(PlonkError::NotEnoughBytes)? =
                *column_ret.get(1).ok_or(PlonkError::NotEnoughBytes)?;
            *mixed_input
                .get_mut(i * 4 + 2)
                .ok_or(PlonkError::NotEnoughBytes)? =
                *column_ret.get(2).ok_or(PlonkError::NotEnoughBytes)?;
            *mixed_input
                .get_mut(i * 4 + 3)
                .ok_or(PlonkError::NotEnoughBytes)? =
                *column_ret.get(3).ok_or(PlonkError::NotEnoughBytes)?;
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

        let two_to_the_seventh = composer.append_constant(BlsScalar::from(0x80_u64));
        let two_to_the_eighth = composer.append_constant(BlsScalar::from(0x100_u64));
        let two = composer.append_constant(BlsScalar::from(0x02_u64));
        let galois_adjustment = composer.append_constant(BlsScalar::from(0x11B_u64));
        for c in input.iter() {
            // c & 0x80
            let msb_is_one = composer.append_logic_and(*c, two_to_the_seventh, 8);
            // c & 0x80 == 0x80
            let overflowed = gate_eq(msb_is_one, two_to_the_seventh, composer)?;
            // c << 1
            let c_shifted = {
                let c_times_two = composer.gate_mul(Constraint::new().mult(1).a(*c).b(two));
                composer.append_logic_xor(c_times_two, two_to_the_eighth, 16)
            };
            // (c << 1) * 0x1B
            let adjusted = composer.append_logic_xor(galois_adjustment, c_shifted, 8);
            // if overflowed then (c << 1) * 0x1B else c << 1
            let b_i = composer.component_select(overflowed, adjusted, c_shifted);
            b.push(b_i); /* implicitly removes high bit because b[c] is an 8-bit char, so we xor by 0x1b and not 0x11b in the next line */
            /* Rijndael's Galois field */
        }

        Ok(vec![
            kary_xor(
                &[
                    *b.get(0).ok_or(PlonkError::NotEnoughBytes)?,
                    *input.get(3).ok_or(PlonkError::NotEnoughBytes)?,
                    *input.get(2).ok_or(PlonkError::NotEnoughBytes)?,
                    *b.get(1).ok_or(PlonkError::NotEnoughBytes)?,
                    *input.get(1).ok_or(PlonkError::NotEnoughBytes)?,
                ],
                composer,
            ),
            kary_xor(
                &[
                    *b.get(1).ok_or(PlonkError::NotEnoughBytes)?,
                    *input.get(0).ok_or(PlonkError::NotEnoughBytes)?,
                    *input.get(3).ok_or(PlonkError::NotEnoughBytes)?,
                    *b.get(2).ok_or(PlonkError::NotEnoughBytes)?,
                    *input.get(2).ok_or(PlonkError::NotEnoughBytes)?,
                ],
                composer,
            ),
            kary_xor(
                &[
                    *b.get(2).ok_or(PlonkError::NotEnoughBytes)?,
                    *input.get(1).ok_or(PlonkError::NotEnoughBytes)?,
                    *input.get(0).ok_or(PlonkError::NotEnoughBytes)?,
                    *b.get(3).ok_or(PlonkError::NotEnoughBytes)?,
                    *input.get(3).ok_or(PlonkError::NotEnoughBytes)?,
                ],
                composer,
            ),
            kary_xor(
                &[
                    *b.get(3).ok_or(PlonkError::NotEnoughBytes)?,
                    *input.get(2).ok_or(PlonkError::NotEnoughBytes)?,
                    *input.get(1).ok_or(PlonkError::NotEnoughBytes)?,
                    *b.get(0).ok_or(PlonkError::NotEnoughBytes)?,
                    *input.get(0).ok_or(PlonkError::NotEnoughBytes)?,
                ],
                composer,
            ),
        ])
    }

    fn key_expansion<C>(
        secret_key: &[Witness],
        substitution_table: &[Witness],
        composer: &mut C,
    ) -> Result<[[Witness; 16]; 11], PlonkError>
    where
        C: dusk_plonk::prelude::Composer,
    {
        let zero = composer.append_constant(BlsScalar::zero());
        let two_to_the_power_of_zero =
            composer.append_constant(BlsScalar::from(u64::from(0x01_u8)));
        let two_to_the_power_of_one = composer.append_constant(BlsScalar::from(u64::from(0x02_u8)));
        let two_to_the_power_of_two = composer.append_constant(BlsScalar::from(u64::from(0x04_u8)));
        let two_to_the_power_of_three =
            composer.append_constant(BlsScalar::from(u64::from(0x08_u8)));
        let two_to_the_power_of_four =
            composer.append_constant(BlsScalar::from(u64::from(0x10_u8)));
        let two_to_the_power_of_five =
            composer.append_constant(BlsScalar::from(u64::from(0x20_u8)));
        let two_to_the_power_of_six = composer.append_constant(BlsScalar::from(u64::from(0x40_u8)));
        let two_to_the_power_of_seven =
            composer.append_constant(BlsScalar::from(u64::from(0x80_u8)));
        let adjustment = composer.append_constant(BlsScalar::from(u64::from(0x1B_u8)));
        let fifty_four = composer.append_constant(BlsScalar::from(u64::from(0x36_u8)));

        let round_constants: [[Witness; 4]; 10] = [
            [two_to_the_power_of_zero, zero, zero, zero],
            [two_to_the_power_of_one, zero, zero, zero],
            [two_to_the_power_of_two, zero, zero, zero],
            [two_to_the_power_of_three, zero, zero, zero],
            [two_to_the_power_of_four, zero, zero, zero],
            [two_to_the_power_of_five, zero, zero, zero],
            [two_to_the_power_of_six, zero, zero, zero],
            [two_to_the_power_of_seven, zero, zero, zero],
            [adjustment, zero, zero, zero],
            [fifty_four, zero, zero, zero],
        ];

        let mut result: [[Witness; 4]; 44] = [constant_vec(4, composer)
            .try_into()
            .map_err(|_e| PlonkError::BlsScalarMalformed)?;
            44];

        result[0].clone_from_slice(secret_key.get(0..4).ok_or(PlonkError::NotEnoughBytes)?);
        result[1].clone_from_slice(secret_key.get(4..8).ok_or(PlonkError::NotEnoughBytes)?);
        result[2].clone_from_slice(secret_key.get(8..12).ok_or(PlonkError::NotEnoughBytes)?);
        result[3].clone_from_slice(secret_key.get(12..16).ok_or(PlonkError::NotEnoughBytes)?);

        for i in 4..44 {
            if i % 4 == 0 {
                let rotated = rotate_left(
                    result.get(i - 1).ok_or(PlonkError::NotEnoughBytes)?,
                    1,
                    composer,
                )?;
                let rotated_and_substituted =
                    Self::sub_bytes(&rotated, substitution_table, composer)?;

                let mut xor = Vec::with_capacity(4);
                for ((a, b), c) in result
                    .get(i - 4)
                    .ok_or(PlonkError::NotEnoughBytes)?
                    .iter()
                    .zip(rotated_and_substituted)
                    .zip(
                        round_constants
                            .get(i / 4 - 1)
                            .ok_or(PlonkError::NotEnoughBytes)?,
                    )
                {
                    xor.push(kary_xor(&[*a, b, *c], composer));
                }

                result
                    .get_mut(i)
                    .ok_or(PlonkError::NotEnoughBytes)?
                    .clone_from_slice(&xor);
            } else {
                let mut xor = Vec::with_capacity(4);
                for (a, b) in result
                    .get(i - 4)
                    .ok_or(PlonkError::NotEnoughBytes)?
                    .iter()
                    .zip(result.get(i - 1).ok_or(PlonkError::NotEnoughBytes)?.iter())
                {
                    xor.push(composer.append_logic_xor(*a, *b, 8));
                }

                result
                    .get_mut(i)
                    .ok_or(PlonkError::NotEnoughBytes)?
                    .clone_from_slice(&xor);
            }
        }

        let mut derived_keys: [[Witness; 16]; 11] = [constant_vec(16, composer)
            .try_into()
            .map_err(|_e| PlonkError::BlsScalarMalformed)?;
            11];

        for (round_key, expansion_result) in derived_keys.iter_mut().zip(result.chunks(4)) {
            let flattened_b = expansion_result
                .iter()
                .copied()
                .flatten()
                .collect::<Vec<_>>();
            round_key.clone_from_slice(flattened_b.as_slice());
        }

        Ok(derived_keys)
    }

    // I allow this clippy lint here because there is no way of using .get() or
    // .get_mut() in the composer.
    #[allow(clippy::indexing_slicing)]
    fn sub_bytes<C>(
        input: &[Witness],
        substitution_table: &[Witness],
        composer: &mut C,
    ) -> Result<Vec<Witness>, PlonkError>
    where
        C: dusk_plonk::prelude::Composer,
    {
        let mut substituted_bytes: Vec<Witness> = vec![];
        for byte in input {
            let byte_in_bits: Vec<Witness> = composer[*byte]
                .to_bits()
                .iter()
                .rev()
                .skip(256 - 8)
                .map(|bit| composer.append_witness(BlsScalar::from(u64::from(*bit))))
                .collect();
            substituted_bytes.push(Self::substitute_byte(
                &byte_in_bits,
                substitution_table,
                composer,
            )?);
        }

        Ok(substituted_bytes)
    }

    // I'm doing it this way because if instead I did something like
    // vec![...] there would be a huge stack allocation that, among other things,
    // would make compilation (yes, compilation) incredibly slow.
    #[allow(clippy::vec_init_then_push)]
    fn substitution_table<C>(composer: &mut C) -> Vec<Witness>
    where
        C: dusk_plonk::prelude::Composer,
    {
        let mut substitution_table = vec![];

        substitution_table.push(composer.append_constant(BlsScalar::from(0x63_u64)));
        substitution_table.push(composer.append_constant(BlsScalar::from(0x7C_u64)));
        substitution_table.push(composer.append_constant(BlsScalar::from(0x77_u64)));
        substitution_table.push(composer.append_constant(BlsScalar::from(0x7B_u64)));
        substitution_table.push(composer.append_constant(BlsScalar::from(0xF2_u64)));
        substitution_table.push(composer.append_constant(BlsScalar::from(0x6B_u64)));
        substitution_table.push(composer.append_constant(BlsScalar::from(0x6F_u64)));
        substitution_table.push(composer.append_constant(BlsScalar::from(0xC5_u64)));
        substitution_table.push(composer.append_constant(BlsScalar::from(0x30_u64)));
        substitution_table.push(composer.append_constant(BlsScalar::from(0x01_u64)));
        substitution_table.push(composer.append_constant(BlsScalar::from(0x67_u64)));
        substitution_table.push(composer.append_constant(BlsScalar::from(0x2B_u64)));
        substitution_table.push(composer.append_constant(BlsScalar::from(0xFE_u64)));
        substitution_table.push(composer.append_constant(BlsScalar::from(0xD7_u64)));
        substitution_table.push(composer.append_constant(BlsScalar::from(0xAB_u64)));
        substitution_table.push(composer.append_constant(BlsScalar::from(0x76_u64)));
        substitution_table.push(composer.append_constant(BlsScalar::from(0xCA_u64)));
        substitution_table.push(composer.append_constant(BlsScalar::from(0x82_u64)));
        substitution_table.push(composer.append_constant(BlsScalar::from(0xC9_u64)));
        substitution_table.push(composer.append_constant(BlsScalar::from(0x7D_u64)));
        substitution_table.push(composer.append_constant(BlsScalar::from(0xFA_u64)));
        substitution_table.push(composer.append_constant(BlsScalar::from(0x59_u64)));
        substitution_table.push(composer.append_constant(BlsScalar::from(0x47_u64)));
        substitution_table.push(composer.append_constant(BlsScalar::from(0xF0_u64)));
        substitution_table.push(composer.append_constant(BlsScalar::from(0xAD_u64)));
        substitution_table.push(composer.append_constant(BlsScalar::from(0xD4_u64)));
        substitution_table.push(composer.append_constant(BlsScalar::from(0xA2_u64)));
        substitution_table.push(composer.append_constant(BlsScalar::from(0xAF_u64)));
        substitution_table.push(composer.append_constant(BlsScalar::from(0x9C_u64)));
        substitution_table.push(composer.append_constant(BlsScalar::from(0xA4_u64)));
        substitution_table.push(composer.append_constant(BlsScalar::from(0x72_u64)));
        substitution_table.push(composer.append_constant(BlsScalar::from(0xC0_u64)));
        substitution_table.push(composer.append_constant(BlsScalar::from(0xB7_u64)));
        substitution_table.push(composer.append_constant(BlsScalar::from(0xFD_u64)));
        substitution_table.push(composer.append_constant(BlsScalar::from(0x93_u64)));
        substitution_table.push(composer.append_constant(BlsScalar::from(0x26_u64)));
        substitution_table.push(composer.append_constant(BlsScalar::from(0x36_u64)));
        substitution_table.push(composer.append_constant(BlsScalar::from(0x3F_u64)));
        substitution_table.push(composer.append_constant(BlsScalar::from(0xF7_u64)));
        substitution_table.push(composer.append_constant(BlsScalar::from(0xCC_u64)));
        substitution_table.push(composer.append_constant(BlsScalar::from(0x34_u64)));
        substitution_table.push(composer.append_constant(BlsScalar::from(0xA5_u64)));
        substitution_table.push(composer.append_constant(BlsScalar::from(0xE5_u64)));
        substitution_table.push(composer.append_constant(BlsScalar::from(0xF1_u64)));
        substitution_table.push(composer.append_constant(BlsScalar::from(0x71_u64)));
        substitution_table.push(composer.append_constant(BlsScalar::from(0xD8_u64)));
        substitution_table.push(composer.append_constant(BlsScalar::from(0x31_u64)));
        substitution_table.push(composer.append_constant(BlsScalar::from(0x15_u64)));
        substitution_table.push(composer.append_constant(BlsScalar::from(0x04_u64)));
        substitution_table.push(composer.append_constant(BlsScalar::from(0xC7_u64)));
        substitution_table.push(composer.append_constant(BlsScalar::from(0x23_u64)));
        substitution_table.push(composer.append_constant(BlsScalar::from(0xC3_u64)));
        substitution_table.push(composer.append_constant(BlsScalar::from(0x18_u64)));
        substitution_table.push(composer.append_constant(BlsScalar::from(0x96_u64)));
        substitution_table.push(composer.append_constant(BlsScalar::from(0x05_u64)));
        substitution_table.push(composer.append_constant(BlsScalar::from(0x9A_u64)));
        substitution_table.push(composer.append_constant(BlsScalar::from(0x07_u64)));
        substitution_table.push(composer.append_constant(BlsScalar::from(0x12_u64)));
        substitution_table.push(composer.append_constant(BlsScalar::from(0x80_u64)));
        substitution_table.push(composer.append_constant(BlsScalar::from(0xE2_u64)));
        substitution_table.push(composer.append_constant(BlsScalar::from(0xEB_u64)));
        substitution_table.push(composer.append_constant(BlsScalar::from(0x27_u64)));
        substitution_table.push(composer.append_constant(BlsScalar::from(0xB2_u64)));
        substitution_table.push(composer.append_constant(BlsScalar::from(0x75_u64)));
        substitution_table.push(composer.append_constant(BlsScalar::from(0x09_u64)));
        substitution_table.push(composer.append_constant(BlsScalar::from(0x83_u64)));
        substitution_table.push(composer.append_constant(BlsScalar::from(0x2C_u64)));
        substitution_table.push(composer.append_constant(BlsScalar::from(0x1A_u64)));
        substitution_table.push(composer.append_constant(BlsScalar::from(0x1B_u64)));
        substitution_table.push(composer.append_constant(BlsScalar::from(0x6E_u64)));
        substitution_table.push(composer.append_constant(BlsScalar::from(0x5A_u64)));
        substitution_table.push(composer.append_constant(BlsScalar::from(0xA0_u64)));
        substitution_table.push(composer.append_constant(BlsScalar::from(0x52_u64)));
        substitution_table.push(composer.append_constant(BlsScalar::from(0x3B_u64)));
        substitution_table.push(composer.append_constant(BlsScalar::from(0xD6_u64)));
        substitution_table.push(composer.append_constant(BlsScalar::from(0xB3_u64)));
        substitution_table.push(composer.append_constant(BlsScalar::from(0x29_u64)));
        substitution_table.push(composer.append_constant(BlsScalar::from(0xE3_u64)));
        substitution_table.push(composer.append_constant(BlsScalar::from(0x2F_u64)));
        substitution_table.push(composer.append_constant(BlsScalar::from(0x84_u64)));
        substitution_table.push(composer.append_constant(BlsScalar::from(0x53_u64)));
        substitution_table.push(composer.append_constant(BlsScalar::from(0xD1_u64)));
        substitution_table.push(composer.append_constant(BlsScalar::from(0x00_u64)));
        substitution_table.push(composer.append_constant(BlsScalar::from(0xED_u64)));
        substitution_table.push(composer.append_constant(BlsScalar::from(0x20_u64)));
        substitution_table.push(composer.append_constant(BlsScalar::from(0xFC_u64)));
        substitution_table.push(composer.append_constant(BlsScalar::from(0xB1_u64)));
        substitution_table.push(composer.append_constant(BlsScalar::from(0x5B_u64)));
        substitution_table.push(composer.append_constant(BlsScalar::from(0x6A_u64)));
        substitution_table.push(composer.append_constant(BlsScalar::from(0xCB_u64)));
        substitution_table.push(composer.append_constant(BlsScalar::from(0xBE_u64)));
        substitution_table.push(composer.append_constant(BlsScalar::from(0x39_u64)));
        substitution_table.push(composer.append_constant(BlsScalar::from(0x4A_u64)));
        substitution_table.push(composer.append_constant(BlsScalar::from(0x4C_u64)));
        substitution_table.push(composer.append_constant(BlsScalar::from(0x58_u64)));
        substitution_table.push(composer.append_constant(BlsScalar::from(0xCF_u64)));
        substitution_table.push(composer.append_constant(BlsScalar::from(0xD0_u64)));
        substitution_table.push(composer.append_constant(BlsScalar::from(0xEF_u64)));
        substitution_table.push(composer.append_constant(BlsScalar::from(0xAA_u64)));
        substitution_table.push(composer.append_constant(BlsScalar::from(0xFB_u64)));
        substitution_table.push(composer.append_constant(BlsScalar::from(0x43_u64)));
        substitution_table.push(composer.append_constant(BlsScalar::from(0x4D_u64)));
        substitution_table.push(composer.append_constant(BlsScalar::from(0x33_u64)));
        substitution_table.push(composer.append_constant(BlsScalar::from(0x85_u64)));
        substitution_table.push(composer.append_constant(BlsScalar::from(0x45_u64)));
        substitution_table.push(composer.append_constant(BlsScalar::from(0xF9_u64)));
        substitution_table.push(composer.append_constant(BlsScalar::from(0x02_u64)));
        substitution_table.push(composer.append_constant(BlsScalar::from(0x7F_u64)));
        substitution_table.push(composer.append_constant(BlsScalar::from(0x50_u64)));
        substitution_table.push(composer.append_constant(BlsScalar::from(0x3C_u64)));
        substitution_table.push(composer.append_constant(BlsScalar::from(0x9F_u64)));
        substitution_table.push(composer.append_constant(BlsScalar::from(0xA8_u64)));
        substitution_table.push(composer.append_constant(BlsScalar::from(0x51_u64)));
        substitution_table.push(composer.append_constant(BlsScalar::from(0xA3_u64)));
        substitution_table.push(composer.append_constant(BlsScalar::from(0x40_u64)));
        substitution_table.push(composer.append_constant(BlsScalar::from(0x8F_u64)));
        substitution_table.push(composer.append_constant(BlsScalar::from(0x92_u64)));
        substitution_table.push(composer.append_constant(BlsScalar::from(0x9D_u64)));
        substitution_table.push(composer.append_constant(BlsScalar::from(0x38_u64)));
        substitution_table.push(composer.append_constant(BlsScalar::from(0xF5_u64)));
        substitution_table.push(composer.append_constant(BlsScalar::from(0xBC_u64)));
        substitution_table.push(composer.append_constant(BlsScalar::from(0xB6_u64)));
        substitution_table.push(composer.append_constant(BlsScalar::from(0xDA_u64)));
        substitution_table.push(composer.append_constant(BlsScalar::from(0x21_u64)));
        substitution_table.push(composer.append_constant(BlsScalar::from(0x10_u64)));
        substitution_table.push(composer.append_constant(BlsScalar::from(0xFF_u64)));
        substitution_table.push(composer.append_constant(BlsScalar::from(0xF3_u64)));
        substitution_table.push(composer.append_constant(BlsScalar::from(0xD2_u64)));
        substitution_table.push(composer.append_constant(BlsScalar::from(0xCD_u64)));
        substitution_table.push(composer.append_constant(BlsScalar::from(0x0C_u64)));
        substitution_table.push(composer.append_constant(BlsScalar::from(0x13_u64)));
        substitution_table.push(composer.append_constant(BlsScalar::from(0xEC_u64)));
        substitution_table.push(composer.append_constant(BlsScalar::from(0x5F_u64)));
        substitution_table.push(composer.append_constant(BlsScalar::from(0x97_u64)));
        substitution_table.push(composer.append_constant(BlsScalar::from(0x44_u64)));
        substitution_table.push(composer.append_constant(BlsScalar::from(0x17_u64)));
        substitution_table.push(composer.append_constant(BlsScalar::from(0xC4_u64)));
        substitution_table.push(composer.append_constant(BlsScalar::from(0xA7_u64)));
        substitution_table.push(composer.append_constant(BlsScalar::from(0x7E_u64)));
        substitution_table.push(composer.append_constant(BlsScalar::from(0x3D_u64)));
        substitution_table.push(composer.append_constant(BlsScalar::from(0x64_u64)));
        substitution_table.push(composer.append_constant(BlsScalar::from(0x5D_u64)));
        substitution_table.push(composer.append_constant(BlsScalar::from(0x19_u64)));
        substitution_table.push(composer.append_constant(BlsScalar::from(0x73_u64)));
        substitution_table.push(composer.append_constant(BlsScalar::from(0x60_u64)));
        substitution_table.push(composer.append_constant(BlsScalar::from(0x81_u64)));
        substitution_table.push(composer.append_constant(BlsScalar::from(0x4F_u64)));
        substitution_table.push(composer.append_constant(BlsScalar::from(0xDC_u64)));
        substitution_table.push(composer.append_constant(BlsScalar::from(0x22_u64)));
        substitution_table.push(composer.append_constant(BlsScalar::from(0x2A_u64)));
        substitution_table.push(composer.append_constant(BlsScalar::from(0x90_u64)));
        substitution_table.push(composer.append_constant(BlsScalar::from(0x88_u64)));
        substitution_table.push(composer.append_constant(BlsScalar::from(0x46_u64)));
        substitution_table.push(composer.append_constant(BlsScalar::from(0xEE_u64)));
        substitution_table.push(composer.append_constant(BlsScalar::from(0xB8_u64)));
        substitution_table.push(composer.append_constant(BlsScalar::from(0x14_u64)));
        substitution_table.push(composer.append_constant(BlsScalar::from(0xDE_u64)));
        substitution_table.push(composer.append_constant(BlsScalar::from(0x5E_u64)));
        substitution_table.push(composer.append_constant(BlsScalar::from(0x0B_u64)));
        substitution_table.push(composer.append_constant(BlsScalar::from(0xDB_u64)));
        substitution_table.push(composer.append_constant(BlsScalar::from(0xE0_u64)));
        substitution_table.push(composer.append_constant(BlsScalar::from(0x32_u64)));
        substitution_table.push(composer.append_constant(BlsScalar::from(0x3A_u64)));
        substitution_table.push(composer.append_constant(BlsScalar::from(0x0A_u64)));
        substitution_table.push(composer.append_constant(BlsScalar::from(0x49_u64)));
        substitution_table.push(composer.append_constant(BlsScalar::from(0x06_u64)));
        substitution_table.push(composer.append_constant(BlsScalar::from(0x24_u64)));
        substitution_table.push(composer.append_constant(BlsScalar::from(0x5C_u64)));
        substitution_table.push(composer.append_constant(BlsScalar::from(0xC2_u64)));
        substitution_table.push(composer.append_constant(BlsScalar::from(0xD3_u64)));
        substitution_table.push(composer.append_constant(BlsScalar::from(0xAC_u64)));
        substitution_table.push(composer.append_constant(BlsScalar::from(0x62_u64)));
        substitution_table.push(composer.append_constant(BlsScalar::from(0x91_u64)));
        substitution_table.push(composer.append_constant(BlsScalar::from(0x95_u64)));
        substitution_table.push(composer.append_constant(BlsScalar::from(0xE4_u64)));
        substitution_table.push(composer.append_constant(BlsScalar::from(0x79_u64)));
        substitution_table.push(composer.append_constant(BlsScalar::from(0xE7_u64)));
        substitution_table.push(composer.append_constant(BlsScalar::from(0xC8_u64)));
        substitution_table.push(composer.append_constant(BlsScalar::from(0x37_u64)));
        substitution_table.push(composer.append_constant(BlsScalar::from(0x6D_u64)));
        substitution_table.push(composer.append_constant(BlsScalar::from(0x8D_u64)));
        substitution_table.push(composer.append_constant(BlsScalar::from(0xD5_u64)));
        substitution_table.push(composer.append_constant(BlsScalar::from(0x4E_u64)));
        substitution_table.push(composer.append_constant(BlsScalar::from(0xA9_u64)));
        substitution_table.push(composer.append_constant(BlsScalar::from(0x6C_u64)));
        substitution_table.push(composer.append_constant(BlsScalar::from(0x56_u64)));
        substitution_table.push(composer.append_constant(BlsScalar::from(0xF4_u64)));
        substitution_table.push(composer.append_constant(BlsScalar::from(0xEA_u64)));
        substitution_table.push(composer.append_constant(BlsScalar::from(0x65_u64)));
        substitution_table.push(composer.append_constant(BlsScalar::from(0x7A_u64)));
        substitution_table.push(composer.append_constant(BlsScalar::from(0xAE_u64)));
        substitution_table.push(composer.append_constant(BlsScalar::from(0x08_u64)));
        substitution_table.push(composer.append_constant(BlsScalar::from(0xBA_u64)));
        substitution_table.push(composer.append_constant(BlsScalar::from(0x78_u64)));
        substitution_table.push(composer.append_constant(BlsScalar::from(0x25_u64)));
        substitution_table.push(composer.append_constant(BlsScalar::from(0x2E_u64)));
        substitution_table.push(composer.append_constant(BlsScalar::from(0x1C_u64)));
        substitution_table.push(composer.append_constant(BlsScalar::from(0xA6_u64)));
        substitution_table.push(composer.append_constant(BlsScalar::from(0xB4_u64)));
        substitution_table.push(composer.append_constant(BlsScalar::from(0xC6_u64)));
        substitution_table.push(composer.append_constant(BlsScalar::from(0xE8_u64)));
        substitution_table.push(composer.append_constant(BlsScalar::from(0xDD_u64)));
        substitution_table.push(composer.append_constant(BlsScalar::from(0x74_u64)));
        substitution_table.push(composer.append_constant(BlsScalar::from(0x1F_u64)));
        substitution_table.push(composer.append_constant(BlsScalar::from(0x4B_u64)));
        substitution_table.push(composer.append_constant(BlsScalar::from(0xBD_u64)));
        substitution_table.push(composer.append_constant(BlsScalar::from(0x8B_u64)));
        substitution_table.push(composer.append_constant(BlsScalar::from(0x8A_u64)));
        substitution_table.push(composer.append_constant(BlsScalar::from(0x70_u64)));
        substitution_table.push(composer.append_constant(BlsScalar::from(0x3E_u64)));
        substitution_table.push(composer.append_constant(BlsScalar::from(0xB5_u64)));
        substitution_table.push(composer.append_constant(BlsScalar::from(0x66_u64)));
        substitution_table.push(composer.append_constant(BlsScalar::from(0x48_u64)));
        substitution_table.push(composer.append_constant(BlsScalar::from(0x03_u64)));
        substitution_table.push(composer.append_constant(BlsScalar::from(0xF6_u64)));
        substitution_table.push(composer.append_constant(BlsScalar::from(0x0E_u64)));
        substitution_table.push(composer.append_constant(BlsScalar::from(0x61_u64)));
        substitution_table.push(composer.append_constant(BlsScalar::from(0x35_u64)));
        substitution_table.push(composer.append_constant(BlsScalar::from(0x57_u64)));
        substitution_table.push(composer.append_constant(BlsScalar::from(0xB9_u64)));
        substitution_table.push(composer.append_constant(BlsScalar::from(0x86_u64)));
        substitution_table.push(composer.append_constant(BlsScalar::from(0xC1_u64)));
        substitution_table.push(composer.append_constant(BlsScalar::from(0x1D_u64)));
        substitution_table.push(composer.append_constant(BlsScalar::from(0x9E_u64)));
        substitution_table.push(composer.append_constant(BlsScalar::from(0xE1_u64)));
        substitution_table.push(composer.append_constant(BlsScalar::from(0xF8_u64)));
        substitution_table.push(composer.append_constant(BlsScalar::from(0x98_u64)));
        substitution_table.push(composer.append_constant(BlsScalar::from(0x11_u64)));
        substitution_table.push(composer.append_constant(BlsScalar::from(0x69_u64)));
        substitution_table.push(composer.append_constant(BlsScalar::from(0xD9_u64)));
        substitution_table.push(composer.append_constant(BlsScalar::from(0x8E_u64)));
        substitution_table.push(composer.append_constant(BlsScalar::from(0x94_u64)));
        substitution_table.push(composer.append_constant(BlsScalar::from(0x9B_u64)));
        substitution_table.push(composer.append_constant(BlsScalar::from(0x1E_u64)));
        substitution_table.push(composer.append_constant(BlsScalar::from(0x87_u64)));
        substitution_table.push(composer.append_constant(BlsScalar::from(0xE9_u64)));
        substitution_table.push(composer.append_constant(BlsScalar::from(0xCE_u64)));
        substitution_table.push(composer.append_constant(BlsScalar::from(0x55_u64)));
        substitution_table.push(composer.append_constant(BlsScalar::from(0x28_u64)));
        substitution_table.push(composer.append_constant(BlsScalar::from(0xDF_u64)));
        substitution_table.push(composer.append_constant(BlsScalar::from(0x8C_u64)));
        substitution_table.push(composer.append_constant(BlsScalar::from(0xA1_u64)));
        substitution_table.push(composer.append_constant(BlsScalar::from(0x89_u64)));
        substitution_table.push(composer.append_constant(BlsScalar::from(0x0D_u64)));
        substitution_table.push(composer.append_constant(BlsScalar::from(0xBF_u64)));
        substitution_table.push(composer.append_constant(BlsScalar::from(0xE6_u64)));
        substitution_table.push(composer.append_constant(BlsScalar::from(0x42_u64)));
        substitution_table.push(composer.append_constant(BlsScalar::from(0x68_u64)));
        substitution_table.push(composer.append_constant(BlsScalar::from(0x41_u64)));
        substitution_table.push(composer.append_constant(BlsScalar::from(0x99_u64)));
        substitution_table.push(composer.append_constant(BlsScalar::from(0x2D_u64)));
        substitution_table.push(composer.append_constant(BlsScalar::from(0x0F_u64)));
        substitution_table.push(composer.append_constant(BlsScalar::from(0xB0_u64)));
        substitution_table.push(composer.append_constant(BlsScalar::from(0x54_u64)));
        substitution_table.push(composer.append_constant(BlsScalar::from(0xBB_u64)));
        substitution_table.push(composer.append_constant(BlsScalar::from(0x16_u64)));

        substitution_table
    }

    fn substitute_byte<C>(
        byte_in_bits: &[Witness],
        substitution_table: &[Witness],
        composer: &mut C,
    ) -> Result<Witness, PlonkError>
    where
        C: dusk_plonk::composer::Composer,
    {
        let n = byte_in_bits.len();
        let mut cur_mux_values = substitution_table.to_vec();

        // Traverse the evaluation tree from bottom to top in level order traversal.
        // This is method 5.1 from https://github.com/mir-protocol/r1cs-workshop/blob/master/workshop.pdf
        // TODO: Add method 5.2/5.3
        for i in 0..n {
            // Size of current layer.
            let cur_size = 1 << (n - i);
            assert_eq!(cur_mux_values.len(), cur_size);

            let mut next_mux_values = Vec::new();
            for j in (0..cur_size).step_by(2) {
                let cur = composer.component_select(
                    *byte_in_bits
                        .get(n - 1 - i)
                        .ok_or(PlonkError::NotEnoughBytes)?,
                    *cur_mux_values
                        .get(j + 1)
                        .ok_or(PlonkError::NotEnoughBytes)?,
                    *cur_mux_values.get(j).ok_or(PlonkError::NotEnoughBytes)?,
                );
                next_mux_values.push(cur);
            }
            cur_mux_values = next_mux_values;
        }

        Ok(*cur_mux_values.get(0).ok_or(PlonkError::NotEnoughBytes)?)
    }
}

fn rotate_left<C>(
    input: &[Witness],
    positions: usize,
    composer: &mut C,
) -> Result<Vec<Witness>, PlonkError>
where
    C: dusk_plonk::prelude::Composer,
{
    let input_len = input.len();
    let mut output = input.to_vec();
    output.rotate_left(positions);

    for i in 0..input_len {
        composer.assert_equal(
            *input.get(i).ok_or(PlonkError::NotEnoughBytes)?,
            *output
                .get((i + positions) % input_len)
                .ok_or(PlonkError::NotEnoughBytes)?,
        );
    }

    Ok(output.clone())
}

fn kary_xor<C>(input: &[Witness], composer: &mut C) -> Witness
where
    C: dusk_plonk::prelude::Composer,
{
    let mut output = composer.append_constant(BlsScalar::zero());
    for w in input {
        output = composer.append_logic_xor(output, *w, 8);
    }

    output
}

// I allow this clippy lint here because there is no way of using .get() or
// .get_mut() in the composer.
#[allow(clippy::indexing_slicing)]
fn gate_eq<C>(a: Witness, b: Witness, composer: &mut C) -> Result<Witness, PlonkError>
where
    C: dusk_plonk::prelude::Composer,
{
    let one = composer.append_constant(BlsScalar::one());
    let zero = composer.append_constant(BlsScalar::zero());

    let constraint = Constraint::new()
        .left(1)
        .right(-BlsScalar::one())
        .a(a)
        .b(b)
        .output(BlsScalar::one());

    let output = composer
        .append_evaluated_output(constraint)
        .ok_or(PlonkError::CircuitInputsNotFound)?;

    let constraint = constraint.o(output);

    let are_equal = composer.append_witness(BlsScalar::from(u64::from(
        composer[output] == BlsScalar::zero(),
    )));
    composer.component_boolean(are_equal);

    composer.append_gate(constraint);

    let result = composer.component_select(are_equal, one, zero);

    Ok(result)
}

fn constant_vec<C>(size: usize, composer: &mut C) -> Vec<Witness>
where
    C: dusk_plonk::prelude::Composer,
{
    (0..size)
        .into_iter()
        .map(|_v| composer.append_constant(BlsScalar::zero()))
        .collect::<Vec<Witness>>()
}

fn to_witness_vec<C>(input: &[u8], composer: &mut C) -> Vec<Witness>
where
    C: dusk_plonk::prelude::Composer,
{
    input
        .iter()
        .map(|byte| composer.append_witness(BlsScalar::from(u64::from(*byte))))
        .collect()
}

fn to_public_vec<C>(input: &[u8], composer: &mut C) -> Vec<Witness>
where
    C: dusk_plonk::prelude::Composer,
{
    input
        .iter()
        .map(|byte| composer.append_public(BlsScalar::from(u64::from(*byte))))
        .collect()
}

#[cfg(test)]
mod plonk_tests {
    use super::{to_witness_vec, AESEncryptionCircuit};
    use dusk_plonk::prelude::{BlsScalar, Builder, Composer, Witness};

    // I allow this clippy lint here because there is no way of using .get() or
    // .get_mut() in the composer.
    #[allow(clippy::indexing_slicing)]
    fn from_witness_vec<C>(input: &[Witness], composer: &mut C) -> Vec<BlsScalar>
    where
        C: dusk_plonk::prelude::Composer,
    {
        input.iter().map(|w| composer[*w]).collect()
    }

    #[test]
    fn test_add_round_key() {
        let mut composer = Builder::initialized(100);

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
            AESEncryptionCircuit::add_round_key(&message, &round_key, &mut composer);

        assert_eq!(
            from_witness_vec(&after_add_round_key, &mut composer),
            from_witness_vec(&expected_after_add_round_key, &mut composer)
        );
    }

    #[test]
    fn test_substitute_bytes() {
        let mut composer = Builder::initialized(100);

        let message = to_witness_vec(
            &[
                0x19, 0x3d, 0xe3, 0xbe, 0xa0, 0xf4, 0xe2, 0x2b, 0x9a, 0xc6, 0x8d, 0x2a, 0xe9, 0xf8,
                0x48, 0x08,
            ],
            &mut composer,
        );

        let substitution_table = AESEncryptionCircuit::substitution_table(&mut composer);

        let expected_after_substitute_bytes = to_witness_vec(
            &[
                0xd4, 0x27, 0x11, 0xae, 0xe0, 0xbf, 0x98, 0xf1, 0xb8, 0xb4, 0x5d, 0xe5, 0x1e, 0x41,
                0x52, 0x30,
            ],
            &mut composer,
        );

        let after_substitute_bytes =
            AESEncryptionCircuit::sub_bytes(&message, &substitution_table, &mut composer).unwrap();

        assert_eq!(
            from_witness_vec(&after_substitute_bytes, &mut composer),
            from_witness_vec(&expected_after_substitute_bytes, &mut composer)
        );
    }

    #[test]
    fn test_shift_rows() {
        let mut composer = Builder::initialized(100);

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
        let mut composer = Builder::initialized(100);

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

    #[test]
    fn test_key_expansion() {
        let mut composer = Builder::initialized(100);

        let secret_key = to_witness_vec(
            &[
                0x2b, 0x7e, 0x15, 0x16, 0x28, 0xae, 0xd2, 0xa6, 0xab, 0xf7, 0x15, 0x88, 0x09, 0xcf,
                0x4f, 0x3c,
            ],
            &mut composer,
        );

        let substitution_table = AESEncryptionCircuit::substitution_table(&mut composer);

        let result =
            AESEncryptionCircuit::key_expansion(&secret_key, &substitution_table, &mut composer)
                .unwrap();

        assert_eq!(
            from_witness_vec(&result[10], &mut composer),
            from_witness_vec(
                &to_witness_vec(
                    &[
                        0xd0, 0x14, 0xf9, 0xa8, 0xc9, 0xee, 0x25, 0x89, 0xe1, 0x3f, 0x0c, 0xc8,
                        0xb6, 0x63, 0x0c, 0xa6,
                    ],
                    &mut composer
                ),
                &mut composer
            )
        );
    }
}
