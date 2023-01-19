use crate::helpers;
use dusk_plonk::prelude::{BlsScalar, Circuit, Witness};

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
        let output: Vec<Witness>;
        todo!()
    }

    fn mix_columns<C>(input: &[Witness], composer: &mut C) -> Result<Vec<Witness>, PlonkError>
    where
        C: dusk_plonk::prelude::Composer,
    {
        let output: Vec<Witness>;
        todo!()
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
