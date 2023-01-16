use crate::helpers;
use dusk_plonk::prelude::{BlsScalar, Circuit, Witness};

type PlonkError = dusk_plonk::prelude::Error;

/// This circuit shows that `ciphertext` is the result of encrypting `message` using AES with `secret_key` as the encryption key.
pub struct AESEncryptionCircuit {
    message: [u8; 64],
    secret_key: [u8; 16],
    ciphertext: [u8; 64],
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
        let message = composer.append_witness(BlsScalar::from_bytes_wide(&self.message));
        let secret_key = composer.append_witness(bls_scalar_from_16_bytes(&self.secret_key)?);
        let ciphertext = composer.append_public(BlsScalar::from_bytes_wide(&self.ciphertext));

        // Lookup table

        // Key derivation
        let round_keys: [Witness; 11] = Self::derive_keys(secret_key)?;

        // Add round 0 key
        let mut after_add_round_key: Witness = Self::add_round_key(message, round_keys[0])?;
        // 10-round AES encryption (we skip the first one because we already added in round 0)
        for (round_number, round_key) in round_keys.iter().enumerate().skip(1) {
            // SubBytes
            let after_sub_bytes = Self::sub_bytes(after_add_round_key)?;
            // ShiftRows
            let after_shift_rows = Self::shift_rows(after_sub_bytes)?;
            // MixColumns
            let round_is_the_last_one = composer.append_witness(BlsScalar::from((round_number == 10).try_into().unwrap_or(0_u64)));
            // FIXME: Do we need to enforce this?
            composer.component_boolean(round_is_the_last_one);
            let after_mix_columns = composer.component_select(round_is_the_last_one, after_shift_rows, Self::mix_columns(after_shift_rows)?);
            // AddRoundKey
            after_add_round_key = Self::add_round_key(after_mix_columns, *round_key)?;
        }

        let computed_ciphertext = after_add_round_key;
        // Enforce that the ciphertext is the result of the encryption
        composer.assert_equal(ciphertext, computed_ciphertext);

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
            message,
            secret_key: key,
            ciphertext,
        }
    }
}

impl AESEncryptionCircuit {
    fn add_round_key(input: Witness, key: Witness) -> Result<Witness, PlonkError> {
        let output: Witness;
        todo!()
    }
    
    fn sub_bytes(input: Witness) -> Result<Witness, PlonkError> {
        let output: Witness;
        todo!()
    }

    fn shift_rows(input: Witness) -> Result<Witness, PlonkError> {
        let output: Witness;
        todo!()
    }

    fn mix_columns(input: Witness) -> Result<Witness, PlonkError> {
        let output: Witness;
        todo!()
    }

    fn derive_keys(secret_key: Witness) -> Result<[Witness; 11], PlonkError> {
        let keys: [Witness; 11];
        todo!()
    }
}
