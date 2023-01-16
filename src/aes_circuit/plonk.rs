use crate::helpers;
use dusk_plonk::prelude::{BlsScalar, Circuit};

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

fn bls_scalar_from_16_bytes(bytes: &[u8; 16]) -> Result<BlsScalar, dusk_plonk::prelude::Error> {
    let mut new_bytes = [0_u64; 4];

    for (old_chunks, new_chunks) in bytes.chunks(8).zip(new_bytes.iter_mut()) {
        *new_chunks = u64::from_le_bytes(
            old_chunks
                .try_into()
                .map_err(|_e| dusk_plonk::prelude::Error::BlsScalarMalformed)?,
        );
    }

    Ok(BlsScalar(new_bytes) * R2)
}

impl Circuit for AESEncryptionCircuit {
    fn circuit<C>(&self, composer: &mut C) -> Result<(), dusk_plonk::prelude::Error>
    where
        C: dusk_plonk::prelude::Composer,
    {
        let message = composer.append_witness(BlsScalar::from_bytes_wide(&self.message));
        let secret_key = composer.append_witness(bls_scalar_from_16_bytes(&self.secret_key)?);
        let ciphertext = composer.append_public(BlsScalar::from_bytes_wide(&self.ciphertext));

        // Lookup table

        // Key derivation

        // 10-round AES encryption

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
