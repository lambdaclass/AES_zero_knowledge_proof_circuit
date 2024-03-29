use aes::cipher::KeyInit;
use anyhow::{ensure, Result};
use criterion::Criterion;

// TODO: Support non-multiple of 16 bytes messages.
#[allow(dead_code)]
fn primitive_encrypt(message: &[u8], key: &[u8]) -> Vec<u8> {
    let primitive_secret_key =
        aes::Aes128::new(digest::generic_array::GenericArray::from_slice(key));
    let mut encrypted_message: Vec<u8> = Vec::new();

    message.chunks_exact(16).for_each(|chunk| {
        let mut block = digest::generic_array::GenericArray::clone_from_slice(chunk);
        aes::cipher::BlockEncrypt::encrypt_block(&primitive_secret_key, &mut block);
        encrypted_message.extend_from_slice(&block);
    });

    encrypted_message
}

fn sample_message(amount_of_bytes: usize) -> Vec<u8> {
    let mut message = vec![0_u8; amount_of_bytes];

    let mut _random_message: [u8; 16] = rand::random();
    for (raw_message_byte, random_message_byte) in message.iter_mut().zip(_random_message) {
        *raw_message_byte = random_message_byte;
        _random_message = rand::random();
    }

    message
}

pub fn encrypt_message_with_bytes(c: &mut Criterion, amount_of_bytes: usize) -> Result<()> {
    ensure!(
        amount_of_bytes % 16 == 0,
        "Message length in bytes should be a multiple of 16 for the moment"
    );
    let message = sample_message(amount_of_bytes);
    let (proving_key, _verifying_key) = zk_aes::synthesize_keys(message.len()).unwrap();
    let key: [u8; 16] = rand::random();

    let mut group = c.benchmark_group("Encryption");
    group.sample_size(10);
    group.bench_function(format!("{amount_of_bytes}_message_encryption"), |b| {
        b.iter(|| {
            zk_aes::encrypt(&message, &key, proving_key.clone()).unwrap();
        })
    });
    group.finish();
    Ok(())
}
