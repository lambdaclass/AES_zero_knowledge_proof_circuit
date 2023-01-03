// These tests assume ECB. They should be updated to test CBC.
#[cfg(test)]
mod tests {
    use ark_relations::r1cs::ConstraintSystem;
    use poc_encryption_proof::{
        aes::{add_round_key, derive_keys, mix_columns, shift_rows, substitute_bytes},
        encrypt, synthesize_keys,
    };
    use simpleworks::{gadgets::ConstraintF, marlin::ConstraintSystemRef};

    #[allow(clippy::too_many_arguments)]
    fn assert_round_steps_results_are_the_expected(
        cs: &ConstraintSystemRef,
        round_key: &[u8; 16],
        expected_start_of_round: [u8; 16],
        expected_after_substituting_bytes: [u8; 16],
        expected_after_shift_rows: [u8; 16],
        expected_after_mix_columns: [u8; 16],
        expected_start_of_next_round: [u8; 16],
        round: usize,
    ) {
        let after_substituting_bytes = substitute_bytes(&expected_start_of_round, cs).unwrap();
        assert_eq!(
            after_substituting_bytes, expected_after_substituting_bytes,
            "Substitution is incorrect in round {round}"
        );
        let after_shift_rows = shift_rows(&after_substituting_bytes, cs).unwrap();
        assert_eq!(
            after_shift_rows, expected_after_shift_rows,
            "Shift rows is incorrect in round {round}"
        );
        let after_mix_columns = if round != 10 {
            let after_mix_columns = mix_columns(&after_shift_rows).unwrap();
            assert_eq!(
                after_mix_columns, expected_after_mix_columns,
                "Mix columns is incorrect in round {round}",
            );
            after_mix_columns
        } else {
            after_shift_rows
        };
        let start_of_next_round = add_round_key(&after_mix_columns, round_key);
        assert_eq!(
            start_of_next_round, expected_start_of_next_round,
            "Start of next round is incorrect in round {round}"
        );
    }

    #[test]
    fn test_aes_encryption_step_by_step() {
        let cs = ConstraintSystem::<ConstraintF>::new_ref();
        let plaintext: [u8; 16] = [
            0x32, 0x43, 0xf6, 0xa8, 0x88, 0x5a, 0x30, 0x8d, 0x31, 0x31, 0x98, 0xa2, 0xe0, 0x37,
            0x07, 0x34,
        ];
        let key: [u8; 16] = [
            0x2b, 0x7e, 0x15, 0x16, 0x28, 0xae, 0xd2, 0xa6, 0xab, 0xf7, 0x15, 0x88, 0x09, 0xcf,
            0x4f, 0x3c,
        ];
        let round_keys = derive_keys(&key).unwrap();
        let expected_output = [
            0x39, 0x25, 0x84, 0x1d, 0x02, 0xdc, 0x09, 0xfb, 0xdc, 0x11, 0x85, 0x97, 0x19, 0x6a,
            0x0b, 0x32,
        ];

        /* Round 1 expected values */
        let expected_start_of_round = [
            // Round 1.
            [
                0x19, 0x3d, 0xe3, 0xbe, 0xa0, 0xf4, 0xe2, 0x2b, 0x9a, 0xc6, 0x8d, 0x2a, 0xe9, 0xf8,
                0x48, 0x08,
            ],
            // Round 2.
            [
                0xa4, 0x9c, 0x7f, 0xf2, 0x68, 0x9f, 0x35, 0x2b, 0x6b, 0x5b, 0xea, 0x43, 0x02, 0x6a,
                0x50, 0x49,
            ],
            // Round 3.
            [
                0xaa, 0x8f, 0x5f, 0x03, 0x61, 0xdd, 0xe3, 0xef, 0x82, 0xd2, 0x4a, 0xd2, 0x68, 0x32,
                0x46, 0x9a,
            ],
            // Round 4.
            [
                0x48, 0x6c, 0x4e, 0xee, 0x67, 0x1d, 0x9d, 0x0d, 0x4d, 0xe3, 0xb1, 0x38, 0xd6, 0x5f,
                0x58, 0xe7,
            ],
            // Round 5.
            [
                0xe0, 0x92, 0x7f, 0xe8, 0xc8, 0x63, 0x63, 0xc0, 0xd9, 0xb1, 0x35, 0x50, 0x85, 0xb8,
                0xbe, 0x01,
            ],
            // Round 6.
            [
                0xf1, 0x00, 0x6f, 0x55, 0xc1, 0x92, 0x4c, 0xef, 0x7c, 0xc8, 0x8b, 0x32, 0x5d, 0xb5,
                0xd5, 0x0c,
            ],
            // Round 7.
            [
                0x26, 0x0e, 0x2e, 0x17, 0x3d, 0x41, 0xb7, 0x7d, 0xe8, 0x64, 0x72, 0xa9, 0xfd, 0xd2,
                0x8b, 0x25,
            ],
            // Round 8.
            [
                0x5a, 0x41, 0x42, 0xb1, 0x19, 0x49, 0xdc, 0x1f, 0xa3, 0xe0, 0x19, 0x65, 0x7a, 0x8c,
                0x04, 0x0c,
            ],
            // Round 9.
            [
                0xea, 0x83, 0x5c, 0xf0, 0x04, 0x45, 0x33, 0x2d, 0x65, 0x5d, 0x98, 0xad, 0x85, 0x96,
                0xb0, 0xc5,
            ],
            // Round 10.
            [
                0xeb, 0x40, 0xf2, 0x1e, 0x59, 0x2e, 0x38, 0x84, 0x8b, 0xa1, 0x13, 0xe7, 0x1b, 0xc3,
                0x42, 0xd2,
            ],
            // Round 10 + 1.
            expected_output,
        ];
        let expected_after_substituting_bytes = [
            // Round 1.
            [
                0xd4, 0x27, 0x11, 0xae, 0xe0, 0xbf, 0x98, 0xf1, 0xb8, 0xb4, 0x5d, 0xe5, 0x1e, 0x41,
                0x52, 0x30,
            ],
            // Round 2.
            [
                0x49, 0xde, 0xd2, 0x89, 0x45, 0xdb, 0x96, 0xf1, 0x7f, 0x39, 0x87, 0x1a, 0x77, 0x02,
                0x53, 0x3b,
            ],
            // Round 3.
            [
                0xac, 0x73, 0xcf, 0x7b, 0xef, 0xc1, 0x11, 0xdf, 0x13, 0xb5, 0xd6, 0xb5, 0x45, 0x23,
                0x5a, 0xb8,
            ],
            // Round 4.
            [
                0x52, 0x50, 0x2f, 0x28, 0x85, 0xa4, 0x5e, 0xd7, 0xe3, 0x11, 0xc8, 0x07, 0xf6, 0xcf,
                0x6a, 0x94,
            ],
            // Round 5.
            [
                0xe1, 0x4f, 0xd2, 0x9b, 0xe8, 0xfb, 0xfb, 0xba, 0x35, 0xc8, 0x96, 0x53, 0x97, 0x6c,
                0xae, 0x7c,
            ],
            // Round 6.
            [
                0xa1, 0x63, 0xa8, 0xfc, 0x78, 0x4f, 0x29, 0xdf, 0x10, 0xe8, 0x3d, 0x23, 0x4c, 0xd5,
                0x03, 0xfe,
            ],
            // Round 7.
            [
                0xf7, 0xab, 0x31, 0xf0, 0x27, 0x83, 0xa9, 0xff, 0x9b, 0x43, 0x40, 0xd3, 0x54, 0xb5,
                0x3d, 0x3f,
            ],
            // Round 8.
            [
                0xbe, 0x83, 0x2c, 0xc8, 0xd4, 0x3b, 0x86, 0xc0, 0x0a, 0xe1, 0xd4, 0x4d, 0xda, 0x64,
                0xf2, 0xfe,
            ],
            // Round 9.
            [
                0x87, 0xec, 0x4a, 0x8c, 0xf2, 0x6e, 0xc3, 0xd8, 0x4d, 0x4c, 0x46, 0x95, 0x97, 0x90,
                0xe7, 0xa6,
            ],
            // Round 10.
            [
                0xe9, 0x09, 0x89, 0x72, 0xcb, 0x31, 0x07, 0x5f, 0x3d, 0x32, 0x7d, 0x94, 0xaf, 0x2e,
                0x2c, 0xb5,
            ],
        ];
        let expected_after_shift_rows = [
            // Round 1.
            [
                0xd4, 0xbf, 0x5d, 0x30, 0xe0, 0xb4, 0x52, 0xae, 0xb8, 0x41, 0x11, 0xf1, 0x1e, 0x27,
                0x98, 0xe5,
            ],
            // Round 2.
            [
                0x49, 0xdb, 0x87, 0x3b, 0x45, 0x39, 0x53, 0x89, 0x7f, 0x02, 0xd2, 0xf1, 0x77, 0xde,
                0x96, 0x1a,
            ],
            // Round 3.
            [
                0xac, 0xc1, 0xd6, 0xb8, 0xef, 0xb5, 0x5a, 0x7b, 0x13, 0x23, 0xcf, 0xdf, 0x45, 0x73,
                0x11, 0xb5,
            ],
            // Round 4.
            [
                0x52, 0xa4, 0xc8, 0x94, 0x85, 0x11, 0x6a, 0x28, 0xe3, 0xcf, 0x2f, 0xd7, 0xf6, 0x50,
                0x5e, 0x07,
            ],
            // Round 5.
            [
                0xe1, 0xfb, 0x96, 0x7c, 0xe8, 0xc8, 0xae, 0x9b, 0x35, 0x6c, 0xd2, 0xba, 0x97, 0x4f,
                0xfb, 0x53,
            ],
            // Round 6.
            [
                0xa1, 0x4f, 0x3d, 0xfe, 0x78, 0xe8, 0x03, 0xfc, 0x10, 0xd5, 0xa8, 0xdf, 0x4c, 0x63,
                0x29, 0x23,
            ],
            // Round 7.
            [
                0xf7, 0x83, 0x40, 0x3f, 0x27, 0x43, 0x3d, 0xf0, 0x9b, 0xb5, 0x31, 0xff, 0x54, 0xab,
                0xa9, 0xd3,
            ],
            // Round 8.
            [
                0xbe, 0x3b, 0xd4, 0xfe, 0xd4, 0xe1, 0xf2, 0xc8, 0x0a, 0x64, 0x2c, 0xc0, 0xda, 0x83,
                0x86, 0x4d,
            ],
            // Round 9.
            [
                0x87, 0x6e, 0x46, 0xa6, 0xf2, 0x4c, 0xe7, 0x8c, 0x4d, 0x90, 0x4a, 0xd8, 0x97, 0xec,
                0xc3, 0x95,
            ],
            // Round 10.
            [
                0xe9, 0x31, 0x7d, 0xb5, 0xcb, 0x32, 0x2c, 0x72, 0x3d, 0x2e, 0x89, 0x5f, 0xaf, 0x09,
                0x07, 0x94,
            ],
        ];
        let expected_after_mix_columns = [
            // Round 1.
            [
                0x04, 0x66, 0x81, 0xe5, 0xe0, 0xcb, 0x19, 0x9a, 0x48, 0xf8, 0xd3, 0x7a, 0x28, 0x06,
                0x26, 0x4c,
            ],
            // Round 2.
            [
                0x58, 0x4d, 0xca, 0xf1, 0x1b, 0x4b, 0x5a, 0xac, 0xdb, 0xe7, 0xca, 0xa8, 0x1b, 0x6b,
                0xb0, 0xe5,
            ],
            // Round 3.
            [
                0x75, 0xec, 0x09, 0x93, 0x20, 0x0b, 0x63, 0x33, 0x53, 0xc0, 0xcf, 0x7c, 0xbb, 0x25,
                0xd0, 0xdc,
            ],
            // Round 4.
            [
                0x0f, 0xd6, 0xda, 0xa9, 0x60, 0x31, 0x38, 0xbf, 0x6f, 0xc0, 0x10, 0x6b, 0x5e, 0xb3,
                0x13, 0x01,
            ],
            // Round 5.
            [
                0x25, 0xd1, 0xa9, 0xad, 0xbd, 0x11, 0xd1, 0x68, 0xb6, 0x3a, 0x33, 0x8e, 0x4c, 0x4c,
                0xc0, 0xb0,
            ],
            // Round 6.
            [
                0x4b, 0x86, 0x8d, 0x6d, 0x2c, 0x4a, 0x89, 0x80, 0x33, 0x9d, 0xf4, 0xe8, 0x37, 0xd2,
                0x18, 0xd8,
            ],
            // Round 7.
            [
                0x14, 0x15, 0xb5, 0xbf, 0x46, 0x16, 0x15, 0xec, 0x27, 0x46, 0x56, 0xd7, 0x34, 0x2a,
                0xd8, 0x43,
            ],
            // Round 8.
            [
                0x00, 0x51, 0x2f, 0xd1, 0xb1, 0xc8, 0x89, 0xff, 0x54, 0x76, 0x6d, 0xcd, 0xfa, 0x1b,
                0x99, 0xea,
            ],
            // Round 9.
            [
                0x47, 0x37, 0x94, 0xed, 0x40, 0xd4, 0xe4, 0xa5, 0xa3, 0x70, 0x3a, 0xa6, 0x4c, 0x9f,
                0x42, 0xbc,
            ],
            // Round 10 (at round 10 mix columns is unnecessary).
            [
                0x47, 0x37, 0x94, 0xed, 0x40, 0xd4, 0xe4, 0xa5, 0xa3, 0x70, 0x3a, 0xa6, 0x4c, 0x9f,
                0x42, 0xbc,
            ],
        ];

        // Round 0.
        let start_of_round = add_round_key(&plaintext, round_keys.first().unwrap());
        assert_eq!(
            start_of_round, expected_start_of_round[0],
            "Start of round is incorrect"
        );

        for i in 0..10 {
            let round = i + 1;
            println!("Start of round {round}");
            assert_round_steps_results_are_the_expected(
                &cs,
                round_keys.get(i + 1).unwrap(),
                *expected_start_of_round
                    .get(i)
                    .expect("Error getting expected start of round"),
                *expected_after_substituting_bytes
                    .get(i)
                    .expect("Error getting expected after substituting bytes"),
                *expected_after_shift_rows
                    .get(i)
                    .expect("Error getting expected after shift rows"),
                *expected_after_mix_columns
                    .get(i)
                    .expect("Error getting expected after mix columns"),
                *expected_start_of_round
                    .get(i + 1)
                    .expect("Error getting expected start of next round"),
                round,
            );
            println!("End of round {round}");
        }
    }

    #[test]
    #[ignore = "Ignoring until we have the universal SRS loaded from a file"]
    fn test_encrypt_a_16_bytes_plaintext() {
        let plaintext: [u8; 16] = [
            0x32, 0x43, 0xf6, 0xa8, 0x88, 0x5a, 0x30, 0x8d, 0x31, 0x31, 0x98, 0xa2, 0xe0, 0x37,
            0x07, 0x34,
        ];
        let key: [u8; 16] = [
            0x2b, 0x7e, 0x15, 0x16, 0x28, 0xae, 0xd2, 0xa6, 0xab, 0xf7, 0x15, 0x88, 0x09, 0xcf,
            0x4f, 0x3c,
        ];
        let (proving_key, _verifying_key) = synthesize_keys(plaintext.len()).unwrap();
        let expected_ciphertext = [
            0x39, 0x25, 0x84, 0x1d, 0x02, 0xdc, 0x09, 0xfb, 0xdc, 0x11, 0x85, 0x97, 0x19, 0x6a,
            0x0b, 0x32,
        ];

        // TODO: Assert against proof.
        let (ciphertext, _proof) = encrypt(&plaintext, &key, proving_key).unwrap();

        assert_eq!(ciphertext, expected_ciphertext);
    }

    #[test]
    #[ignore = "Ignoring until we have the universal SRS loaded from a file"]
    fn test_one_round_aes_encryption_of_a_64_bytes_plaintext() {
        let plaintext: [u8; 64] = [
            0x32, 0x43, 0xf6, 0xa8, 0x88, 0x5a, 0x30, 0x8d, 0x31, 0x31, 0x98, 0xa2, 0xe0, 0x37,
            0x07, 0x34, 0x32, 0x43, 0xf6, 0xa8, 0x88, 0x5a, 0x30, 0x8d, 0x31, 0x31, 0x98, 0xa2,
            0xe0, 0x37, 0x07, 0x34, 0x32, 0x43, 0xf6, 0xa8, 0x88, 0x5a, 0x30, 0x8d, 0x31, 0x31,
            0x98, 0xa2, 0xe0, 0x37, 0x07, 0x34, 0x32, 0x43, 0xf6, 0xa8, 0x88, 0x5a, 0x30, 0x8d,
            0x31, 0x31, 0x98, 0xa2, 0xe0, 0x37, 0x07, 0x34,
        ];
        let key: [u8; 16] = [
            0x2b, 0x7e, 0x15, 0x16, 0x28, 0xae, 0xd2, 0xa6, 0xab, 0xf7, 0x15, 0x88, 0x09, 0xcf,
            0x4f, 0x3c,
        ];
        let (proving_key, _verifying_key) = synthesize_keys(plaintext.len()).unwrap();

        let expected_ciphertext = [
            0x39, 0x25, 0x84, 0x1d, 0x02, 0xdc, 0x09, 0xfb, 0xdc, 0x11, 0x85, 0x97, 0x19, 0x6a,
            0x0b, 0x32, 0x39, 0x25, 0x84, 0x1d, 0x02, 0xdc, 0x09, 0xfb, 0xdc, 0x11, 0x85, 0x97,
            0x19, 0x6a, 0x0b, 0x32, 0x39, 0x25, 0x84, 0x1d, 0x02, 0xdc, 0x09, 0xfb, 0xdc, 0x11,
            0x85, 0x97, 0x19, 0x6a, 0x0b, 0x32, 0x39, 0x25, 0x84, 0x1d, 0x02, 0xdc, 0x09, 0xfb,
            0xdc, 0x11, 0x85, 0x97, 0x19, 0x6a, 0x0b, 0x32,
        ];

        // TODO: Assert against proof.
        let (ciphertext, _proof) = encrypt(&plaintext, &key, proving_key).unwrap();

        assert_eq!(ciphertext, expected_ciphertext);
    }
}
