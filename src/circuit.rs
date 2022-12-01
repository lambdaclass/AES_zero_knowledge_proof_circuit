/// Ark deps
use ark_crypto_primitives::encryption::constraints::AsymmetricEncryptionGadget;
use ark_crypto_primitives::encryption::elgamal::constraints::{
    ParametersVar, PlaintextVar, RandomnessVar,
};
use ark_crypto_primitives::encryption::elgamal::{
    constraints::ElGamalEncGadget, ElGamal, Plaintext, Randomness,
};
use ark_crypto_primitives::encryption::{elgamal, AsymmetricEncryptionScheme};
use ark_ec::models::twisted_edwards_extended;
use ark_ed_on_bls12_381::{constraints::EdwardsVar, EdwardsProjective as JubJub, Fq};
use ark_r1cs_std::prelude::*;
use ark_relations::r1cs::{ConstraintSystem, ConstraintSystemRef};
use ark_std::str::FromStr;
use ark_std::{test_rng, UniformRand};
type Enc = ElGamal<JubJub>;
type Gadget = ElGamalEncGadget<JubJub, EdwardsVar>;
type CS = ConstraintSystem<Fq>;
type CSRef = ConstraintSystemRef<Fq>;
type Rand = Randomness<JubJub>;
use ark_bls12_381::{Bls12_381, Fr};
/// Marlin
use ark_marlin::{Marlin, SimpleHashFiatShamirRng};
use ark_poly::univariate::DensePolynomial;
use ark_poly_commit::marlin_pc::MarlinKZG10;
use blake2::Blake2s;
use rand_chacha::ChaChaRng;
type MultiPC = MarlinKZG10<Bls12_381, DensePolynomial<Fr>>;
type FS = SimpleHashFiatShamirRng<Blake2s, ChaChaRng>;
type MarlinInst = Marlin<Fr, MultiPC, FS>;

// #[derive(Clone)]
// pub struct EncryptCircuit {
//     randomness: RandomnessVar<Fq>,
//     // parameters_var: ParametersVar<JubJub>,
//     msg_var: String,
//     pk_var: String,
//     public_key: String,
// }
pub fn build_encrypt_circuit(message: &str) -> CSRef {
    let rng = &mut test_rng();
    let parameters = Enc::setup(rng).unwrap();
    let (pk, _sk) = Enc::keygen(&parameters, rng).unwrap();
    let msg = twisted_edwards_extended::GroupAffine::from_str("Hello, World!").unwrap();
    // let msg = JubJub::rand(rng).into();
    let randomness: Rand = Randomness::rand(rng);
    // let primitive_result = Enc::encrypt(&parameters, &pk, &my_msg, &randomness).unwrap();

    // construct constraint system
    let cs = CS::new_ref();
    let randomness_var =
        <Gadget as AsymmetricEncryptionGadget<Enc, Fq>>::RandomnessVar::new_witness(
            ark_relations::ns!(cs, "randomness"),
            || Ok(&randomness),
        )
        .unwrap();
    let parameters_var =
        <Gadget as AsymmetricEncryptionGadget<Enc, Fq>>::ParametersVar::new_constant(
            ark_relations::ns!(cs, "parameters"),
            &parameters,
        )
        .unwrap();
    let msg_var = <Gadget as AsymmetricEncryptionGadget<Enc, Fq>>::PlaintextVar::new_witness(
        ark_relations::ns!(cs, "message"),
        || Ok(&msg),
    )
    .unwrap();
    let pk_var = <Gadget as AsymmetricEncryptionGadget<Enc, Fq>>::PublicKeyVar::new_witness(
        ark_relations::ns!(cs, "public_key"),
        || Ok(&pk),
    )
    .unwrap();

    // check that result equals expected ciphertext in the constraint system
    // let expected_var = <Gadget as AsymmetricEncryptionGadget<Enc, Fq>>::OutputVar::new_input(
    //     ark_relations::ns!(cs, "expected"),
    //     || Ok(&primitive_result),
    // )
    // .unwrap();
    // let (index_pk, index_vk) = MarlinInst::index(&universal_srs, cs).unwrap();
    // let result_var = Gadget::encrypt(&parameters_var, &msg_var, &randomness_var, &pk_var).unwrap();
    cs.is_satisfied().unwrap();
    return cs;
}
