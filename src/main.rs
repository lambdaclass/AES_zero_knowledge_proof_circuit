/// Ark deps
use ark_crypto_primitives::encryption::constraints::AsymmetricEncryptionGadget;
use ark_crypto_primitives::encryption::elgamal::{constraints::ElGamalEncGadget, ElGamal, Randomness};
use ark_crypto_primitives::encryption::AsymmetricEncryptionScheme;
use ark_ed_on_bls12_381::{constraints::EdwardsVar, EdwardsProjective as JubJub, Fq};
use ark_r1cs_std::prelude::*;
use ark_relations::r1cs::{ConstraintSystem, ConstraintSystemRef};
use ark_std::{test_rng, UniformRand};
use ark_std::str::FromStr;
use ark_ec::models::twisted_edwards_extended;
type Enc = ElGamal<JubJub>;
type Gadget = ElGamalEncGadget<JubJub, EdwardsVar>;
type CS = ConstraintSystem<Fq>;
type CSRef = ConstraintSystemRef<Fq>;
type Rand = Randomness<JubJub>;
fn main() {
    build_encrypt_circuit("MyPrivateKey");
}
fn build_encrypt_circuit(message: &str) -> CSRef {
    let rng = &mut test_rng();
    // compute primitive result
    let parameters = Enc::setup(rng).unwrap();
    let (pk, _sk) = Enc::keygen(&parameters, rng).unwrap();
    let my_msg = twisted_edwards_extended::GroupAffine::from_str(message).unwrap();
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
        || Ok(&my_msg),
    )
    .unwrap();
    let pk_var = <Gadget as AsymmetricEncryptionGadget<Enc, Fq>>::PublicKeyVar::new_witness(
        ark_relations::ns!(cs, "public_key"),
        || Ok(&pk),
    )
    .unwrap();

    // use gadget
    let result_var =
        Gadget::encrypt(&parameters_var, &msg_var, &randomness_var, &pk_var).unwrap();

    // check that result equals expected ciphertext in the constraint system
    // let expected_var = <Gadget as AsymmetricEncryptionGadget<Enc, Fq>>::OutputVar::new_input(
    //     ark_relations::ns!(cs, "expected"),
    //     || Ok(&primitive_result),
    // )
    // .unwrap();
    return cs;
}
