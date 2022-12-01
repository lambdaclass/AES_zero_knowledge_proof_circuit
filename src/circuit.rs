/// Ark deps
use ark_crypto_primitives::encryption::constraints::AsymmetricEncryptionGadget;
use ark_crypto_primitives::encryption::elgamal::{
    constraints::ElGamalEncGadget, ElGamal,
};
use ark_crypto_primitives::encryption::AsymmetricEncryptionScheme;
use ark_ed_on_bls12_381::{
    constraints::EdwardsVar, EdwardsParameters, EdwardsProjective as JubJub, Fq,
};
use ark_r1cs_std::prelude::*;
use ark_relations::r1cs::{ConstraintSystem, ConstraintSystemRef, Namespace, SynthesisError};
use ark_std::{test_rng, UniformRand};
type Enc = ElGamal<JubJub>;
type Gadget = ElGamalEncGadget<JubJub, EdwardsVar>;
type CS = ConstraintSystem<Fq>;
type CSRef = ConstraintSystemRef<Fq>;
type CurveRandomness = ark_crypto_primitives::encryption::elgamal::Randomness<
    ark_ec::models::twisted_edwards_extended::GroupProjective<EdwardsParameters>,
>;
type EdwardsAffine = ark_ec::models::twisted_edwards_extended::GroupAffine<EdwardsParameters>;
type CurveParameters = ark_crypto_primitives::encryption::elgamal::Parameters<
    ark_ec::models::twisted_edwards_extended::GroupProjective<EdwardsParameters>,
>;
#[allow(dead_code)]
pub struct ElGamalMessage {
    /// Little-endian representation: least significant bit first
    pub(crate) bytes: Vec<UInt8<Fq>>,
    pub(crate) value: Option<[u8; 256]>,
}
impl AllocVar<[u8; 256], Fq> for ElGamalMessage {
    fn new_variable<T: std::borrow::Borrow<[u8; 256]>>(
        cs: impl Into<Namespace<Fq>>,
        f: impl FnOnce() -> Result<T, SynthesisError>,
        mode: AllocationMode,
    ) -> Result<Self, SynthesisError> {
        let ns = cs.into();
        let cs = ns.cs();
        let value = f().map(|f| *f.borrow()).ok();

        let mut address_as_bytes = vec![];
        if let Some(val) = value {
            for byte in val {
                address_as_bytes.push(UInt8::new_variable(cs.clone(), || Ok(byte), mode)?);
            }
        }

        Ok(Self {
            bytes: address_as_bytes,
            value,
        })
    }
}

pub struct CircuitParams {
    public_key: EdwardsAffine,
    randomness: CurveRandomness,
    parameters: CurveParameters,
}

pub fn setup_circuit_params() -> CircuitParams {
    let rng = &mut test_rng();
    let parameters = Enc::setup(rng).unwrap();
    let (public_key, _secret_key) = Enc::keygen(&parameters, rng).unwrap();
    let randomness = CurveRandomness::rand(rng);
    return CircuitParams {
        public_key,
        parameters,
        randomness,
    };
}
pub fn build_encrypt_circuit(message: &[u8; 256]) -> CSRef {
    let CircuitParams {
        public_key,
        randomness,
        parameters,
    } = setup_circuit_params();
    let cs = CS::new_ref();
    let _randomness_var =
        <Gadget as AsymmetricEncryptionGadget<Enc, Fq>>::RandomnessVar::new_witness(
            ark_relations::ns!(cs, "randomness"),
            || Ok(&randomness),
        );
    let _parameters_var =
        <Gadget as AsymmetricEncryptionGadget<Enc, Fq>>::ParametersVar::new_constant(
            ark_relations::ns!(cs, "parameters"),
            &parameters,
        );
    let _msg_var = ElGamalMessage::new_witness(ark_relations::ns!(cs, "msg"), || Ok(message));
    let _public_key = <Gadget as AsymmetricEncryptionGadget<Enc, Fq>>::PublicKeyVar::new_witness(
        ark_relations::ns!(cs, "public_key"),
        || Ok(&public_key),
    );
    cs.is_satisfied().unwrap();
    return cs;
}
