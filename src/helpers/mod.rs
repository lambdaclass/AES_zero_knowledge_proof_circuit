use self::traits::ToAnyhow;
use anyhow::Result;
use ark_bls12_377::Fq;
use ark_r1cs_std::{prelude::AllocVar, uint8::UInt8};
use ark_relations::r1cs::ConstraintSystemRef;

pub mod traits;

pub fn to_matrix_gadget(
    primitive_matrix: Vec<Vec<u8>>,
    cs: &ConstraintSystemRef<Fq>,
) -> Result<Vec<Vec<UInt8<Fq>>>> {
    let mut gadget_lookup_table = Vec::new();
    primitive_matrix.iter().try_for_each(|row| {
        let mut gadget_row = Vec::new();
        row.iter().try_for_each(|row_element| {
            gadget_row.push(
                UInt8::<Fq>::new_constant(
                    ark_relations::ns!(cs, "lookup table element"),
                    row_element,
                )
                .to_anyhow("Error allocating lookup table")?,
            );
            Ok::<_, anyhow::Error>(())
        })?;
        gadget_lookup_table.push(gadget_row);
        Ok::<_, anyhow::Error>(())
    })?;

    Ok(gadget_lookup_table)
}
