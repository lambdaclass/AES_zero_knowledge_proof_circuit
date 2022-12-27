use anyhow::anyhow;
use ark_relations::r1cs::SynthesisError;

pub trait ToAnyhow<T> {
    fn to_anyhow(self, error_message: &str) -> anyhow::Result<T>;
}

impl<T> ToAnyhow<T> for Result<T, SynthesisError> {
    fn to_anyhow(self, error_message: &str) -> anyhow::Result<T> {
        self.map_err(|primitive_error_message| {
            anyhow!("{error_message}: {primitive_error_message}")
        })
    }
}

impl<T> ToAnyhow<T> for Option<T> {
    fn to_anyhow(self, error_message: &str) -> anyhow::Result<T> {
        self.ok_or_else(|| anyhow!("{error_message}"))
    }
}
