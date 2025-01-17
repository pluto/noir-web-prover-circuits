use ark_ff::PrimeField;
use ark_r1cs_std::{
    alloc::{AllocVar, AllocationMode},
    fields::fp::FpVar,
};
use ark_relations::r1cs::{Namespace, SynthesisError};
use ark_std::fmt::Debug;
use core::borrow::Borrow;

#[derive(Clone, Debug)]
pub struct VecF<F: PrimeField, const L: usize>(pub [F; L]);

impl<F: PrimeField, const L: usize> Default for VecF<F, L> {
    fn default() -> Self {
        VecF([F::zero(); L])
    }
}

#[derive(Clone, Debug)]
pub struct VecFpVar<F: PrimeField, const L: usize>(pub [FpVar<F>; L]);

impl<F: PrimeField, const L: usize> AllocVar<VecF<F, L>, F> for VecFpVar<F, L> {
    fn new_variable<T: Borrow<VecF<F, L>>>(
        cs: impl Into<Namespace<F>>,
        f: impl FnOnce() -> Result<T, SynthesisError>,
        mode: AllocationMode,
    ) -> Result<Self, SynthesisError> {
        f().and_then(|val| {
            let cs = cs.into();
            // Explicitly use the [I; N] implementation
            let arr: [F; L] = val.borrow().0;
            let v =
                <[FpVar<F>; L] as AllocVar<[F; L], F>>::new_variable(cs.clone(), || Ok(arr), mode)?;
            Ok(VecFpVar(v))
        })
    }
}

impl<F: PrimeField, const L: usize> Default for VecFpVar<F, L> {
    fn default() -> Self {
        VecFpVar(core::array::from_fn(|_| FpVar::<F>::Constant(F::zero())))
    }
}
