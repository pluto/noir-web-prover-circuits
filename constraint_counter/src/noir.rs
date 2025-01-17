use acvm::{
    acir::{
        acir_field::GenericFieldElement,
        circuit::{brillig::BrilligBytecode, Circuit, Program},
        native_types::{Witness as AcvmWitness, WitnessMap},
    },
    pwg::ACVM,
};
use ark_ff::PrimeField;
use ark_r1cs_std::{alloc::AllocVar, fields::fp::FpVar, R1CSVar};
use ark_relations::r1cs::{ConstraintSynthesizer, ConstraintSystemRef, SynthesisError};

use serde::{self, Deserialize, Serialize};
use std::collections::HashMap;

use super::*;
use crate::bridge::AcirCircuitSonobe;

use folding_schemes::Error; // TODO: remove this crate entirely

#[derive(Clone, Debug)]
pub struct NoirFCircuit<const PUBLIC_IO_LENGTH: usize, const PRIVATE_INPUT_LENGTH: usize> {
    pub circuit: Circuit<GenericFieldElement<Fr>>,
    pub unconstrained_functions: Vec<BrilligBytecode<GenericFieldElement<Fr>>>,
}

#[derive(Clone, Serialize, Deserialize, Debug)]
pub struct ProgramArtifactGeneric<F: PrimeField> {
    #[serde(
        serialize_with = "Program::serialize_program_base64",
        deserialize_with = "Program::deserialize_program_base64"
    )]
    pub bytecode: Program<GenericFieldElement<F>>,
}

impl<const PUBLIC_IO_LENGTH: usize, const PRIVATE_INPUT_LENGTH: usize>
    NoirFCircuit<PUBLIC_IO_LENGTH, PRIVATE_INPUT_LENGTH>
{
    pub fn new(bin: &[u8]) -> Result<Self, Error> {
        let program: ProgramArtifactGeneric<Fr> =
            serde_json::from_slice(bin).map_err(|err| Error::JSONSerdeError(err.to_string()))?;
        let circuit: Circuit<GenericFieldElement<Fr>> = program.bytecode.functions[0].clone();
        let ivc_input_length = circuit.public_parameters.0.len();
        let ivc_return_length = circuit.return_values.0.len();

        if ivc_input_length != ivc_return_length {
            return Err(Error::NotSameLength(
                "IVC input: ".to_string(),
                ivc_input_length,
                "IVC output: ".to_string(),
                ivc_return_length,
            ));
        }
        if ivc_input_length != PUBLIC_IO_LENGTH {
            return Err(Error::NotSameLength(
                "IVC input: ".to_string(),
                ivc_input_length,
                "PUBLIC_IO_LENGTH: ".to_string(),
                PUBLIC_IO_LENGTH,
            ));
        }

        Ok(Self {
            circuit,
            unconstrained_functions: program.bytecode.unconstrained_functions,
        })
    }

    pub fn generate_step_constraints(
        &self,
        cs: ConstraintSystemRef<Fr>,
        z_i: [FpVar<Fr>; PUBLIC_IO_LENGTH],
        external_inputs: [FpVar<Fr>; PRIVATE_INPUT_LENGTH],
    ) -> Result<Vec<FpVar<Fr>>, SynthesisError> {
        let mut acvm = ACVM::new(
            &bn254_blackbox_solver::Bn254BlackBoxSolver(false),
            &self.circuit.opcodes,
            WitnessMap::new(),
            &self.unconstrained_functions,
            &[],
        );

        let mut already_assigned_witness_values = HashMap::new();

        self.circuit.public_parameters.0.iter().for_each(|witness| {
            let idx: usize = witness.as_usize();
            let witness = AcvmWitness(witness.witness_index());
            already_assigned_witness_values.insert(witness, &z_i[idx]);
            let val = z_i[idx].value().unwrap();

            let f = GenericFieldElement::<Fr>::from_repr(val);
            acvm.overwrite_witness(witness, f);
        });

        // write witness values for external_inputs
        self.circuit.private_parameters.iter().for_each(|witness| {
            let idx = witness.as_usize() - z_i.len();
            let witness = AcvmWitness(witness.witness_index());
            already_assigned_witness_values.insert(witness, &external_inputs[idx]);

            let val = external_inputs[idx].value().unwrap();

            let f = GenericFieldElement::<Fr>::from_repr(val);
            acvm.overwrite_witness(witness, f);
        });

        // computes the witness
        let start = std::time::Instant::now();
        let _status = dbg!(acvm.solve());
        let witness_map = acvm.finalize();
        println!("ACVM solve and finalize: {:?}", start.elapsed());

        // get the z_{i+1} output state
        let assigned_z_i1 = self
            .circuit
            .return_values
            .0
            .iter()
            .map(|witness| {
                let noir_field_element = witness_map
                    .get(witness)
                    .ok_or(SynthesisError::AssignmentMissing)?;
                FpVar::<Fr>::new_witness(cs.clone(), || Ok(noir_field_element.into_repr()))
            })
            .collect::<Result<Vec<FpVar<Fr>>, SynthesisError>>()?;

        // initialize circuit and set already assigned values
        let mut acir_circuit = AcirCircuitSonobe::from((&self.circuit, witness_map));
        acir_circuit.already_assigned_witnesses = already_assigned_witness_values;

        let start = std::time::Instant::now();
        acir_circuit.generate_constraints(cs)?;
        println!(
            "Duration for `acir_circuit.generate_constraints(cs)`: {:?}",
            start.elapsed()
        );

        Ok(assigned_z_i1)
    }
}

#[cfg(test)]
mod tests {
    use ark_bn254::Fr;
    use ark_ff::PrimeField;
    use ark_r1cs_std::R1CSVar;
    use ark_r1cs_std::{alloc::AllocVar, fields::fp::FpVar};
    use ark_relations::r1cs::ConstraintSystem;
    use folding_schemes::{frontend::FCircuit, Error};
    use std::env;

    use crate::noir::NoirFCircuit;

    /// Native implementation of `src/noir/test_folder/test_circuit`
    fn external_inputs_step_native<F: PrimeField>(z_i: Vec<F>, external_inputs: Vec<F>) -> Vec<F> {
        let xx = external_inputs[0] * z_i[0];
        let yy = external_inputs[1] * z_i[1];
        vec![xx, yy]
    }

    #[test]
    fn test_step_native() -> Result<(), Error> {
        let inputs = vec![Fr::from(2), Fr::from(5)];
        let res = external_inputs_step_native(inputs.clone(), inputs);
        assert_eq!(res, vec![Fr::from(4), Fr::from(25)]);
        Ok(())
    }

    // #[test]
    // fn test_step_constraints() -> Result<(), Error> {
    //     let cs = ConstraintSystem::<Fr>::new_ref();
    //     let cur_path = env::current_dir()?;
    //     // external inputs length: 2, state length: 2
    //     let noirfcircuit = NoirFCircuit::<Fr, 2>::new((
    //         cur_path
    //             .join("src/noir/test_folder/test_circuit/target/test_circuit.json")
    //             .into(),
    //         2,
    //     ))?;
    //     let inputs = vec![Fr::from(2), Fr::from(5)];
    //     let z_i = Vec::<FpVar<Fr>>::new_witness(cs.clone(), || Ok(inputs.clone()))?;
    //     let external_inputs = Vec::<FpVar<Fr>>::new_witness(cs.clone(), || Ok(inputs))?;
    //     let output = noirfcircuit.generate_step_constraints(
    //         cs.clone(),
    //         0,
    //         z_i,
    //         VecFpVar(external_inputs),
    //     )?;
    //     assert_eq!(output[0].value()?, Fr::from(4));
    //     assert_eq!(output[1].value()?, Fr::from(25));
    //     Ok(())
    // }

    // #[test]
    // fn test_step_constraints_no_external_inputs() -> Result<(), Error> {
    //     let cs = ConstraintSystem::<Fr>::new_ref();
    //     let cur_path = env::current_dir()?;
    //     // external inputs length: 0, state length: 2
    //     let noirfcircuit = NoirFCircuit::<Fr, 0>::new((
    //         cur_path
    //             .join("src/noir/test_folder/test_no_external_inputs/target/test_no_external_inputs.json")
    //             .into(),
    //         2,
    //     ))
    //     ?;
    //     let inputs = vec![Fr::from(2), Fr::from(5)];
    //     let z_i = Vec::<FpVar<Fr>>::new_witness(cs.clone(), || Ok(inputs.clone()))?;
    //     let external_inputs = vec![];
    //     let output = noirfcircuit.generate_step_constraints(
    //         cs.clone(),
    //         0,
    //         z_i,
    //         VecFpVar(external_inputs),
    //     )?;
    //     assert_eq!(output[0].value()?, Fr::from(4));
    //     assert_eq!(output[1].value()?, Fr::from(25));
    //     Ok(())
    // }
}
