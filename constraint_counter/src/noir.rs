use acvm::{
    acir::{
        acir_field::GenericFieldElement,
        circuit::{brillig::BrilligBytecode, Circuit, Program},
        native_types::{Witness as AcvmWitness, WitnessMap},
    },
    blackbox_solver::StubbedBlackBoxSolver,
    pwg::ACVM,
};
use ark_ff::PrimeField;
use ark_r1cs_std::{alloc::AllocVar, fields::fp::FpVar, R1CSVar};
use ark_relations::r1cs::{ConstraintSynthesizer, ConstraintSystemRef, SynthesisError};

use serde::{self, Deserialize, Serialize};
use std::collections::HashMap;

use super::*;
use crate::bridge::AcirCircuitSonobe;

#[derive(Clone, Debug)]
pub struct NoirFCircuit {
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

impl NoirFCircuit {
    pub fn new(bin: &[u8]) -> Self {
        let program: ProgramArtifactGeneric<Fr> = serde_json::from_slice(bin).unwrap();
        let circuit: Circuit<GenericFieldElement<Fr>> = program.bytecode.functions[0].clone();
        let public_io_length = circuit.public_parameters.0.len();
        let ivc_return_length = circuit.return_values.0.len();

        if public_io_length != ivc_return_length {
            panic!("Public input and output are not the same length!'\n    IVC input: {public_io_length}\n    IVC output: {ivc_return_length}");
        }

        Self {
            circuit,
            unconstrained_functions: program.bytecode.unconstrained_functions,
        }
    }

    pub fn generate_step_constraints(
        &self,
        cs: ConstraintSystemRef<Fr>,
        z_i: &[FpVar<Fr>],
        external_inputs: &[FpVar<Fr>],
    ) -> Result<Vec<FpVar<Fr>>, SynthesisError> {
        let mut acvm = ACVM::new(
            &StubbedBlackBoxSolver(false),
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
        let _status = acvm.solve();
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
