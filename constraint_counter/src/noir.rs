use std::collections::BTreeMap;

use acvm::{
    acir::{
        acir_field::GenericFieldElement,
        circuit::{Circuit, Opcode, Program},
        native_types::{Witness, WitnessMap},
    },
    blackbox_solver::StubbedBlackBoxSolver,
    pwg::ACVM,
};
use ark_ff::{Field, PrimeField};

use ark_r1cs_std::{alloc::AllocVar, fields::fp::FpVar};
use ark_relations::{
    lc,
    r1cs::{ConstraintSystem, LinearCombination, Variable},
};
use serde::{self, Deserialize, Serialize};

#[derive(Clone, Serialize, Deserialize, Debug)]
pub struct ProgramArtifactGeneric<F: PrimeField> {
    #[serde(
        serialize_with = "Program::serialize_program_base64",
        deserialize_with = "Program::deserialize_program_base64"
    )]
    pub bytecode: Program<GenericFieldElement<F>>,
}

pub fn num_constraints<F: Field + PrimeField>(bytes: &[u8]) -> usize {
    let program: ProgramArtifactGeneric<F> = serde_json::from_slice(bytes).unwrap();
    let circuit: Circuit<GenericFieldElement<F>> = program.bytecode.functions[0].clone();

    let mut acvm = ACVM::new(
        &StubbedBlackBoxSolver(false),
        &circuit.opcodes,
        WitnessMap::new(),
        &[],
        &[],
    );

    let _ = acvm.solve();
    let witness_map = acvm.finalize();

    // Get gates and vars and shit
    let public_inputs = circuit.public_inputs();
    let gates: Vec<_> = circuit
        .opcodes
        .iter()
        .filter_map(|opcode| {
            if let Opcode::AssertZero(code) = opcode {
                Some(code.clone())
            } else {
                None
            }
        })
        .collect();

    let num_variables: usize = circuit.num_vars().try_into().unwrap();

    let values: BTreeMap<Witness, _> = (0..num_variables)
        .map(|witness_index| {
            // Get the value if it exists. If i does not, then we fill it with the zero value
            let witness = Witness(witness_index as u32);
            let value = witness_map
                .get(&witness)
                .map_or(F::zero(), |field| field.into_repr());

            (witness, value)
        })
        .collect();

    // Now write to a CS
    let mut variables = Vec::with_capacity(values.len());
    let cs = ConstraintSystem::<F>::new_ref();

    // First create all of the witness indices by adding the values into the constraint system
    for (i, val) in values.iter() {
        let var = if public_inputs.contains(i.0.try_into().unwrap()) {
            cs.new_witness_variable(|| Ok(*val)).unwrap()
        } else {
            cs.new_witness_variable(|| Ok(*val)).unwrap()
        };
        variables.push(var);
    }

    // Now iterate each gate and add it to the constraint system
    for gate in gates {
        let mut arith_gate = LinearCombination::<F>::new();

        // Process mul terms
        for mul_term in gate.mul_terms {
            let coeff = mul_term.0;
            let left_val = values[&mul_term.1];
            let right_val = values[&mul_term.2];

            let out_val = left_val * right_val;
            let out_var = FpVar::<F>::new_witness(cs.clone(), || Ok(out_val)).unwrap();
            // out var can't be a type different from FpVar::Var
            if let FpVar::Var(allocated) = out_var {
                arith_gate += (coeff.into_repr(), allocated.variable);
            }
        }

        // Process Add terms
        for add_term in gate.linear_combinations {
            let coeff = add_term.0;
            let add_var = &variables[add_term.1.as_usize()];
            arith_gate += (coeff.into_repr(), *add_var);
        }

        // Process constant term
        arith_gate += (gate.q_c.into_repr(), Variable::One);

        cs.enforce_constraint(lc!() + Variable::One, arith_gate, lc!())
            .unwrap();
    }
    cs.num_constraints()
}
