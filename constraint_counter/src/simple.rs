use std::collections::HashMap;

use acvm::{
    acir::{
        acir_field::GenericFieldElement,
        circuit::{brillig::BrilligBytecode, Circuit, Opcode, Program},
        native_types::Witness,
    },
    AcirField,
};
use ark_ff::Field;
use ark_relations::{
    lc,
    r1cs::{ConstraintSynthesizer, LinearCombination, Variable},
};
use serde::{Deserialize, Serialize};

use super::*;

#[derive(Clone, Serialize, Deserialize, Debug)]
pub struct NoirProgram {
    #[serde(
        serialize_with = "Program::serialize_program_base64",
        deserialize_with = "Program::deserialize_program_base64"
    )]
    pub bytecode: Program<GenericFieldElement<Fr>>,
}

impl NoirProgram {
    pub fn new(bin: &[u8]) -> Self {
        serde_json::from_slice(bin).unwrap()
    }

    pub fn circuit(&self) -> &Circuit<GenericFieldElement<Fr>> {
        &self.bytecode.functions[0]
    }

    pub fn unconstrained_functions(&self) -> &Vec<BrilligBytecode<GenericFieldElement<Fr>>> {
        &self.bytecode.unconstrained_functions
    }
}

impl ConstraintSynthesizer<Fr> for NoirProgram {
    fn generate_constraints(self, cs: ConstraintSystemRef<Fr>) -> ark_relations::r1cs::Result<()> {
        let mut witness_map: HashMap<Witness, Variable> = HashMap::new();

        for opcode in self.circuit().opcodes.iter() {
            if let Opcode::AssertZero(gate) = opcode {
                let mut left_terms = LinearCombination::<Fr>::new();
                let mut right_terms = LinearCombination::<Fr>::new();
                let mut output_terms = LinearCombination::<Fr>::new();

                // Handle multiplication terms
                for mul_term in &gate.mul_terms {
                    let coeff = Fr::from(mul_term.0.into_repr());
                    let left_var = allocate_variable(&mut witness_map, mul_term.1, &cs)?;
                    let right_var = allocate_variable(&mut witness_map, mul_term.2, &cs)?;

                    left_terms += (coeff, left_var);
                    right_terms += (Fr::ONE, right_var);
                }

                // Handle linear combinations (add terms)
                for add_term in &gate.linear_combinations {
                    let coeff = Fr::from(add_term.0.into_repr());
                    let var = allocate_variable(&mut witness_map, add_term.1, &cs)?;

                    // Add to the output terms
                    output_terms += (coeff, var);
                }

                // Add constant term if present
                if !gate.q_c.is_zero() {
                    output_terms += (Fr::from(gate.q_c.into_repr()), Variable::One);
                }

                // The constraint becomes: left_terms * right_terms + output_terms = 0
                cs.enforce_constraint(left_terms, right_terms, -output_terms)?;
            }
        }

        Ok(())
    }
}

// Helper function to allocate variables in the constraint system
fn allocate_variable(
    witness_map: &mut HashMap<Witness, Variable>,
    witness: Witness,
    cs: &ConstraintSystemRef<Fr>,
) -> ark_relations::r1cs::Result<Variable> {
    if let Some(&var) = witness_map.get(&witness) {
        Ok(var)
    } else {
        // Create a new variable without needing concrete witness values
        let var = cs.new_witness_variable(|| Ok(Fr::ZERO))?;
        witness_map.insert(witness, var);
        Ok(var)
    }
}
