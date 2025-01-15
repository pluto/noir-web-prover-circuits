pub mod noir;

const NOIR_JSON: &[u8] = include_bytes!("../../target/bin.json");

pub fn main() {
    dbg!(noir::num_constraints::<ark_bn254::Fr>(NOIR_JSON));
}
