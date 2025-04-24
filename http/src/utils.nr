use std::hash::poseidon::bn254::hash_1;

// TODO: can we use generics for input?
pub fn polynomial_digest<let N: u32>(
    input: [Field; N],
    digest_ratio: Field,
    default_multiplier: Field,
) -> Field {
    let mut digest = Field::default();

    let mut multiplier = default_multiplier;
    for item in input {
        digest += multiplier * item; // TODO: check if subtyping is expensive
        multiplier *= digest_ratio;
    }

    digest
}

pub fn hash_accumulate<let N: u32>(input: [Field; N]) -> Field {
    let mut output = Field::default();

    for item in input {
        // filter only non-zero items
        if item != 0 {
            let hashed = hash_1([item]);
            output += hashed;
        }
    }

    output
}
