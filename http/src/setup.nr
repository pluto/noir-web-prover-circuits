use crate::parser::Parser;
use crate::utils::{hash_accumulate, polynomial_digest};

// todo: should data be passed as zeroed
pub struct SetupState<let N: u32, let NUM_DIGESTS: u32> {
    data: [u8; N],
    line_digests: [Field; NUM_DIGESTS],
    polynomial_input: Field,
}

impl<let N: u32, let NUM_DIGESTS: u32> SetupState<N, NUM_DIGESTS> {
    fn verify<let PUBLIC_IO_LENGTH: u32>(
        self,
        step_in: [Field; PUBLIC_IO_LENGTH],
        machine_state: Parser,
    ) -> [Field; PUBLIC_IO_LENGTH] {
        let data_as_field = self.data.map(|f| f as Field);
        let data_digest = polynomial_digest(data_as_field, self.polynomial_input, step_in[2]);
        let line_digests_hash = hash_accumulate(self.line_digests);

        assert_eq(machine_state.digest(self.polynomial_input), step_in[3]);
        assert_eq(line_digests_hash, step_in[4]);

        let mut polynomial_input_pow = step_in[2];
        let body_ctr_is_zero = step_in[6] == 0;
        let mut pow_accumulation = Field::default();
        let mut body_switch = [Field::default(); N - 1];

        let mut parser = machine_state;

        let mut line_monomials = [Field::default(); N];
        let mut body_monomials = [Field::default(); N];
        let mut line_digests = [Field::default(); N];
        let mut body_digest = [Field::default(); N];
        let mut num_matched: Field = 0;

        let mut body_ctr = [Field::default(); N];
        if body_ctr_is_zero {
            if parser.parsing_body {
                pow_accumulation = 1;
                body_ctr[0] = 1;
            } else {
                pow_accumulation = 0;
                body_ctr[0] = 0;
            }
        } else {
            pow_accumulation = step_in[6];
            body_ctr[0] = 1;
        }

        body_monomials[0] = pow_accumulation;
        body_digest[0] = body_monomials[0] * data_as_field[0];
        line_monomials[0] = machine_state.line_monomial;
        line_digests[0] = machine_state.line_digest;

        for i in 1..N {
            // memorize parser state
            parser = parser.update_state(self.data[i]);

            // update polynomial input power
            if self.data[i - 1] != 0 {
                polynomial_input_pow *= self.polynomial_input;
            }

            // body_monomials, body_digest
            body_ctr[i] = body_ctr[i - 1];
            if (parser.parsing_body) {
                body_ctr[i] += 1;
            }

            body_switch[i - 1] = (body_ctr[i] == 1) as Field;
            body_monomials[i] = body_monomials[i - 1] * self.polynomial_input + body_switch[i - 1];
            body_digest[i] = body_digest[i - 1] + body_monomials[i] * data_as_field[i];

            // line_monomials
            let body_or_line_change =
                parser.parsing_body | (self.data[i] == 10) | (self.data[i] == 13);
            let was_cleared = line_monomials[i - 1] == 0;

            if body_or_line_change {
                line_monomials[i] = 0;
            } else {
                if was_cleared {
                    line_monomials[i] = 1;
                } else {
                    line_monomials[i] = line_monomials[i - 1] * self.polynomial_input;
                }
            }

            // calc line_digests
            let mut accum_prev = Field::default();
            if was_cleared {
                accum_prev = 0;
            } else {
                accum_prev = line_digests[i - 1];
            }
            line_digests[i] = accum_prev + data_as_field[i - 1] * line_monomials[i - 1];

            let mut is_match = false;
            if line_digests[i] != 0 {
                is_match = self.line_digests.any(|x| x == line_digests[i]);
                if is_match {
                    num_matched += 1;
                }
            }
        }

        // set next parser state
        parser.line_digest = line_digests[N - 1];
        parser.line_monomial = line_monomials[N - 1] * self.polynomial_input;

        let next_polynomial_input_pow = polynomial_input_pow * self.polynomial_input;
        let next_body_monomial = body_monomials[N - 1] * self.polynomial_input;

        let mut step_out = step_in;
        // step_out[1] == step_in[1], step_out[4] = step_in[4]

        step_out[0] =
            step_in[0] - data_digest + (body_digest[N - 1] * parser.parsing_body as Field);
        step_out[2] = next_polynomial_input_pow;
        step_out[3] = parser.digest(self.polynomial_input);
        step_out[5] = step_in[5] - num_matched;
        step_out[6] = next_body_monomial;

        step_out
    }
}
