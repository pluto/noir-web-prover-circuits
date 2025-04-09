use std::hash::poseidon::bn254::hash_1;
pub mod data;
pub mod tests; 

comptime global CARRIAGE_RETURN: u8 = "\r".as_bytes()[0]; // 13
comptime global LINE_FEED: u8 = "\n".as_bytes()[0]; // 10
comptime global COLON: u8 = ":".as_bytes()[0]; // 58
comptime global SPACE: u8 = " ".as_bytes()[0]; // 32

// todo: pack parser into field
struct Parser {
    parsing_start: u8,
    parsing_header: u8,
    parsing_header_name: bool,
    parsing_header_value: bool,
    parsing_body: bool,
    line_status: u8,
    line_digest: Field,
    line_monomial: Field,
}

impl Into<[Field; 8]> for Parser {
    fn into(self) -> [Field; 8] {
        [
            self.parsing_start as Field,
            self.parsing_header as Field,
            self.parsing_header_name as Field,
            self.parsing_header_value as Field,
            self.parsing_body as Field,
            self.line_status as Field,
            self.line_digest,
            self.line_monomial,
        ]
    }
}

impl Parser {
    pub(crate) fn default() -> Self {
        Self {
            parsing_start: 1,
            parsing_header: 0,
            parsing_header_name: false,
            parsing_header_value: false,
            parsing_body: false,
            line_status: 0,
            line_digest: 0,
            line_monomial: 1,
        }
    }

    // unconstrained fn _pack_into_field(self) -> Field {
    //     self.parsing_start as Field +
    //     self.parsing_header as Field * 0x1000 +
    //     self.parsing_header_name as Field << 6 +
    //     self.parsing_header_value as Field << 7 +
    //     self.parsing_body as Field << 8 +
    //     self.line_status as Field << 9
    // }

    fn digest(self, polynomial_input: Field) -> Field {
        polynomial_digest(self.into(), polynomial_input, 1)
    }

    fn update_state(self, character: u8 ) -> Self {
        let mut state = self;

        if !state.parsing_body {
            // TODO: note, this does not check the state of `parsing_header_name` and `parsing_header_value` are valid
            // Handle the line breaking
            if (self.line_status == 2) & (character != CARRIAGE_RETURN) {
                state.parsing_header += 1;
                state.parsing_header_name = true;
                state.parsing_start = 0;
                state.line_status = 0;
            }
            // Handle parsing body
            else if state.line_status == 4 {
                state.parsing_header = 0; // TODO: this is a little bit unintuitive, but we'll start counting headers at 1?
                state.parsing_header_value = false;
                state.parsing_body = true;
                state.line_status = 0;
            }
            // Handle start line
            // TODO: handle multiple spaces between start line
            else if (state.parsing_start != 0) & (character == SPACE) {
                state.parsing_start += 1;
            }
            // Handle headers
            else if state.parsing_header_name & (character == COLON) {
                state.parsing_header_name = false;
                state.parsing_header_value = true;
            }
            // Check for return characters
            else if (character == CARRIAGE_RETURN) & (self.line_status == 0)
                | (self.line_status == 2) {
                state.line_status += 1;
                state.parsing_header_value = false;
            } else if (character == LINE_FEED) & (self.line_status == 1) | (self.line_status == 3) {
                state.line_status += 1;
            } else {
                state.line_status = 0;
            }
        }
        state
    }
}

pub fn parse<let N: u32>(data: str<N>) {
    let mut parser = Parser::default();
    for character in data.as_bytes() {
        parser = parser.update_state(character);
    }
}

// TODO: can we use generics for input?
pub fn polynomial_digest<let N: u32>(
    input: [Field; N],
    polynomial_input: Field,
    monomial_counter: Field,
) -> Field {
    let mut digest = Field::default();

    let mut monomial = monomial_counter;
    for item in input {
        digest += monomial * item; // TODO: check if subtyping is expensive
        monomial *= polynomial_input;
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

// todo: should data be passed as zeroed
pub struct HttpVerification<let N: u32, let NUM_DIGESTS: u32> {
    data: [u8; N],
    line_digests: [Field; NUM_DIGESTS],
    polynomial_input: Field,
}

impl<let N: u32, let NUM_DIGESTS: u32> HttpVerification<N, NUM_DIGESTS> {
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
        let initial_pow_accumulation = step_in[6] * self.polynomial_input;
        let mut pow_accumulation = Field::default();
        let mut body_switch = [Field::default(); N - 1];

        let mut parser = machine_state;

        let mut line_monomials = [Field::default(); N];
        let mut body_monomials = [Field::default(); N];
        let mut body_digest = [Field::default(); N];
        let mut line_digests = [Field::default(); N];
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
            pow_accumulation = initial_pow_accumulation;
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
            let body_or_line_change = parser.parsing_body | (self.data[i] == 10) | (self.data[i] == 13);
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

        // set parser state
        parser.line_digest = line_digests[N - 1];
        parser.line_monomial = line_monomials[N - 1] * self.polynomial_input;
        polynomial_input_pow *= self.polynomial_input;

        let mut step_out = step_in;
        step_out[0] =
            step_in[0] - data_digest + (body_digest[N - 1] * parser.parsing_body as Field);
        step_out[2] = polynomial_input_pow;
        step_out[3] = parser.digest(self.polynomial_input);
        step_out[5] = step_in[5] - num_matched; // TODO: should I check?
        step_out[6] = body_monomials[N - 1];

        step_out
    }
}
