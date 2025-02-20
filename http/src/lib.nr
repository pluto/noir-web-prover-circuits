use std::hash::poseidon::bn254::hash_1;

comptime global CARRIAGE_RETURN: u8 = "\r".as_bytes()[0];
comptime global LINE_FEED: u8 = "\n".as_bytes()[0];
comptime global COLON: u8 = ":".as_bytes()[0];
comptime global SPACE: u8 = " ".as_bytes()[0];

// comptime global CARRIAGE_RETURN: Field = 13;
// comptime global LINE_FEED: Field = 10;
// comptime global COLON: Field = 58;
// comptime global SPACE: Field = 32;

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

    fn update_state(self, character: u8, polynomial_input: Field) -> Self {
        let mut state = self;

        if !state.parsing_body {
            // TODO: note, this does not check the state of `parsing_header_name` and `parsing_header_value` are valid
            // Handle the line breaking
            if (self.line_status == 2) & (character != CARRIAGE_RETURN) {
                state.parsing_header += 1;
                state.parsing_header_name = true;
                state.parsing_start = 0;
                state.line_status = 0;
                state.line_digest = state.line_monomial * character as Field;
                state.line_monomial *= polynomial_input;
            }
            // Handle parsing body
            else if state.line_status == 4 {
                state.parsing_header = 0; // TODO: this is a little bit unintuitive, but we'll start counting headers at 1?
                state.parsing_header_value = false;
                state.parsing_body = true;
                state.line_status = 0;
                state.line_digest += state.line_monomial * character as Field;
                state.line_monomial *= polynomial_input;
            }
            // Handle start line
            // TODO: handle multiple spaces between start line
            else if (state.parsing_start != 0) & (character == SPACE) {
                state.parsing_start += 1;
                state.line_digest += state.line_monomial * character as Field;
                state.line_monomial *= polynomial_input;
            }
            // Handle headers
            else if state.parsing_header_name & (character == COLON) {
                state.parsing_header_name = false;
                state.parsing_header_value = true;
                state.line_digest += state.line_monomial * character as Field;
                state.line_monomial *= polynomial_input;
            }
            // Check for return characters
            else if (character == CARRIAGE_RETURN) & (self.line_status == 0)
                | (self.line_status == 2) {
                state.line_status += 1;
                state.parsing_header_value = false;
                state.line_digest = -1;
                state.line_monomial = 1;
            } else if (character == LINE_FEED) & (self.line_status == 1) | (self.line_status == 3) {
                state.line_status += 1;
                state.line_digest = -1;
                state.line_monomial = 1;
            } else {
                state.line_status = 0;
                state.line_digest += state.line_monomial * character as Field;
                state.line_monomial *= polynomial_input;
            }
        }
        state
    }
}

pub fn parse<let N: u32>(data: str<N>, polynomial_input: Field) {
    let mut parser = Parser::default();
    for character in data.as_bytes() {
        parser = parser.update_state(character, polynomial_input);
        // println(character);
        // println(parser);
    }
    // Assert HTTP was valid
    // assert(parser.parsing_start == 1);
    // assert(parser.parsing_header == 0);
    // assert(!parser.parsing_header_name);
    // assert(!parser.parsing_header_value);
    // assert(parser.parsing_body);
    // assert(parser.line_status == 0);
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
        let hashed = hash_1([item]);
        output += hashed;
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

        // assertions
        let line_digests_hash = hash_accumulate(self.line_digests);
        assert_eq(machine_state.digest(self.polynomial_input), step_in[3]);
        assert_eq(line_digests_hash, step_in[4]);

        let mut parser = machine_state;
        let mut num_matched: Field = 0;
        let mut polynomial_input_pow = step_in[2];
        for i in 0..N {
            parser = parser.update_state(self.data[i], self.polynomial_input);
            num_matched += self.line_digests.any(|x| x == parser.line_digest) as Field;
            if self.data[i] != 0 {
                polynomial_input_pow *= self.polynomial_input;
            }
        }

        println(parser);
        println(data_digest);

        // step_in[6]: body_monomials not needed?
        let mut step_out = step_in;
        step_out[0] =
            step_in[0] - data_digest + (parser.line_digest * parser.parsing_body as Field);
        step_out[2] = polynomial_input_pow;
        step_out[3] = parser.digest(self.polynomial_input);
        step_out[5] = step_in[5] - num_matched;

        step_out
    }
}

mod tests {
    use super::{hash_accumulate, HttpVerification, parse, Parser, polynomial_digest};
    use std::hash::poseidon::bn254::hash_1;

    global NUM_HEADERS: u32 = 10;
    global PUBLIC_IO_LENGTH: u32 = 11;

    global data: str<89> = "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: 19\r\n\r\n{\"success\":\"true\"}";

    fn polynomial_input() -> Field {
        hash_1([69])
    }

    #[test]
    fn test_parse() {
        parse(data, polynomial_input());
    }

    #[test]
    fn test_http_verification() {
        let polynomial_input = polynomial_input();

        let mut line_digests = [Field::default(); NUM_HEADERS];
        let input = "HTTP/1.1 200 OK".as_bytes().map(|x| x as Field);
        line_digests[0] = polynomial_digest(input, polynomial_input, 1);
        let input_1 = "Content-Type: application/json".as_bytes().map(|x| x as Field);
        line_digests[1] = polynomial_digest(input_1, polynomial_input, 1);

        let http_verification =
            HttpVerification { data: data.as_bytes(), line_digests, polynomial_input };

        let machine_state = Parser::default();
        let step_in = [
            0,
            0,
            1,
            machine_state.digest(polynomial_input),
            hash_accumulate(line_digests),
            2,
            0,
            0,
            0,
            0,
            0,
        ];
        let step_out = http_verification.verify(step_in, machine_state);

        println(step_out);
    }
}
