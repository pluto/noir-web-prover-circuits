use crate::{CARRIAGE_RETURN, COLON, LINE_FEED, SPACE};
use crate::utils::polynomial_digest;

// todo: pack parser into field
pub struct Parser {
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

    fn digest(self, polynomial_input: Field) -> Field {
        polynomial_digest(self.into(), polynomial_input, 1)
    }

    fn update_state(self, character: u8) -> Self {
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
