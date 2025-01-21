comptime global CARRIAGE_RETURN: u8 = "\r".as_bytes()[0];
comptime global LINE_FEED: u8 = "\n".as_bytes()[0];
comptime global COLON: u8 = ":".as_bytes()[0];
comptime global SPACE: u8 = " ".as_bytes()[0];

// comptime global CARRIAGE_RETURN: Field = 13;
// comptime global LINE_FEED: Field = 10;
// comptime global COLON: Field = 58;
// comptime global SPACE: Field = 32;

struct Parser {
    parsing_start: Field,
    parsing_header: Field,
    parsing_header_name: bool,
    parsing_header_value: bool,
    parsing_body: bool,
    line_status: Field,
}

impl Parser {
    fn default() -> Self {
        Self {
            parsing_start: 1,
            parsing_header: 0,
            parsing_header_name: false,
            parsing_header_value: false,
            parsing_body: false,
            line_status: 0,
        }
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
            if state.line_status == 4 {
                state.parsing_header = 0; // TODO: this is a little bit unintuitive, but we'll start counting headers at 1?
                state.parsing_header_value = false;
                state.parsing_body = true;
                state.line_status = 0;
            }
            // Handle start line
            if (state.parsing_start != 0) & (character == SPACE) {
                state.parsing_start += 1;
            }
            // Handle headers
            if state.parsing_header_name & (character == COLON) {
                state.parsing_header_name = false;
                state.parsing_header_value = true;
            }
            // Check for return characters
            if (character == CARRIAGE_RETURN) & (self.line_status == 0) | (self.line_status == 2) {
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

mod tests {
    use super::parse;

    global data: str<89> = "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: 19\r\n\r\n{\"success\":\"true\"}";

    #[test]
    fn test_parse() {
        parse(data);
    }
}
