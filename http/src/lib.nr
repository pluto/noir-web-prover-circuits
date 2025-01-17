comptime global CARRIAGE_RETURN: u8 = "\r".as_bytes()[0];
comptime global LINE_FEED: u8 = "\n".as_bytes()[0];
comptime global COLON: u8 = ":".as_bytes()[0];
comptime global SPACE: u8 = " ".as_bytes()[0];

struct LineStatus {
    first_cr: bool,
    first_lf: bool,
    second_cr: bool,
    second_lf: bool,
}

impl LineStatus {
    fn default() -> Self {
        Self { first_cr: false, first_lf: false, second_cr: false, second_lf: false }
    }

    fn is_single_line_break(self) -> bool {
        self.first_cr & self.first_lf & !self.second_cr & !self.second_lf
    }

    fn is_double_line_break(self) -> bool {
        self.first_cr & self.first_lf & self.second_cr & self.second_lf
    }
}

struct Parser {
    parsing_start: Field,
    parsing_header: Field,
    parsing_header_name: Field,
    parsing_header_value: Field,
    parsing_body: Field,
    // line_status: LineStatus,
    line_status: bool,
}

impl Parser {
    fn default() -> Self {
        Self {
            parsing_start: 1,
            parsing_header: 0,
            parsing_header_name: 0,
            parsing_header_value: 0,
            parsing_body: 0,
            line_status: false,
        }
    }

    fn update_state(self, character: Field) -> Self {
        let mut state = self;

        // if !state.parsing_body {
        //     // TODO: note, this does not check the state of `parsing_header_name` and `parsing_header_value` are valid
        //     // Handle the line breaking
        //     if state.line_status.is_single_line_break() & (character != CARRIAGE_RETURN) {
        //         state.parsing_header += 1;
        //         state.parsing_header_name = true;
        //         state.parsing_start = 0;
        //     }
        //     if state.line_status.is_double_line_break() {
        //         state.parsing_header = 0; // TODO: this is a little bit unintuitive, but we'll start counting headers at 1?
        //         state.parsing_header_value = false;
        //         state.parsing_body = true;
        //     }
        //     // Handle start line
        //     if (state.parsing_start != 0) & (character == SPACE) {
        //         state.parsing_start += 1;
        //     }
        //     // Handle headers
        //     if state.parsing_header_name & (character == COLON) {
        //         state.parsing_header_name = false;
        //         state.parsing_header_value = true;
        //     }
        //     // Check for return characters
        //     if (character == CARRIAGE_RETURN) & !self.line_status.first_cr {
        //         state.line_status.first_cr = true;
        //         state.parsing_header_value = false;
        //     } else if (character == LINE_FEED)
        //         & self.line_status.first_cr
        //         & !self.line_status.second_cr {
        //         state.line_status.first_lf = true;
        //     } else if (character == CARRIAGE_RETURN)
        //         & self.line_status.first_cr
        //         & self.line_status.first_lf {
        //         state.line_status.second_cr = true;
        //     } else if (character == LINE_FEED)
        //         & self.line_status.first_cr
        //         & self.line_status.first_lf
        //         & self.line_status.second_cr {
        //         state.line_status.second_lf = true;
        //     } else {
        //         state.line_status = LineStatus::default();
        //     }
        // }
        state.parsing_start = 0;
        state
    }
}

pub fn parse<let N: u32>(data: [Field; N]) {
    let mut parser = Parser::default();
    for character in data {
        parser = parser.update_state(character);
        // println(parser);
    }
    // Assert HTTP was valid
    assert(parser.parsing_start == 0);
    assert(parser.parsing_header == 0);
    assert(parser.parsing_header_name == 0);
    assert(parser.parsing_header_value == 0);
    assert(parser.parsing_body == 0);
    // assert(!parser.line_status.first_cr);
    // assert(!parser.line_status.first_lf);
    // assert(!parser.line_status.second_cr);
    // assert(!parser.line_status.second_lf);
}

mod tests {
    use super::parse;

    global data: str<89> = "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: 19\r\n\r\n{\"success\":\"true\"}";

    // #[test]
    // fn test_parse() {
    //     parse(data);
    // }
}
