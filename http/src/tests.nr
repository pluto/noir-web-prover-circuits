use crate::data::http_data;
use crate::{hash_accumulate, HttpVerification, parse, Parser, polynomial_digest};
use dep::std::hash::poseidon::bn254::hash_2;

global NUM_HEADERS: u32 = 10;

comptime global HTTP_RESPONSE_SIZE: u32 = http_data::http_response_plaintext_bytes().len();
comptime global MID: u32 = HTTP_RESPONSE_SIZE / 2;

fn polynomial_input() -> Field {
    hash_2([69, 420])
}

#[test]
fn test_parse() {
    let data: str<89> = "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: 19\r\n\r\n{\"success\":\"true\"}";
    parse(data)
}

#[test]
fn test_http_verification_no_header() {
    let polynomial_input = polynomial_input();
    let mut line_digests = [Field::default(); NUM_HEADERS];

    let http_response_plaintext_bytes = http_data::http_response_plaintext_bytes();
    let http_start_line = http_data::http_start_line();
    // let http_header_0 = http_data::http_header_0();
    // let http_header_1 = http_data::http_header_1();
    // let http_header_2 = http_data::http_header_2();
    let http_body_bytes = http_data::http_body_bytes();

    let start_line_digest = polynomial_digest(http_start_line, polynomial_input, 1);
    // let header_0_digest = polynomial_digest(http_header_0, polynomial_input, 1);
    // let header_1_digest = polynomial_digest(http_header_1, polynomial_input, 1);
    // let header_2_digest = polynomial_digest(http_header_2, polynomial_input, 1);

    line_digests[0] = start_line_digest;
    // line_digests[1] = header_0_digest;
    // line_digests[2] = header_1_digest;
    // line_digests[3] = header_2_digest;

    let body_digest: Field =
        polynomial_digest(http_body_bytes.map(|x| x as Field), polynomial_input, 1);
    let http_response_plaintext_digest = polynomial_digest(
        http_response_plaintext_bytes.map(|x| x as Field),
        polynomial_input,
        1,
    );

    let http_verification =
        HttpVerification { data: http_response_plaintext_bytes, line_digests, polynomial_input };

    let machine_state = Parser::default();

    let line_digests_hash = hash_accumulate(line_digests);

    let step_in = [
        0,
        0,
        1, // ciphertext_digest_pow
        machine_state.digest(polynomial_input), // machine_state_digest
        line_digests_hash, // sumof hashof digestof inputs
        1, // total number of matches to expect
        0, // body_monomials
        0, // 7, 8, 9, 10, 11 is not used
        0,
        0,
        0,
    ];

    let step_out = http_verification.verify(step_in, machine_state);
    let output_difference = body_digest - http_response_plaintext_digest;

    assert_eq(step_out[0], output_difference);
    assert_eq(step_out[2], polynomial_input.pow_32(http_response_plaintext_bytes.len() as Field));
    assert_eq(step_out[5], 0);
    assert_eq(step_out[6], polynomial_input.pow_32(http_body_bytes.len() as Field - 1));
}

#[test]
fn test_http_verification_one_header() {
    let polynomial_input = polynomial_input();
    let mut line_digests = [Field::default(); NUM_HEADERS];

    let http_response_plaintext_bytes = http_data::http_response_plaintext_bytes();
    let http_start_line = http_data::http_start_line();
    let http_header_0 = http_data::http_header_0();
    // let http_header_1 = http_data::http_header_1();
    // let http_header_2 = http_data::http_header_2();
    let http_body_bytes = http_data::http_body_bytes();

    let start_line_digest = polynomial_digest(http_start_line, polynomial_input, 1);
    let header_0_digest = polynomial_digest(http_header_0, polynomial_input, 1);
    // let header_1_digest = polynomial_digest(http_header_1, polynomial_input, 1);
    // let header_2_digest = polynomial_digest(http_header_2, polynomial_input, 1);

    line_digests[0] = start_line_digest;
    line_digests[1] = header_0_digest;
    // line_digests[2] = header_1_digest;
    // line_digests[3] = header_2_digest;

    let body_digest: Field =
        polynomial_digest(http_body_bytes.map(|x| x as Field), polynomial_input, 1);
    let http_response_plaintext_digest = polynomial_digest(
        http_response_plaintext_bytes.map(|x| x as Field),
        polynomial_input,
        1,
    );

    let http_verification =
        HttpVerification { data: http_response_plaintext_bytes, line_digests, polynomial_input };

    let machine_state = Parser::default();
    let step_in = [
        0,
        0,
        1, // ciphertext_digest_pow
        machine_state.digest(polynomial_input), // machine_state_digest
        hash_accumulate(line_digests), // sumof hashof digestof inputs
        2, // total number of matches to expect
        0, // body_monomials
        0, // 7, 8, 9, 10, 11 is not used
        0,
        0,
        0,
    ];

    let step_out = http_verification.verify(step_in, machine_state);

    let output_difference = body_digest - http_response_plaintext_digest;
    // let output_difference = http_response_plaintext_digest - body_digest;

    assert_eq(step_out[0], output_difference);
    assert_eq(step_out[2], polynomial_input.pow_32(http_response_plaintext_bytes.len() as Field));
    assert_eq(step_out[5], 0);
    assert_eq(step_out[6], polynomial_input.pow_32(http_body_bytes.len() as Field - 1));
}

#[test]
fn test_http_verification_split_two_headers() {
    let polynomial_input = polynomial_input();
    let mut line_digests = [Field::default(); NUM_HEADERS];

    let http_response_plaintext_bytes = http_data::http_response_plaintext_bytes();
    let http_start_line = http_data::http_start_line();
    let http_header_0 = http_data::http_header_0();
    let http_header_1 = http_data::http_header_1();
    // let http_header_2 = http_data::http_header_2();
    let http_body_bytes = http_data::http_body_bytes();

    let start_line_digest = polynomial_digest(http_start_line, polynomial_input, 1);
    let header_0_digest = polynomial_digest(http_header_0, polynomial_input, 1);
    let header_1_digest = polynomial_digest(http_header_1, polynomial_input, 1);
    // let header_2_digest = polynomial_digest(http_header_2, polynomial_input, 1);

    line_digests[0] = start_line_digest;
    line_digests[1] = header_0_digest;
    line_digests[2] = header_1_digest;
    // line_digests[3] = header_2_digest;

    let body_digest: Field =
        polynomial_digest(http_body_bytes.map(|x| x as Field), polynomial_input, 1);

    let http_response_plaintext_digest = polynomial_digest(
        http_response_plaintext_bytes.map(|x| x as Field),
        polynomial_input,
        1,
    );

    // Create arrays with the correct sizes
    let mut http_response_plaintext_0: [u8; MID] = [0; MID];
    for i in 0..MID {
        http_response_plaintext_0[i] = http_response_plaintext_bytes[i];
    }

    let mut http_response_plaintext_1: [u8; MID] = [0; MID];
    for i in 0..MID {
        http_response_plaintext_1[i] = http_response_plaintext_bytes[MID + i];
    }

    let http_verification_0 =
        HttpVerification { data: http_response_plaintext_0, line_digests, polynomial_input };

    let machine_state_0 = Parser::default();
    let step_in_0 = [
        0,
        0,
        1, // ciphertext_digest_pow
        machine_state_0.digest(polynomial_input), // machine_state_digest
        hash_accumulate(line_digests), // sumof hashof digestof inputs
        3, // total number of matches to expect
        0, // body_monomials
        0, // 7, 8, 9, 10, 11 is not used
        0,
        0,
        0,
    ];

    let step_out_0 = http_verification_0.verify(step_in_0, machine_state_0);
    assert_eq(step_out_0[2], polynomial_input.pow_32(http_response_plaintext_0.len() as Field));

    let machine_state_1 = Parser {
        parsing_start: 0,
        parsing_header: 0,
        parsing_header_name: false,
        parsing_header_value: false,
        parsing_body: true,
        line_status: 0,
        line_digest: 0,
        line_monomial: 0,
    };
    let step_in_1 = step_out_0;

    let http_verification_1 =
        HttpVerification { data: http_response_plaintext_1, line_digests, polynomial_input };
    let step_out_1 = http_verification_1.verify(step_in_1, machine_state_1);

    let output_difference = body_digest - http_response_plaintext_digest;

    assert_eq(step_out_1[0], output_difference);
    assert_eq(step_out_1[2], polynomial_input.pow_32(http_response_plaintext_bytes.len() as Field));
    assert_eq(step_out_1[5], 0);
    assert_eq(step_out_1[6], polynomial_input.pow_32(http_body_bytes.len() as Field - 1));
}
