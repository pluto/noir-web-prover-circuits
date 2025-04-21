use crate::chacha20::{ChaChaState, chacha20_block, quarter_round, add32, rotate_left32};

#[test]
fn test_quarter_round_example() {
    // Example from RFC 7539
    // 2.1.1.  Test Vector for the ChaCha Quarter Round
    let a = 0x11111111;
    let b = 0x01020304;
    let c = 0x9b8d6f43;
    let d = 0x01234567;

    let (a_out, b_out, c_out, d_out) = quarter_round(a, b, c, d);
    // Expected values from the example
   assert_eq(a_out, 0xea2a92f4);
   assert_eq(b_out, 0xcb1cf8ce);
   assert_eq(c_out, 0x4581472e);
   assert_eq(d_out, 0x5881c4bb);
}

#[test]
fn test_quarter_round_zero_input() {
    let (a_out, b_out, c_out, d_out) = quarter_round(0, 0, 0, 0);
    // All zeros should result in all zeros
    assert_eq(a_out, 0);
    assert_eq(b_out, 0);
    assert_eq(c_out, 0);
    assert_eq(d_out, 0);
}

#[test]
fn test_block_function() {
    // https://www.rfc-editor.org/rfc/rfc7539.html#section-2.3.2
    let mut key = [0 as u32; 8];
    let key = [
        0x03020100, 0x07060504, 0x0b0a0908, 0x0f0e0d0c,
        0x13121110, 0x17161514, 0x1b1a1918, 0x1f1e1d1c
        ];

    let nonce = [
        0x09000000, 0x4a000000, 0x00000000

    ];

    let counter = 0x00000001;
    let expected_result = [
        0xe4e7f110, 0x15593bd1, 0x1fdd0f50, 0xc47120a3,
        0xc7f4d1c7, 0x0368c033, 0x9aaa2204, 0x4e6cd4c3,
        0x466482d2, 0x09aa9f07, 0x05d7c214, 0xa2028bd9,
        0xd19c12b5, 0xb94e16de, 0xe883d0cb, 0x4e3c50a2
    ];

    let result = chacha20_block(key, nonce, counter);
    for i in 0..16 {
        assert(result[i] == expected_result[i]);
    }
}