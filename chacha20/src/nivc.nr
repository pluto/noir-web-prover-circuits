use crate::chacha20::{add32, chacha20_block};
use std::hash::{self, poseidon::bn254::hash_2};

fn little_to_big_endian(word: u32) -> u32 {
    ((word & 0xFF) << 24)
        | ((word & 0xFF00) << 8)
        | ((word & 0xFF0000) >> 8)
        | ((word & 0xFF000000) >> 24)
}

fn get_byte_from_word(word: u32, byte_idx: u8) -> u8 {
    // ex) word = [00000001, 00000010, 00000011, 00000100]
    // byte_idx = 0 -> 00000001
    // byte_idx = 1 -> 00000010
    // byte_idx = 2 -> 00000011
    // byte_idx = 3 -> 00000100
    let byte = (word >> (24 - byte_idx * 8)) & 0xFF;
    byte as u8
}

pub fn data_hasher<let DATA_BYTES: u32>(data: [u8; DATA_BYTES], seed: Field) -> Field {
    let mut hash: Field = seed;

    // ceil(DATA_BYTES/16)
    for i in 0..((DATA_BYTES + 15) / 16) {
        let mut packed_input = Field::default();
        let mut is_padded_chunk = 0;

        for j in 0..16 {
            let byte_idx = i * 16 + j;
            if byte_idx < DATA_BYTES {
                let is_padding = data[byte_idx] == 0;
                if !is_padding {
                    let byte_value = Field::from(data[byte_idx] as u32);
                    let pow_num = 8 * j;
                    let shift = 2.pow_32(pow_num as Field);

                    packed_input += byte_value * shift;
                } else {
                    is_padded_chunk += 1;
                }
            }
        }

        if is_padded_chunk == 16 {
            // If all bytes are padding, use previous hash - do nothing
        } else {
            hash = hash_2([hash, packed_input]);
        }
    }

    hash
}

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

// Structure for NIVC state
pub struct NivcState<let DATA_BYTES: u32, let PUBLIC_IO_LENGTH: u32> {
    key: [u32; 8],
    nonce: [u32; 3],
    counter: u32,
    plaintext: [u8; DATA_BYTES],
    ciphertext_digest: Field,
}

impl<let DATA_BYTES: u32, let PUBLIC_IO_LENGTH: u32> NivcState<DATA_BYTES, PUBLIC_IO_LENGTH> {
    fn verify(self, step_in: [Field; PUBLIC_IO_LENGTH]) -> [Field; PUBLIC_IO_LENGTH] {
        let mut step_out = step_in;
        // let mut ciphertext_digest_pow = [Field::default(); DATA_BYTES];
        let mut ciphertext_digest_pow = Field::default();
        ciphertext_digest_pow = step_in[1];

        let mut counter = self.counter;
        let mut ciphertext: [u32; (DATA_BYTES / 4)] = [0; (DATA_BYTES / 4)];
        let mut plaintext_bits: [u32; (DATA_BYTES / 4)] = [0; (DATA_BYTES / 4)];
        let mut is_padding: [bool; DATA_BYTES] = [false; DATA_BYTES];
        let mut zeroed_plaintext: [u8; DATA_BYTES] = [0; DATA_BYTES];
        let mut big_endian_ciphertext: [u8; DATA_BYTES] = [0; DATA_BYTES];

        // Convert plaintext to bits with padding handling
        for i in 0..(DATA_BYTES / 4) {
            // Process each byte in the word
            let mut word: [u8; 4] = [0; 4];
            for j in 0..4 {
                let byte_idx = i * 4 + j;
                let is_padding_current = self.plaintext[byte_idx] == 0; // TODO: fix to -1.
                is_padding[byte_idx] = is_padding_current;

                if is_padding_current {
                    word[j] = 0;
                    zeroed_plaintext[byte_idx] = 0;
                } else {
                    word[j] = self.plaintext[byte_idx];
                    zeroed_plaintext[byte_idx] = word[j];
                }
            }
            // concat 4 u8 into 1 u32, with little endian
            let concatenated = (word[3] as u32) << 24
                | (word[2] as u32) << 16
                | (word[1] as u32) << 8
                | (word[0] as u32);

            plaintext_bits[i] = concatenated;
        }

        // Step 1: Generate ChaCha20 blocks and store in ciphertext array
        for block_idx in 0..(DATA_BYTES / 64) {
            let key_stream = chacha20_block(self.key, self.nonce, counter);
            // Copy block to ciphertext array
            for j in 0..16 {
                ciphertext[block_idx * 16 + j] = key_stream[j] ^ plaintext_bits[block_idx * 16 + j];
            }
            counter = add32(counter, 1);
        }

        // Step 2: Convert ciphertext to big endian and handle padding
        for i in 0..(DATA_BYTES / 4) {
            // input is words(32bits)
            let be_word = little_to_big_endian(ciphertext[i]);

            for j in 0..4 {
                let byte_idx = i * 4 + j;
                let is_padding_current = is_padding[byte_idx];

                let byte = if is_padding_current {
                    0
                } else {
                    get_byte_from_word(be_word, j as u8)
                };
                big_endian_ciphertext[byte_idx] = byte;
            }
        }

        // Step 3: Calculate digests
        let mut part_ciphertext_digest = Field::default();
        let mut plaintext_digest = Field::default();

        part_ciphertext_digest = data_hasher(big_endian_ciphertext, step_in[10]);

        plaintext_digest = polynomial_digest(
            zeroed_plaintext.map(|x| x as Field),
            self.ciphertext_digest,
            step_in[1],
        );

        for i in 0..DATA_BYTES {
            if (is_padding[i]) {
                // do nothing
            } else {
                ciphertext_digest_pow *= self.ciphertext_digest;
            }
        }

        // Step 4: Update step_out
        step_out[0] = step_in[0] + step_in[10] - part_ciphertext_digest + plaintext_digest;
        step_out[1] = ciphertext_digest_pow;
        step_out[2] = step_in[2]; // Ciphertext digest POW accumulator
        step_out[3] = polynomial_digest([1, 0, 0, 0, 0, 0, 0, 1], self.ciphertext_digest, 1);
        step_out[10] = part_ciphertext_digest;

        step_out[4] = step_in[4];
        step_out[5] = step_in[5];
        step_out[6] = 0; // Body ciphertext digest pow counter
        step_out[7] = step_in[7];
        step_out[8] = step_in[8];
        step_out[9] = step_in[9];

        step_out
    }
}
