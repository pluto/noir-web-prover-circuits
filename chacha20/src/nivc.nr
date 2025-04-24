// Helper function to simulate 32-bit addition with overflow
fn add32(a: u32, b: u32) -> u32 {
    let sum = (a as u64 + b as u64) & 0xFFFFFFFF;
    sum as u32
}

// Helper function to simulate 32-bit rotation
fn rotate_left32(x: u32, n: u8) -> u32 {
    ((x << n) | (x >> (32 - n))) & 0xFFFFFFFF
}

// ChaCha20 Quarter Round operation
// Takes four 32-bit unsigned integers and performs the quarter round operation
fn quarter_round(a: u32, b: u32, c: u32, d: u32) -> (u32, u32, u32, u32) {
    // 1. a += b; d ^= a; d <<<= 16;
    let a1 = add32(a, b);
    let d1 = d ^ a1;
    let d2 = rotate_left32(d1, 16);

    // 2. c += d; b ^= c; b <<<= 12;
    let c1 = add32(c, d2);
    let b1 = b ^ c1;
    let b2 = rotate_left32(b1, 12);

    // 3. a += b; d ^= a; d <<<= 8;
    let a2 = add32(a1, b2);
    let d3 = d2 ^ a2;
    let d4 = rotate_left32(d3, 8);

    // 4. c += d; b ^= c; b <<<= 7;
    let c2 = add32(c1, d4);
    let b3 = b2 ^ c2;
    let b4 = rotate_left32(b3, 7);

    (a2, b4, c2, d4)
}

// Structure that holds the chacha20 state
struct ChaChaState {
    state: [u32; 16],
}

impl ChaChaState {
    // Instantiate a new chacha20 state with the required parameters
    fn new(key: [u32; 8], nonce: [u32; 3], counter: u32) -> Self {
        Self {
            state: [
                0x61707865, 0x3320646e, 0x79622d32, 0x6b206574, // Constants
                key[0], key[1], key[2], key[3], key[4], key[5], key[6], key[7], counter, nonce[0],
                nonce[1], nonce[2],
            ],
        }
    }

    // Add two ChaChaState's together elementwise
    fn add(&mut self, other: Self) {
        for i in 0..16 {
            self.state[i] = add32(self.state[i], other.state[i]);
        }
    }

    fn to_bytes(self) -> [u32; 16] {
        let mut res = [0; 16];
        for i in 0..16 {
            res[i] = self.state[i];
        }
        res
    }

    // Runs quarter round on the working state 8 times
    fn inner_block(&mut self) {
        // Column rounds
        let (a0, a4, a8, a12) =
            quarter_round(self.state[0], self.state[4], self.state[8], self.state[12]);
        let (a1, a5, a9, a13) =
            quarter_round(self.state[1], self.state[5], self.state[9], self.state[13]);
        let (a2, a6, a10, a14) =
            quarter_round(self.state[2], self.state[6], self.state[10], self.state[14]);
        let (a3, a7, a11, a15) =
            quarter_round(self.state[3], self.state[7], self.state[11], self.state[15]);

        // Diagonal rounds
        let (b0, b5, b10, b15) = quarter_round(a0, a5, a10, a15);
        let (b1, b6, b11, b12) = quarter_round(a1, a6, a11, a12);
        let (b2, b7, b8, b13) = quarter_round(a2, a7, a8, a13);
        let (b3, b4, b9, b14) = quarter_round(a3, a4, a9, a14);

        // Update state
        self.state = [b0, b1, b2, b3, b4, b5, b6, b7, b8, b9, b10, b11, b12, b13, b14, b15];
    }
}

// Main ChaCha20 block function
fn chacha20_block(key: [u32; 8], nonce: [u32; 3], counter: u32) -> [u32; 16] {
    let mut state = ChaChaState::new(key, nonce, counter);
    let mut working_state = ChaChaState::new(key, nonce, counter);

    // Run 10 rounds
    for _i in 0..10 {
        working_state.inner_block();
    }

    // Add working state to original state
    state.add(working_state);
    state.to_bytes()
}

// Helper function to check if a byte is padding
fn is_padding(byte: u8) -> bool {
    byte == 0xFF
}

// Helper function to convert little endian to big endian
fn little_to_big_endian(word: u32) -> u32 {
    ((word & 0xFF) << 24)
        | ((word & 0xFF00) << 8)
        | ((word & 0xFF0000) >> 8)
        | ((word & 0xFF000000) >> 24)
}

fn big_to_little_endian(word: u32) -> u32 {
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

        // Initialize arrays
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
            // concat 4 u8 into 1 u32
            let concatenated = (word[0] as u32) << 24
                | (word[1] as u32) << 16
                | (word[2] as u32) << 8
                | (word[3] as u32);
            let le_word = big_to_little_endian(concatenated);

            plaintext_bits[i] = le_word;
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
        step_out[3] = polynomial_digest([1, 0, 0, 0, 0, 0, 0, 1], self.ciphertext_digest, 1); // Default machine state digest
        step_out[10] = part_ciphertext_digest;

        step_out[4] = step_in[4];
        step_out[5] = step_in[5];
        step_out[6] = 0; // Body ciphertext digest pow counter
        step_out[7] = step_in[7];
        step_out[8] = step_in[8];
        step_out[9] = step_in[9];

        step_out

        // step_out
    }
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

use std::hash::{self, poseidon::bn254::hash_2};

pub fn data_hasher<let DATA_BYTES: u32>(data: [u8; DATA_BYTES], seed: Field) -> Field {
    // ceil(DATA_BYTES/16) == (DATA_BYTES + 15) / 16 + 1
    let mut hashes: [Field; (DATA_BYTES + 15) / 16 + 1] =
        [Field::default(); (DATA_BYTES + 15) / 16 + 1];
    hashes[0] = seed;

    // Process data in chunks of 16 bytes
    for i in 0..((DATA_BYTES + 15) / 16) {
        let mut packed_input = Field::default();
        let mut is_padded_chunk = 0;

        // Process each byte in the chunk
        for j in 0..16 {
            let byte_idx = i * 16 + j;
            if byte_idx < DATA_BYTES {
                let is_padding = data[byte_idx] == 0;
                if !is_padding {
                    // Pack byte into input (little endian)
                    let byte_value = Field::from(data[byte_idx] as u32);

                    let pow_num = 8 * j;
                    let shift = 2.pow_32(pow_num as Field);

                    packed_input += byte_value * shift;
                } else {
                    is_padded_chunk += 1;
                }
            }
        }

        // Compute next hash
        if is_padded_chunk == 16 {
            // If all bytes are padding, use previous hash
            hashes[i + 1] = hashes[i];
        } else {
            // Use Poseidon hash function
            hashes[i + 1] = hash_2([hashes[i], packed_input]);
        }
    }

    hashes[hashes.len() - 1]
}
