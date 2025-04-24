// Helper function to simulate 32-bit addition with overflow
fn add32(a: u32, b: u32) -> u32 {
    std::wrapping_add(a, b)
}

// Helper function to simulate 32-bit rotation
fn rotate_left32(x: u32, n: u8) -> u32 {
    ((x << n) | (x >> (32 - n)))
}

// ChaCha20 Quarter Round operation
// Takes four 32-bit unsigned integers and performs the quarter round operation
pub fn quarter_round(a: u32, b: u32, c: u32, d: u32) -> (u32, u32, u32, u32) {
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

pub fn chacha20_block(key: [u32; 8], nonce: [u32; 3], counter: u32) -> [u32; 16] {
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
