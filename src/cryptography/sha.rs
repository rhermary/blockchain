
use std::io::Cursor;
use std::io::Read;

pub enum SHA {
    SHA1,
    SHA224,
    SHA256,
    SHA384,
    SHA512,
    SHA512_224,
    SHA512_256,
}//https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.180-4.pdf

mod sha_common {
    use super::SHA;
    pub struct PaddingParameters {
        pub remainder: u128,
        pub block_size: u128,
        pub length_size: usize,
    }

    pub const PADDING_PARAMETERS: [PaddingParameters; 2] = [
        PaddingParameters { remainder: 448 / 8, block_size: 512 / 8, length_size: 64 / 8},
        PaddingParameters { remainder: 896 / 8, block_size: 1024 / 8, length_size: 128 / 8},
    ];

    fn include_separator(bytes: &mut [u8], buffer_size: &mut usize) {
        assert!(bytes.len() != *buffer_size);

        bytes[*buffer_size] = 1u8 << 7;
        *buffer_size += 1;
    }

    fn include_length(bytes: &mut [u8], message_length: usize, length_size: usize) {
        let length = message_length.to_be_bytes();

        for i in (0..length_size).rev() {
            bytes[bytes.len() - 1 - i] = length[length.len() - 1 - i]
        }
    }

    fn include_padding(bytes: &mut [u8], buffer_size: usize, padding_end: usize) {
        bytes[buffer_size..padding_end].fill(0u8);
    }

    pub fn pad_input(bytes: &mut [u8], buffer_size: usize, message_length: usize, algorithm: SHA, separator: bool) -> u8 {
        let parameters = match algorithm {
            SHA::SHA1 | SHA::SHA224 | SHA::SHA256 => {&PADDING_PARAMETERS[0]}
            _ => {&PADDING_PARAMETERS[1]}
        };
        let mut buffer_size_ = buffer_size;

        if bytes.len() == buffer_size_ {
            return 0u8;
        }

        if separator {
            include_separator(bytes, &mut buffer_size_);

            if bytes.len() - buffer_size_ < parameters.length_size {
                return 1u8;
            }
        }

        include_length(bytes, message_length, parameters.length_size);
        include_padding(bytes, buffer_size_, bytes.len() - parameters.length_size);

        2u8
    }
}

mod sha1 {

    use super::sha_common::PADDING_PARAMETERS;

    use super::sha_common;
    use super::SHA;

    type Word = u32;
    const WORDS_SCHEDULE_SIZE: usize = 80;
    const WORD_SIZE_BYTES: usize = std::mem::size_of::<Word>();

    const K: [u32; 4] = [
        0x5a827999,
        0x6ed9eba1,
        0x8f1bbcdc,
        0xca62c1d6,
    ];

    const INITIAL: [u32; 5] = [
        0x67452301,
        0xefcdab89,
        0x98badcfe,
        0x10325476,
        0xc3d2e1f0
    ];

    fn ch(x: u32, y: u32, z: u32) -> u32 {
        (x & y) ^ (!x & z)
    }

    fn parity(x: u32, y: u32, z: u32) -> u32 {
        x ^ y ^ z
    }

    fn maj(x: u32, y: u32, z: u32) -> u32 {
        (x & y) ^ (x & z) ^ (y & z)
    }

    fn inner_function(iteration: usize, variable1: u32, variable2: u32, variable3: u32) -> u32 {
        if iteration <= 19 {
            return ch(variable1, variable2, variable3);
        } else if iteration <= 39 {
            return parity(variable1, variable2, variable3)
        } else if iteration <= 59 {
            return maj(variable1, variable2, variable3)
        } else {
            return parity(variable1, variable2, variable3)
        }
    }

    fn inner_k(iteration: usize) -> u32 {
        if iteration <= 19 {
            return K[0];
        } else if iteration <= 39 {
            return K[1];
        } else if iteration <= 59 {
            return K[2];
        } else {
            return K[3];
        }
    }

    fn process_block(bytes: &[u8], hash_variables: &mut [u32]) {
        let mut words = vec![0 as Word; WORDS_SCHEDULE_SIZE];

        for (i, chunk) in bytes.chunks_exact(WORD_SIZE_BYTES).enumerate() {
            let word = u32::from_be_bytes(chunk.try_into().unwrap());
            words[i] = word;
        }

        for i in 16..WORDS_SCHEDULE_SIZE {
            let mut word = 0u32;
            for j in [3, 8, 14, 16] {
                word ^= words[i - j];
            }

            words[i] = word.rotate_left(1);
        }

        let mut variables = [0 as Word; 5];
        for i in 0..5 {
            variables[i] = hash_variables[i];
        }

        for (i, &word) in words.iter().enumerate() {
            let tmp = variables[0].rotate_left(5)
                .wrapping_add(inner_function(i, variables[1], variables[2], variables[3]))
                .wrapping_add(variables[4])
                .wrapping_add(inner_k(i))
                .wrapping_add(word);
            variables[4] = variables[3];
            variables[3] = variables[2];
            variables[2] = variables[1].rotate_left(30);
            variables[1] = variables[0];
            variables[0] = tmp;
        }

        update_hash_variables(&variables, hash_variables);
    }

    fn update_hash_variables(variables: &[u32], hash_variables: &mut [u32]) {
        for j in 0..5 {
            hash_variables[j] = variables[j].wrapping_add(hash_variables[j]);
        }
    }

    fn process_final_block(bytes: &mut [u8], hash_variables: &mut [u32], block_id: usize, buffer_size: usize) {
        let message_length = (block_id * (PADDING_PARAMETERS[0].block_size as usize * WORD_SIZE_BYTES) + buffer_size) * 8;
        let success = sha_common::pad_input(bytes, buffer_size, message_length, SHA::SHA1, true);
        if success < 2 {
            process_block(bytes, hash_variables);
            sha_common::pad_input(bytes, 0, block_id, SHA::SHA1, success != 1);
        }

        process_block(bytes, hash_variables);
    }

    pub fn hash<R: super::Read>(mut reader: R) -> String {
        const BLOCK_SIZE: usize = PADDING_PARAMETERS[0].block_size as usize;
        let mut buffer = [0u8; BLOCK_SIZE];

        let mut hash_variables = INITIAL.clone();
        let mut iteration = 0usize;
        let mut buffer_size = 0;

        while iteration < 1usize << 61 {
            buffer_size = 0;

            while buffer_size < BLOCK_SIZE {
                let n = reader.read(&mut buffer[buffer_size..]).expect("Could not Read");
                if n == 0 {
                    break;
                }
                buffer_size += n;
            }

            if buffer_size < BLOCK_SIZE {
                break;
            }

            process_block(&mut buffer, &mut hash_variables);
            iteration += 1;
        }

        assert!(iteration < 1usize << 61);
        process_final_block(&mut buffer, &mut hash_variables, iteration, buffer_size);

        let mut s = String::with_capacity(hash_variables.len() * 8);

        for w in hash_variables {
            use std::fmt::Write;
            write!(&mut s, "{:08x}", w).unwrap();
        }

        s
    }
}

mod sha256 {
    use super::sha_common::{self, PADDING_PARAMETERS};
    use super::SHA;

    type Word = u32;
    const WORDS_SCHEDULE_SIZE: usize = 64;
    const WORD_SIZE_BYTES: usize = std::mem::size_of::<Word>();

    const K: [u32; 64] = [
        0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
        0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
        0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
        0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
        0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
        0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
        0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
        0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2,
    ];

    const INITIAL: [u32; 8] = [
        0x6a09e667,
        0xbb67ae85,
        0x3c6ef372,
        0xa54ff53a,
        0x510e527f,
        0x9b05688c,
        0x1f83d9ab,
        0x5be0cd19,
    ];

    fn ch(x: u32, y: u32, z: u32) -> u32 {
        (x & y) ^ (!x & z)
    }

    fn maj(x: u32, y: u32, z: u32) -> u32 {
        (x & y) ^ (x & z) ^ (y & z)
    }

    fn lsigma0(x: u32) -> u32 {
        x.rotate_right(7) ^ x.rotate_right(18) ^ (x >> 3)
    }

    fn lsigma1(x: u32) -> u32{
        x.rotate_right(17) ^ x.rotate_right(19) ^ (x >> 10)
    }

    fn csigma0(x: u32) -> u32 {
        x.rotate_right(2) ^ x.rotate_right(13) ^ x.rotate_right(22)
    }

    fn csigma1(x: u32) -> u32{
        x.rotate_right(6) ^ x.rotate_right(11) ^ x.rotate_right(25)
    }

    fn process_block(bytes: &[u8], hash_variables: &mut [u32]) {
        let mut words = vec![0 as Word; WORDS_SCHEDULE_SIZE];

        for (i, chunk) in bytes.chunks_exact(WORD_SIZE_BYTES).enumerate() {
            let word = u32::from_be_bytes(chunk.try_into().unwrap());
            words[i] = word;
        }

        for i in 16..WORDS_SCHEDULE_SIZE {
            words[i] = lsigma1(words[i - 2]).wrapping_add(words[i - 7]).wrapping_add(lsigma0(words[i-15])).wrapping_add(words[i - 16])
        }

        let mut variables = [0 as Word; 8];
        for i in 0..8 {
            variables[i] = hash_variables[i];
        }

        for (i, &word) in words.iter().enumerate() {
            let tmp1 = variables[7]
                .wrapping_add(csigma1(variables[4]))
                .wrapping_add(ch(variables[4], variables[5], variables[6]))
                .wrapping_add(K[i])
                .wrapping_add(word);
            let tmp2 = csigma0(variables[0]).wrapping_add(maj(variables[0], variables[1], variables[2]));

            variables[7] = variables[6];
            variables[6] = variables[5];
            variables[5] = variables[4];
            variables[4] = variables[3].wrapping_add(tmp1);
            variables[3] = variables[2];
            variables[2] = variables[1];
            variables[1] = variables[0];
            variables[0] = tmp1.wrapping_add(tmp2);
        }

        update_hash_variables(&variables, hash_variables);
    }

    fn update_hash_variables(variables: &[u32], hash_variables: &mut [u32]) {
        for j in 0..8 {
            hash_variables[j] = variables[j].wrapping_add(hash_variables[j]);
        }
    }

    fn process_final_block(bytes: &mut [u8], hash_variables: &mut [u32], block_id: usize, buffer_size: usize) {
        let message_length = (block_id * (PADDING_PARAMETERS[0].block_size as usize * WORD_SIZE_BYTES) + buffer_size) * 8;
        let success = sha_common::pad_input(bytes, buffer_size, message_length, SHA::SHA1, true);
        if success < 2 {
            process_block(bytes, hash_variables);
            sha_common::pad_input(bytes, 0, block_id, SHA::SHA1, success != 1);
        }

        process_block(bytes, hash_variables);
    }

    pub fn hash<R: super::Read>(mut reader: R) -> String {
        const BLOCK_SIZE: usize = PADDING_PARAMETERS[0].block_size as usize;
        let mut buffer = [0u8; BLOCK_SIZE];

        let mut hash_variables = INITIAL.clone();
        let mut iteration = 0usize;
        let mut buffer_size = 0;

        while iteration < 1usize << 61 {
            buffer_size = 0;

            while buffer_size < BLOCK_SIZE {
                let n = reader.read(&mut buffer[buffer_size..]).expect("Could not Read");
                if n == 0 {
                    break;
                }
                buffer_size += n;
            }

            if buffer_size < BLOCK_SIZE {
                break;
            }

            process_block(&mut buffer, &mut hash_variables);
            iteration += 1;
        }

        assert!(iteration < 1usize << 61);
        process_final_block(&mut buffer, &mut hash_variables, iteration, buffer_size);

        let mut s = String::with_capacity(hash_variables.len() * 8);

        for w in hash_variables {
            use std::fmt::Write;
            write!(&mut s, "{:08x}", w).unwrap();
        }

        s
    }
}

pub fn hash(message: &str, algorithm: SHA) {
    // Assumes byte encoding, not bit-level
    match algorithm {
        SHA::SHA1 | SHA::SHA256 => {
            assert!(message.len() < 1usize << 61)
        }
        _ => {unimplemented!("Support for this SHA version is not yet implemented.")}
    }

    let reader = Cursor::new(message.as_bytes());
    let res = match algorithm {
        SHA::SHA1 => {
            sha1::hash(reader)
        }
        SHA::SHA256 => {
            sha256::hash(reader)
        }
        _ => {unimplemented!("Support for this SHA version is not yet implemented.")}
    };

    println!("Hash Result: {res}")
}