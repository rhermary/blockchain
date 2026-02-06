
use std::io::Cursor;

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
    use std::io::Read   ;

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


    pub fn hash<R: Read>(mut reader: R) -> String {
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
        SHA::SHA1 => {
            assert!(message.len() < 1usize << 61)
        }
        _ => {unimplemented!("Support for this SHA version is not yet implemented.")}
    }

    let res = sha1::hash(Cursor::new(message.as_bytes()));
    println!("Hash Result: {res}")
}