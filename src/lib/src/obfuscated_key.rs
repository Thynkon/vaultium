use crate::symetric::SymetricKey;

pub struct ObfuscatedKey {
    data: SymetricKey,
}

impl ObfuscatedKey {
    pub const fn obfuscate_const(key: &[u8; 32]) -> Self {
        let mask = Self::generate_mask();
        let rotation = 3u8;
        let swap_pattern = [2, 0, 3, 1];
        let mut data = [0u8; 32];

        // XOR and rotate
        let mut i = 0;
        while i < 32 {
            let xored = key[i] ^ mask[i];
            let rotated = xored.rotate_left(rotation as u32);
            data[i] = rotated;
            i += 1;
        }

        // Swap chunks (8-byte chunks)
        let mut swapped = [0u8; 32];
        let mut chunk_idx = 0;
        while chunk_idx < 4 {
            let src_chunk = swap_pattern[chunk_idx];
            let mut byte_idx = 0;
            while byte_idx < 8 {
                swapped[chunk_idx * 8 + byte_idx] = data[src_chunk * 8 + byte_idx];
                byte_idx += 1;
            }
            chunk_idx += 1;
        }

        Self {
            data: SymetricKey { data: swapped },
        }
    }

    pub fn deobfuscate(&self) -> [u8; 32] {
        let mask = Self::generate_mask();
        let rotation = 3u8;
        let swap_pattern = [2, 0, 3, 1];

        // Reverse chunk swapping
        let mut unswapped = [0u8; 32];
        for new_idx in 0..4 {
            let old_idx = swap_pattern[new_idx];
            for byte_idx in 0..8 {
                unswapped[old_idx * 8 + byte_idx] = self.data.data[new_idx * 8 + byte_idx];
            }
        }

        // Reverse bit rotation and XOR
        let mut key = [0u8; 32];
        for i in 0..32 {
            let rotated = unswapped[i];
            let unrotated = rotated.rotate_right(rotation as u32);
            key[i] = unrotated ^ mask[i];
        }

        key
    }

    const fn generate_mask() -> [u8; 32] {
        let build_info = [0xAA, 0x55, 0xF0, 0x0F, 0xCC, 0x33, 0x99, 0x66];
        let mut mask = [0u8; 32];
        let mut i = 0;
        while i < 32 {
            let fib = ((i * 89 + 144) % 256) as u8;
            let build = build_info[i % build_info.len()];
            mask[i] = fib ^ build ^ ((i as u8).wrapping_mul(0x2F));
            i += 1;
        }
        mask
    }

    pub fn from_bytes(bytes: &[u8]) -> anyhow::Result<Self> {
        if bytes.len() != 32 {
            anyhow::bail!(
                "Invalid obfuscated key size: expected 32 bytes, got {}",
                bytes.len()
            );
        }

        let mut data = [0u8; 32];
        data.copy_from_slice(bytes);

        Ok(Self {
            data: SymetricKey { data },
        })
    }

    pub fn as_bytes(&self) -> &[u8; 32] {
        &self.data.data
    }
}
