/*
This file is part of stic.

stic is free software: you can redistribute it and/or modify it under the terms of the GNU
General Public License as published by the Free Software Foundation, either version 3 of the
License, or (at your option) any later version.

stic is distributed in the hope that it will be useful, but WITHOUT ANY WARRANTY; without even
the implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU General
Public License for more details.

You should have received a copy of the GNU General Public License along with stic.
If not, see <https://www.gnu.org/licenses/>.

Copyright (C) 2022 Salvador Bravo Garnica
*/

// Version
pub const BUILD: &str = "0.1.0";
pub const VERSION: &[u8] = b"\x00\x00\x00\x01";

// Passwords
pub const PASSWORD_MIN: usize = 8;
pub const PASSWORD_MAX: usize = 4_000;
pub const PBKDF2_HMAC_ITERATIONS: usize = 1_000_000;
pub const INVALID_PASSWORD_TIMEOUT: u64 = 2;

// Files
pub const EXTENSION: &str = "ic";
pub const BUFFER_SIZE: usize = 10_485_760; // 10 MiB
pub const MAX_FILE_SIZE: usize = 68_719_476_704; // ~64 GiB (see NIST 800-38D)
pub const TMP_FILENAME_SIZE: u8 = 64;
pub const TMP_FILENAME_CHARSET: &str = "0123456789abdef";

// Tokens
pub const TOKEN_KEY_SIZE: usize = 64;
pub const TOKEN_SALT_SIZE: usize = 64;
pub const TOKEN_IV_SIZE: usize = 16;
pub const TOKEN_CIPHERTEXT_SIZE: usize = 48;
pub const TOKEN_HMAC_SIZE: usize = 64;

// Stream
pub const BLOCK_SIZE: usize = 1;
pub const STREAM_IV_SIZE: usize = 32;
pub const STREAM_TAG_SIZE: usize = 16;
pub const STREAM_KEY_SIZE: usize = 32;

// Header
pub const TOKEN_SIZE: usize =
    VERSION.len() + TOKEN_SALT_SIZE + TOKEN_IV_SIZE + TOKEN_CIPHERTEXT_SIZE + TOKEN_HMAC_SIZE;
pub const AAD_SIZE: usize = STREAM_IV_SIZE;
pub const HEADER_SIZE: usize = TOKEN_SIZE + AAD_SIZE;
