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

use std::{
    error::Error,
    fs::File,
    io::{prelude::*, Write},
    path::Path,
};

use crate::{constants, utils};

use openssl::{
    hash::{hash, MessageDigest},
    memcmp,
    pkey::PKey,
    sign::Signer,
    symm::{decrypt, Cipher, Crypter, Mode},
};

use zeroize::Zeroizing;

pub fn decrypt_file(
    input_path: &Path,
    password: &str,
    output_path: &Path,
) -> Result<(), Box<dyn Error>> {
    let mut input_file = File::open(input_path)?;

    let tar_path = utils::TmpPath::new(input_path.parent().unwrap());
    let mut tar_file = File::create(&tar_path.path())?;

    let mut header = [0u8; constants::HEADER_SIZE];
    input_file.read_exact(&mut header)?;

    let token = &header[..constants::TOKEN_SIZE];
    let iv = &header[constants::TOKEN_SIZE..];

    let key = get_stream_key(password.as_bytes(), token)?;

    let result = _decrypt(&mut input_file, &key, iv, &mut tar_file);

    if let Err(e) = result {
        return Err(e);
    }

    let tmp_dir = utils::TmpPath::new(input_path.parent().unwrap());
    utils::from_tar(tar_path.path(), tmp_dir.path())?;

    let mut contents = std::fs::read_dir(&tmp_dir.path())?;
    let content = contents.next().unwrap().unwrap().path();
    std::fs::rename(&content, output_path)?;

    Ok(())
}

fn _decrypt(
    input_file: &mut File,
    key: &[u8],
    iv: &[u8],
    output_file: &mut File,
) -> Result<(), Box<dyn Error>> {
    let mut remaining_to_read = input_file.metadata()?.len() as usize;
    remaining_to_read -= constants::HEADER_SIZE;

    let stream_cipher = Cipher::aes_256_gcm();

    let mut read_buffer = vec![0u8; constants::BUFFER_SIZE];
    let mut plaintext_buffer = vec![0u8; constants::BUFFER_SIZE + constants::BLOCK_SIZE];

    let mut crypter = Crypter::new(stream_cipher, Mode::Decrypt, key, Some(iv))?;

    let aad = [constants::VERSION, iv].concat();
    crypter.aad_update(&aad)?;

    while remaining_to_read != constants::STREAM_TAG_SIZE {
        if remaining_to_read < constants::BUFFER_SIZE + constants::STREAM_TAG_SIZE {
            read_buffer.truncate(remaining_to_read - constants::STREAM_TAG_SIZE);
        }

        let read_count = input_file.read(&mut read_buffer)?;
        remaining_to_read -= read_count;

        let count = crypter.update(&read_buffer[..read_count], &mut plaintext_buffer)?;

        output_file.write_all(&plaintext_buffer[..count])?;
    }

    let mut tag = [0u8; constants::STREAM_TAG_SIZE];
    input_file.read_exact(&mut tag)?;

    crypter.set_tag(&tag)?;
    let mut finalize = vec![0u8; constants::BLOCK_SIZE];
    crypter.finalize(&mut finalize)?;

    Ok(())
}

fn get_stream_key(password: &[u8], token: &[u8]) -> Result<Zeroizing<Vec<u8>>, Box<dyn Error>> {
    let block_cipher = Cipher::aes_256_cbc();
    let sha = MessageDigest::sha3_512();

    const VERSION_END: usize = constants::VERSION.len();
    const SALT_END: usize = VERSION_END + constants::TOKEN_SALT_SIZE;
    const IV_END: usize = SALT_END + constants::TOKEN_IV_SIZE;
    const CIPHER_END: usize = IV_END + constants::TOKEN_CIPHERTEXT_SIZE;
    const HMAC_END: usize = CIPHER_END + constants::TOKEN_HMAC_SIZE;

    let salt = &token[VERSION_END..SALT_END];
    let iv = &token[SALT_END..IV_END];
    let ciphertext = &token[IV_END..CIPHER_END];
    let token_hmac = &token[CIPHER_END..HMAC_END];

    let password_key = utils::key_from_password(password, salt)?;

    let half_key = constants::TOKEN_KEY_SIZE / 2;
    let encryption_key = &password_key[..half_key];
    let signing_key = &password_key[half_key..];

    let to_hash = [constants::VERSION, salt, iv, ciphertext].concat();
    let hashed = hash(sha, &to_hash)?;

    let signing_key = PKey::hmac(signing_key)?;
    let mut signer = Signer::new(sha, &signing_key)?;
    signer.update(&hashed)?;

    let hmac = signer.sign_to_vec()?;

    if !memcmp::eq(token_hmac, &hmac) {
        std::thread::sleep(std::time::Duration::from_secs(
            constants::INVALID_PASSWORD_TIMEOUT,
        ));
        return Err(Box::from("Invalid Password"));
    }

    let key = Zeroizing::new(decrypt(block_cipher, encryption_key, Some(iv), ciphertext)?);

    Ok(key)
}
