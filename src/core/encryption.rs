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
    fs::{remove_file, File},
    io::{prelude::*, Write},
    path::Path,
};

use crate::{constants, utils};

use openssl::{
    hash::{hash, MessageDigest},
    pkey::PKey,
    rand::rand_bytes,
    sign::Signer,
    symm::{encrypt, Cipher, Crypter, Mode},
};

use zeroize::Zeroizing;

pub fn encrypt_file(
    input_path: &Path,
    password: &str,
    output_path: &Path,
) -> Result<(), Box<dyn Error>> {
    let mut output_file = File::create(output_path)?;

    let tar_path = utils::TmpPath::new(input_path.parent().unwrap());

    utils::to_tar(input_path, tar_path.path())?;

    let mut input_file = File::open(&tar_path.path())?;

    let (key, token) = new_stream_key(password.as_bytes())?;
    output_file.write_all(&token)?;

    let result = _encrypt(&mut input_file, &key, &mut output_file);

    if let Err(e) = result {
        remove_file(output_path)?;
        return Err(e);
    }

    Ok(())
}

fn _encrypt(
    input_file: &mut File,
    key: &[u8],
    output_file: &mut File,
) -> Result<(), Box<dyn Error>> {
    let mut remaining_to_read = input_file.metadata()?.len() as usize;

    let stream_cipher = Cipher::aes_256_gcm();

    let mut iv = [0u8; constants::STREAM_IV_SIZE];
    rand_bytes(&mut iv)?;

    let mut read_buffer = Zeroizing::new(vec![0u8; constants::BUFFER_SIZE]);
    let mut ciphertext_buffer = vec![0u8; constants::BUFFER_SIZE + constants::BLOCK_SIZE];

    let aad = [constants::VERSION, &iv].concat();

    let mut crypter = Crypter::new(stream_cipher, Mode::Encrypt, key, Some(&iv))?;
    crypter.aad_update(&aad)?;

    output_file.write_all(&iv)?;

    while remaining_to_read != 0 {
        let read_count = input_file.read(&mut read_buffer)?;
        remaining_to_read -= read_count;

        let count = crypter.update(&read_buffer[..read_count], &mut ciphertext_buffer)?;

        output_file.write_all(&ciphertext_buffer[..count])?;
    }

    crypter.finalize(&mut ciphertext_buffer)?;

    let mut tag = [0u8; constants::STREAM_TAG_SIZE];
    crypter.get_tag(&mut tag)?;

    output_file.write_all(&tag)?;

    Ok(())
}

type KeyAndToken = (Zeroizing<Vec<u8>>, Vec<u8>);
fn new_stream_key(password: &[u8]) -> Result<KeyAndToken, Box<dyn Error>> {
    let block_cipher = Cipher::aes_256_cbc();
    let sha = MessageDigest::sha3_512();

    let mut salt = [0u8; constants::TOKEN_SALT_SIZE];
    rand_bytes(&mut salt)?;

    let mut iv = [0u8; constants::TOKEN_IV_SIZE];
    rand_bytes(&mut iv)?;

    let mut key = Zeroizing::new(vec![0u8; constants::STREAM_KEY_SIZE]);
    rand_bytes(&mut key)?;

    let password_key = utils::key_from_password(password, &salt)?;

    let half_key = constants::TOKEN_KEY_SIZE / 2;
    let encryption_key = &password_key[..half_key];
    let signing_key = &password_key[half_key..];

    let ciphertext = encrypt(block_cipher, encryption_key, Some(&iv), &key)?;

    let to_hash = [constants::VERSION, &salt, &iv, &ciphertext].concat();
    let hashed = hash(sha, &to_hash)?;

    let signing_key = PKey::hmac(signing_key)?;
    let mut signer = Signer::new(sha, &signing_key)?;
    signer.update(&hashed)?;

    let hmac = signer.sign_to_vec()?;

    let mut token = to_hash;
    for byte in hmac {
        token.push(byte);
    }

    Ok((key, token))
}
