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

use std::error::Error;

use crate::constants;

use openssl::{hash::MessageDigest, pkcs5::pbkdf2_hmac};

use zeroize::Zeroizing;

pub fn key_from_password(
    password: &[u8],
    salt: &[u8],
) -> Result<Zeroizing<Vec<u8>>, Box<dyn Error>> {
    let hash: MessageDigest = MessageDigest::sha3_512();

    let mut key = Zeroizing::new(vec![0u8; constants::TOKEN_KEY_SIZE]);

    pbkdf2_hmac(
        password,
        salt,
        constants::PBKDF2_HMAC_ITERATIONS,
        hash,
        &mut key,
    )?;

    Ok(key)
}

pub fn read_password(confirmation: bool) -> Result<Zeroizing<String>, Box<dyn Error>> {
    let password = Zeroizing::new(rpassword::prompt_password("password: ")?);

    verify_password(&password)?;

    if confirmation {
        let password_confirmation =
            Zeroizing::new(rpassword::prompt_password("repeat password: ")?);

        if password != password_confirmation {
            return Err(Box::from("Passwords do not match"));
        }
    }

    Ok(password)
}

fn verify_password(password: &str) -> Result<(), Box<dyn Error>> {
    if password.len() < constants::PASSWORD_MIN {
        return Err(Box::from(format!(
            "Password must be at least {} characters long",
            constants::PASSWORD_MIN
        )));
    } else if password.len() > constants::PASSWORD_MAX {
        return Err(Box::from(format!(
            "Password must be at most {} characters long",
            constants::PASSWORD_MAX
        )));
    }

    let mut contains_lowercase = false;
    let mut contains_uppercase = false;
    let mut contains_number = false;
    let mut contains_symbol = false;

    for c in password.chars() {
        if c.is_lowercase() {
            contains_lowercase = true;
        } else if c.is_uppercase() {
            contains_uppercase = true;
        } else if c.is_numeric() {
            contains_number = true;
        } else if c.is_ascii_punctuation() {
            contains_symbol = true;
        }
    }

    if !contains_lowercase {
        return Err(Box::from(
            "Password must contain at least one lowercase character",
        ));
    } else if !contains_uppercase {
        return Err(Box::from(
            "Password must contain at least one uppercase character",
        ));
    } else if !contains_number {
        return Err(Box::from("Password must contain at least one number"));
    } else if !contains_symbol {
        return Err(Box::from("Password must contain at least one symbol"));
    }

    Ok(())
}
