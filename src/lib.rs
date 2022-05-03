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

mod constants;
mod core;
mod utils;

use std::{error::Error, path::PathBuf};

pub use crate::{
    constants::BUILD,
    core::{decrypt_file, encrypt_file},
    utils::{
        get_decrypted_path, get_encrypted_path, read_password, sanitize_path, validate_decryption,
        validate_encryption,
    },
};

use zeroize::Zeroizing;

pub struct Config {
    input_path: PathBuf,
    action: Action,
    output_path: PathBuf,
    password: Zeroizing<String>,
}

enum Action {
    Encrypt,
    Decrypt,
}

impl Config {
    fn new() -> Self {
        Self {
            input_path: PathBuf::new(),
            action: Action::Encrypt,
            output_path: PathBuf::new(),
            password: Zeroizing::new(String::new()),
        }
    }

    pub fn run(&self) -> Result<(), Box<dyn Error>> {
        match &self.action {
            Action::Encrypt => {
                encrypt_file(&self.input_path, &self.password, &self.output_path)?;
            }
            Action::Decrypt => {
                decrypt_file(&self.input_path, &self.password, &self.output_path)?;
            }
        }
        Ok(())
    }

    pub fn parse() -> Result<Config, Box<dyn Error>> {
        let args: Vec<String> = std::env::args().collect();

        let n = args.len();
        let name = &args[0];

        return match n {
            2 => {
                let action = args[1].as_str();
                match action {
                    "-v" | "--version" => Err(Box::from(BUILD)),
                    "-h" | "--help" => Err(Box::from(help(name))),
                    _ => Err(Box::from(usage(name))),
                }
            }
            3 => {
                let mut config = Config::new();
                let action = args[1].as_str();
                let path = sanitize_path(args[2].as_str())?;
                match action {
                    "-e" | "--encrypt" => {
                        config.action = Action::Encrypt;
                        validate_encryption(&path)?;
                        config.input_path = path;
                        config.output_path = get_encrypted_path(&config.input_path);
                        config.password = read_password(true)?;
                    }
                    "-d" | "--decrypt" => {
                        config.action = Action::Decrypt;
                        validate_decryption(&path)?;
                        config.input_path = path;
                        config.output_path = get_decrypted_path(&config.input_path);
                        config.password = read_password(false)?;
                    }
                    _ => {
                        return Err(Box::from(usage(name)));
                    }
                }
                return Ok(config);
            }
            _ => Err(Box::from(usage(name))),
        };
    }
}

fn usage(name: &str) -> String {
    format!(
        "usage:
    {name} [-v|-h]
    {name} (-e|-d) path"
    )
}

fn help(name: &str) -> String {
    format!(
        "stic: rust symmetric file encryption

{}

flags:
    -v, --version     show release version and exit
    -h, --help        show this help message and exit

actions:
    -e, --encrypt     encrypt path
    -d, --decrypt     decrypt path

path                  path to a file

Copyright (C) 2022 Salvador Bravo Garnica

This program is free software: you can redistribute it and/or modify
it under the terms of the GNU General Public License as published by
the Free Software Foundation, either version 3 of the License, or
(at your option) any later version.

This program is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU General Public License for more details.

You should have received a copy of the GNU General Public License
along with this program.  If not, see <https://www.gnu.org/licenses/>.",
        usage(name)
    )
}
