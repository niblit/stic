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

mod paths;
mod secrets;

pub use paths::{
    from_tar, get_decrypted_path, get_encrypted_path, sanitize_path, to_tar, validate_decryption,
    validate_encryption, TmpPath,
};

pub use secrets::{key_from_password, read_password};
