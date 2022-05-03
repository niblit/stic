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
    fs::{remove_dir_all, remove_file, File},
    io::Read,
    path::{Path, PathBuf},
};

use crate::constants;

use tar::{Archive, Builder};

pub fn sanitize_path(path: &str) -> Result<PathBuf, Box<dyn Error>> {
    let mut _path = PathBuf::from(path);
    if !_path.exists() {
        return Err(Box::from("Path does not exist"));
    }

    if !_path.is_absolute() {
        _path = _path.canonicalize()?;
    }

    let str_path = _path.to_str().unwrap();
    let str_path_len = str_path.len();
    if (str_path.ends_with('/') || str_path.ends_with('\\')) && str_path_len > 1 {
        _path = PathBuf::from(&str_path[..str_path_len - 1]);
    }

    if !_path.is_file() && !_path.is_dir() {
        return Err(Box::from("Path is not a file or directory"));
    }

    if _path.metadata()?.permissions().readonly() {
        return Err(Box::from("Path does not have write permissions"));
    }

    let parent = _path.parent().unwrap();

    if parent.metadata()?.permissions().readonly() {
        return Err(Box::from("Parent dir does not have write permissions"));
    }

    Ok(_path)
}

pub fn validate_encryption(path: &Path) -> Result<(), Box<dyn Error>> {
    if let Some(ext) = path.extension() {
        let ext = ext.to_str().unwrap();

        if constants::EXTENSION == ext {
            return Err(Box::from("Path already encrypted"));
        }
    }
    let file = File::open(path)?;

    let size = file.metadata().unwrap().len() as usize;

    if size == 0 {
        return Err(Box::from("File is empty"));
    } else if size >= constants::MAX_FILE_SIZE {
        return Err(Box::from("File is too big"));
    }

    Ok(())
}

pub fn validate_decryption(path: &Path) -> Result<(), Box<dyn Error>> {
    if !path.is_file() {
        return Err(Box::from("Path is not a file"));
    }
    if let Some(ext) = path.extension() {
        let ext = ext.to_str().unwrap();

        if constants::EXTENSION != ext {
            return Err(Box::from("Path is not encrypted"));
        }
    } else {
        return Err(Box::from("Path is not encrypted"));
    }
    let mut file = File::open(path)?;
    let size = file.metadata().unwrap().len() as usize;

    if size >= constants::MAX_FILE_SIZE + constants::HEADER_SIZE + constants::STREAM_TAG_SIZE
        || size <= constants::HEADER_SIZE + constants::STREAM_TAG_SIZE
    {
        return Err(Box::from("An invalid file was provided"));
    }

    let mut version = [0u8; constants::VERSION.len()];

    file.read_exact(&mut version)?;

    if version != constants::VERSION {
        return Err(Box::from("Invalid file version"));
    }

    Ok(())
}

pub fn get_encrypted_path(path: &Path) -> PathBuf {
    let str_path = path.to_str().unwrap();
    let new_path = PathBuf::from(format!("{}.{}", str_path, constants::EXTENSION));
    new_path
}

pub fn get_decrypted_path(path: &Path) -> PathBuf {
    let str_path = path.to_str().unwrap();
    PathBuf::from(&str_path[..str_path.len() - (constants::EXTENSION.len() + 1)])
}

pub fn to_tar(input_path: &Path, output_path: &Path) -> Result<(), Box<dyn Error>> {
    let mut tar_file = Builder::new(File::create(output_path)?);

    if input_path.is_dir() {
        tar_file.append_dir_all(input_path.file_name().unwrap(), input_path)?;
    } else {
        let mut input_file = File::open(input_path)?;
        tar_file.append_file(input_path.file_name().unwrap(), &mut input_file)?;
    }
    tar_file.finish()?;
    Ok(())
}

pub fn from_tar(input_tar: &Path, output_dir: &Path) -> Result<(), Box<dyn Error>> {
    let mut tar_file = Archive::new(File::open(input_tar)?);
    tar_file.unpack(output_dir)?;
    Ok(())
}

pub struct TmpPath {
    path: PathBuf,
}

impl TmpPath {
    pub fn path(&self) -> &PathBuf {
        &self.path
    }

    pub fn new(parent: &Path) -> Self {
        loop {
            let mut filename = String::new();
            for _ in 0..constants::TMP_FILENAME_SIZE {
                filename += &constants::TMP_FILENAME_CHARSET
                    .chars()
                    .nth(rand::random::<usize>() % constants::TMP_FILENAME_CHARSET.len())
                    .unwrap()
                    .to_string();
            }
            let path = parent.join(PathBuf::from(filename));
            if !path.exists() {
                return Self { path };
            }
        }
    }
}

impl Drop for TmpPath {
    fn drop(&mut self) {
        if self.path.is_file() {
            remove_file(&self.path).unwrap_or(());
        } else if self.path.is_dir() {
            remove_dir_all(&self.path).unwrap_or(());
        }
    }
}
