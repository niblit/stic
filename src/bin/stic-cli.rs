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

fn main() {
    let config = stic::Config::parse().unwrap_or_else(|e| {
        eprintln!("{e}");
        std::process::exit(1);
    });

    if let Err(e) = config.run() {
        eprintln!("{e}");
        std::process::exit(1);
    }
}
