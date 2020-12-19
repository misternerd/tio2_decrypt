extern crate aesstream;
extern crate crypto;

use std::fs::{File, OpenOptions};
use std::io::{BufReader, Read, Write};
use std::io;
use std::path::Path;
use std::process::exit;

use aesstream::AesReader;
use clap::Clap;
use crypto::aessafe::AesSafe256Decryptor;

use crate::helper::backup_header::BackupHeader;
use crate::helper::cli_options::CliOpts;

mod helper;

fn main() {
	let opts: CliOpts = CliOpts::parse();

	if !Path::new(&opts.input_file).exists() {
		println!("Cannot read input file {}", opts.input_file);
		exit(1);
	}

	let input_file = File::open(&opts.input_file).expect("Failed to read input file");
	let mut input_file_buffer = BufReader::new(input_file);
	let passphrase = read_passphrase_from_input();

	match BackupHeader::parse_from_file(&mut input_file_buffer, &passphrase) {
		None => {
			println!("Failed to parse header");
			exit(1);
		}
		Some(header) => {
			decrypt_backup_data(&header.session_key, &mut input_file_buffer, &opts.output_file);
		}
	}
}


fn read_passphrase_from_input() -> String {
	let mut passphrase = String::new();
	println!("Please enter passphrase: ");
	io::stdin().read_line(&mut passphrase).expect("error: unable to read user input");
	passphrase.trim().to_string()
}


fn decrypt_backup_data(decrypted_session_key: &Vec<u8>, input_file: &mut BufReader<File>, output_filename: &String) {
	let mut output_file = OpenOptions::new()
		.create(true)
		.append(false)
		.write(true)
		.truncate(true)
		.open(output_filename)
		.expect("Failed to create output file");

	let decryptor = AesSafe256Decryptor::new(&decrypted_session_key);
	let iv: Vec<u8> = vec![0; 16];
	let mut reader = AesReader::new(input_file, decryptor, iv);
	let mut output_buffer: Vec<u8> = vec![0; 4096];

	loop {
		match reader.read(&mut output_buffer) {
			Ok(bytes_read) => {
				if bytes_read > 0 {
					let decrypted_data = &output_buffer[0..bytes_read];
					match output_file.write_all(decrypted_data) {
						Ok(_) => {
							// println!("Processed {} bytes", decrypted_data.len());
						}
						Err(error) => {
							println!("Failed to write to output file: {:?}", error);
							break;
						}
					}
				}
				else {
					break;
				}
			}
			Err(err) => {
				println!("Failed to AES decode: {:?}", err);
			}
		}
	}
}
