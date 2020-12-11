extern crate base64;
extern crate crypto;

use std::fs::{File, OpenOptions};
use std::io::{BufReader, Read, Write};
use std::io;
use std::path::Path;
use std::process::exit;

use clap::Clap;
use crypto::aes::cbc_decryptor;
use crypto::aes::KeySize::KeySize256;
use crypto::blockmodes;
use crypto::buffer::{ReadBuffer, RefReadBuffer, RefWriteBuffer, WriteBuffer};

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
	let iv: Vec<u8> = vec![0; 16];
	let mut decryptor = cbc_decryptor(KeySize256, decrypted_session_key, &iv, blockmodes::NoPadding);

	let mut total_bytes_read = 0;
	let mut total_bytes_written = 0;
	let mut input_buffer: Vec<u8> = vec![0; 4096];
	let mut output_buffer: Vec<u8> = vec![0; 4096];
	let mut output_file = OpenOptions::new()
		.create(true)
		.append(false)
		.write(true)
		.truncate(true)
		.open(output_filename)
		.expect("Failed to create output file");
	let mut decryptor_output = RefWriteBuffer::new(&mut output_buffer);

	loop {
		match input_file.read(&mut input_buffer) {
			Ok(bytes_read) => {
				total_bytes_read += bytes_read;
				let mut decryptor_input = RefReadBuffer::new(&input_buffer[0..bytes_read]);
				decryptor_output.reset();

				let res = decryptor.decrypt(&mut decryptor_input, &mut decryptor_output, true);
				let decrypted_data = decryptor_output.take_read_buffer().take_remaining().to_vec();

				match output_file.write_all(&decrypted_data) {
					Ok(_) => {
						println!("Processed {} bytes", decrypted_data.len());
						total_bytes_written += decrypted_data.len();
					}
					Err(error) => {
						println!("Failed to write to output file: {:?}", error);
						break;
					}
				}

				match res {
					Ok(_) => {}
					Err(err) => {
						println!("Failed to decrypt AES data: {:?}", err);
						break;
					}
				}

				// AES needs one more round to process the rest of the data, so the condition's at the end
				if bytes_read < 1 {
					println!("Done reading input file after {} bytes, wrote {} bytes", total_bytes_read, total_bytes_written);
					break;
				}
			}
			Err(err) => {
				println!("Failed to read data from input: {:?}", err);
				break;
			}
		}
	}

	output_file.flush().expect("Failed to flush output file");
}
