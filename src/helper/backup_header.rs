extern crate base64;
extern crate crypto;

use std::fs::File;
use std::io::{BufRead, BufReader};

use crypto::aes::cbc_decryptor;
use crypto::aes::KeySize::KeySize256;
use crypto::blockmodes;
use crypto::buffer::{BufferResult, ReadBuffer, WriteBuffer};
use crypto::digest::Digest;
use crypto::hmac::Hmac;
use crypto::mac::Mac;
use crypto::sha1::Sha1;
use rsa::padding::PaddingScheme;
use rsa::RSAPrivateKey;

#[derive(Debug)]
pub struct BackupHeader {
	passphrase_hmac_key: Vec<u8>,
	passphrase_hmac_result: Vec<u8>,
	public_key: Vec<u8>,
	pub private_key: Vec<u8>,
	pub session_key: Vec<u8>,
}


impl BackupHeader {
	pub fn parse_from_file(input_file_buffer: &mut BufReader<File>, passphrase: &String) -> Option<BackupHeader> {
		let mut header_size = 0;

		// line 1: header `TB_ARMOR_V1`
		let (len, header) = BackupHeader::read_trimmed_line_from_buffer(input_file_buffer);
		header_size += len;

		if !header.eq("TB_ARMOR_V1") {
			println!("Cannot find expected header=TB_ARMOR_V1 in input file");
			return None;
		}

		// line 2: passphrase hmac, base64 encoded
		let (len, tmp) = BackupHeader::read_trimmed_line_from_buffer(input_file_buffer);
		let passphrase_hmac_key = base64::decode(tmp).expect("Failed to base64 decode passphrase hmac");
		header_size += len;
		if passphrase_hmac_key.len() != 20 {
			println!("Passphrase HMAC key length doesn't match");
			return None;
		}

		// line 3: passphrase hmac result, base64 encoded
		let (len, tmp) = BackupHeader::read_trimmed_line_from_buffer(input_file_buffer);
		let passphrase_hmac_result = base64::decode(tmp).expect("Failed to base64 decode hmac result");
		header_size += len;
		if passphrase_hmac_result.len() != 20 {
			println!("Passphrase HMAC result length doesn't match");
			return None;
		}

		// line 4: public key, base64 encoded
		let (len, tmp) = BackupHeader::read_trimmed_line_from_buffer(input_file_buffer);
		let public_key = base64::decode(tmp).expect("Failed to base64 decode public key");
		header_size += len;

		// line 5: encrypted private key
		let (len, tmp) = BackupHeader::read_trimmed_line_from_buffer(input_file_buffer);
		let encrypted_private_key = base64::decode(tmp).expect("Failed to base64 decode encrypted private key");
		header_size += len;

		// line 6: encrypted session key
		let (len, tmp) = BackupHeader::read_trimmed_line_from_buffer(input_file_buffer);
		let encrypted_session_key = base64::decode(tmp).expect("Failed to base64 decode session key");
		header_size += len;

		if !BackupHeader::is_passphrase_hmac_valid(passphrase, &passphrase_hmac_key, &passphrase_hmac_result) {
			println!("The passphrase isn't matching the HMAC stored in the backup file, please validate that you inserted it correctly");
			return None;
		}

		let aes_key = BackupHeader::create_aes_key_from_passphrase(&passphrase);
		let decrypted_private_key = BackupHeader::decrypt_private_key(&aes_key, &encrypted_private_key);
		let decrypted_session_key = BackupHeader::decrypt_session_key(&decrypted_private_key, &encrypted_session_key);

		println!("Parsed header: {} bytes total, decrypted private key={} bytes, decrypted session key={} bytes",
				 header_size, decrypted_private_key.len(), decrypted_session_key.len());

		Some(BackupHeader {
			private_key: decrypted_private_key,
			public_key,
			passphrase_hmac_key,
			passphrase_hmac_result,
			session_key: decrypted_session_key,
		})
	}

	fn read_trimmed_line_from_buffer(buffer: &mut BufReader<File>) -> (usize, String) {
		let mut str = String::new();
		let bytes_read = buffer.read_line(&mut str).expect("Failed to read line from file buffer");
		str = String::from(str.trim());
		(bytes_read, str)
	}

	fn is_passphrase_hmac_valid(passphrase: &String, stored_hmac_key: &Vec<u8>, stored_hmac_result: &Vec<u8>) -> bool {
		let mut mac = Hmac::new(Sha1::new(), stored_hmac_key);
		mac.input(passphrase.as_bytes());
		let hmac_result = mac.result();
		let computed_hmac = hmac_result.code();
		let match_count = stored_hmac_result.iter().zip(computed_hmac.iter()).filter(|&(a, b)| a == b).count();

		stored_hmac_result.len() == computed_hmac.len() && computed_hmac.len() == match_count
	}

	fn create_aes_key_from_passphrase(passphrase: &String) -> Vec<u8> {
		let mut sha1 = Sha1::new();
		// The SHA1 creates 20 bytes, the rest is padded with zero bytes
		let mut key: Vec<u8> = vec![0; 32];
		sha1.input(passphrase.as_bytes());
		sha1.result(&mut key);
		key
	}

	fn decrypt_private_key(aes_key: &Vec<u8>, encrypted_private_key: &Vec<u8>) -> Vec<u8> {
		let iv: Vec<u8> = vec![0; 16];
		let mut decryptor = cbc_decryptor(KeySize256, aes_key, &iv, blockmodes::PkcsPadding);
		let mut decryptor_input = crypto::buffer::RefReadBuffer::new(encrypted_private_key);
		let mut buffer: Vec<u8> = vec![0; 4096];
		let mut decryptor_output = crypto::buffer::RefWriteBuffer::new(&mut buffer);
		let mut result = Vec::<u8>::new();

		loop {
			let res = decryptor.decrypt(&mut decryptor_input, &mut decryptor_output, true);
			result.extend(decryptor_output.take_read_buffer().take_remaining().iter().map(|&i| i));

			match res.expect("Error decrypting AES") {
				BufferResult::BufferUnderflow => break,
				BufferResult::BufferOverflow => {}
			}
		}

		result
	}

	fn decrypt_session_key(decrypted_private_key: &Vec<u8>, encrypted_session_key: &Vec<u8>) -> Vec<u8> {
		let private_key = RSAPrivateKey::from_pkcs8(decrypted_private_key).expect("Error creating RSA private key from input");
		let padding = PaddingScheme::new_pkcs1v15_encrypt();
		let decrypted = private_key.decrypt(padding, encrypted_session_key);
		decrypted.expect("Failed to decrypt session key")
	}
}