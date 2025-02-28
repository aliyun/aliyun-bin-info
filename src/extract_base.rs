
use std::fs::File;
use std::io::{BufReader, Read};
use md5::{Md5, Digest as Md5Digest};
use sha1::Sha1;
use sha2::Sha256;
use data_encoding::HEXLOWER;

pub fn calc_file_hashes(file_path: &str) -> anyhow::Result<(String, String, String)> {
    let file = File::open(file_path)?;
    let mut reader = BufReader::new(file);

    let mut md5_hasher = Md5::new();
    let mut sha1_hasher = Sha1::new();
    let mut sha256_hasher = Sha256::new();

    let mut buffer = [0; 4096];

    loop {
        let count = reader.read(&mut buffer)?;
        
        if count == 0 {
            break;
        }

        md5_hasher.update(&buffer[..count]);
        sha1_hasher.update(&buffer[..count]);
        sha256_hasher.update(&buffer[..count]);
    }

    let md5_hex = HEXLOWER.encode(&md5_hasher.finalize());
    let sha1_hex = HEXLOWER.encode(&sha1_hasher.finalize());
    let sha256_hex = HEXLOWER.encode(&sha256_hasher.finalize());

    Ok((md5_hex, sha1_hex, sha256_hex))
}

pub fn calc_file_ssdeep(file_path: &str) -> anyhow::Result<String> {
    let ssdeep_hash= fuzzyhash::FuzzyHash::file(file_path)?;
    Ok(ssdeep_hash.to_string())
}

pub fn get_file_size(file_path: &str) -> anyhow::Result<u64> {
    let metadata = std::fs::metadata(file_path)?;
    Ok(metadata.len())
}

pub fn get_file_type(file_path: &str) -> anyhow::Result<String> {
    let mut file = File::open(file_path)?; 
    let mut buffer = vec![0; 256]; 
    let bytes_read = file.read(&mut buffer)?;
    buffer.resize(bytes_read, 0);

    let ret = infer::get(&buffer);
    if let Some(file_type) = ret {
        return Ok(file_type.extension().to_string());
    }

    let guess = mime_guess::from_path(file_path);
    if let Some(mime) = guess.first() {
        return Ok(mime.to_string());
    }

    Ok("unknown".to_string())
}