use figlet_rs::FIGfont;
use comfy_table::Table;
use std::path::Path;
use clap::Parser;
use colored::Colorize;
use serde::{Serialize, Deserialize};

use bin_info::{
    calc_file_hashes,
    calc_file_ssdeep,
    extract_pe_sign,
    extract_bin_strings,
    extract_binary_info,
    get_file_size,
    get_file_type
};
use bin_info::extract_execute::BinaryInfo;
use bin_info::extract_sign::CertInfo;

#[derive(Parser, Debug)]
#[clap(version = "1.0")]
struct Args {
    #[clap(long)]
    json: bool,

    #[clap(long)]
    strings: bool,

    #[clap(value_name = "path")]
    path: String,
}

#[derive(Serialize, Deserialize, Debug)]
struct BinaryAllInfo {
    file_size: u64,
    md5: String,
    sha1: String,
    sha256: String,
    ssdeep: String,
    file_type: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    binary_info: Option<BinaryInfo>,
    #[serde(skip_serializing_if = "Option::is_none")]
    cert_infos: Option<Vec<CertInfo>>,
}

fn file_exists(path: impl AsRef<Path>) -> bool {
    let path = path.as_ref();
    path.exists() && path.is_file()
}

fn string_split_with_new_line(string: String, split_size: usize) -> String {
    if string.len() < split_size {
        return string
    }

    let mut new_str = String::new();
    for (i, v) in string.char_indices() {
        if (i + 1) % split_size == 0 {
            new_str += "\n"
        }
        new_str += &v.to_string()
    }
    new_str
}

fn show_binary_strings(file_path: &str) -> anyhow::Result<()> {
    let ret = extract_bin_strings(file_path);
    let extracted_strings = match ret {
        Ok(strings) => strings,
        Err(err) => {
            println!("error:{:?}", err);
            return Err(anyhow::anyhow!(err));
        }
    };

    for string in extracted_strings {
        println!("{}", string);
    }
    Ok(())
}

fn show_binary_base_info(file_path: &str) -> anyhow::Result<()> {
    let ret = get_file_size(file_path);
    let file_size = match ret {
        Ok(size) => size,
        Err(err) => {
            println!("error:{:?}", err);
            return anyhow::Result::Err(err);
        }
    };

    let ret = calc_file_hashes(file_path);
    let (md5, sha1, sha256) = match ret {
        Ok(hashes) => hashes,
        Err(err) => {
            println!("error:{:?}", err);
            return anyhow::Result::Err(err);
        }
    };

    let ret = calc_file_ssdeep(file_path);
    let ssdeep = match ret {
        Ok(ssdeep) => ssdeep,
        Err(err) => {
            println!("error:{:?}", err);
            return anyhow::Result::Err(err);
        }
    };

    let ret = get_file_type(file_path);
    let file_type = match ret {
        Ok(file_type) => file_type,
        Err(err) => {
            println!("error:{:?}", err);
            return anyhow::Result::Err(err);
        }
    };

    let mut table = Table::new();
    table
        .set_header(vec!["base info", "value"])
        .add_row(vec![
            "path",
            &string_split_with_new_line(file_path.to_string(), 70),
        ])
        .add_row(vec![
            "size",
            &format!("{} ({})", &bytesize::ByteSize(file_size).to_string(), file_size),
        ])
        .add_row(vec![
            "md5",
            &md5,
        ])
        .add_row(vec![
            "sha1",
            &sha1,
        ])
        .add_row(vec![
            "sha256",
            &sha256,
        ])
        .add_row(vec![
            "ssdeep",
            &string_split_with_new_line(ssdeep, 70),
        ])
        .add_row(vec![
            "file_type",
            &file_type,
        ]);

    let tip = "Base Info:".green().bold();
    println!("{}", tip);
    println!("{table}\n");

    Ok(())
}

fn show_binary_section(info: &BinaryInfo) -> anyhow::Result<()> {
    if info.sections.is_empty() {
        return Ok(())
    }

    let mut table = Table::new();
    table.set_header(vec![
        "sections", "virtual_addr", "virtual_size", "raw_addr", "raw_size", "characteristics"
    ]);
    
    for section in &info.sections {
        table.add_row(vec![
            &section.name,
            &format!("0x{:x}", section.virtual_address),
            &format!("{}", section.virtual_size),
            &format!("0x{:x}", section.raw_address),
            &format!("{}", section.raw_size),
            &section.characteristics_str,
        ]);
    }

    let tip = "Sections:".green().bold();
    println!("{}", tip);
    println!("{table}\n");
    Ok(())
}

fn show_binary_execute_info(info: &BinaryInfo)  -> anyhow::Result<()> {
    let mut table = Table::new();
    table
        .set_header(vec!["execute info", "value"])
        .add_row(vec![
            "entry",
            &info.entry,
        ])
        .add_row(vec![
            "architecture",
            &info.architecture,
        ]);

    let tip = "Execute Info:".green().bold();
    println!("{}", tip);
    println!("{table}\n");
    Ok(())
}

fn show_binary_import(info: &BinaryInfo) -> anyhow::Result<()> {
    if info.imports.is_empty() {
        return Ok(())
    }

    let mut table = Table::new();
    table.set_header(vec!["import module", "func"]);

    for (key, value) in &info.imports {
        let mut funcs = String::new();
        for item in value {
            funcs += item;
            funcs += "\n";
        }
        table.add_row(vec![
            key,
            &funcs]);
    }

    let tip = "Imports".green().bold();
    println!("{}", tip);
    println!("{table}\n");
    Ok(())
}

fn show_binary_export(info: &BinaryInfo) -> anyhow::Result<()> {
    if info.exports.is_empty() {
        return Ok(())
    }

    let mut table = Table::new();
    table.set_header(vec!["export func"]);

    for value in &info.exports {
        table.add_row(vec![value]);
    }

    let tip = "Exports".green().bold();
    println!("{}", tip);
    println!("{table}\n");
    Ok(())
}

fn show_pe_sign(file_path: &str) -> anyhow::Result<()> {
    let ret = extract_pe_sign(file_path)?;

    let Some(cert_infos) = ret else {
        return Err(anyhow::anyhow!("empty cert"));
    };
    if cert_infos.is_empty() {
        return Ok(())
    };

    let tip = "Certificates:".green().bold();
    println!("{}", tip);

    for cert_info in cert_infos {
        let mut table = Table::new();
        table
            .set_header(vec!["cert", "value"])
            .add_row(vec![
                "issuer",
                &string_split_with_new_line(cert_info.issuer, 70),
            ])
            .add_row(vec![
                "subject",
                &string_split_with_new_line(cert_info.subject, 70),
            ])
            .add_row(vec![
                "version",
                &string_split_with_new_line(cert_info.version, 70),
            ])
            .add_row(vec![
                "signature_algorithm",
                &string_split_with_new_line(cert_info.signature_algorithm, 70),
            ])
            .add_row(vec![
                "signature_value",
                &cert_info.signature_value,
            ])
            ;
    
        println!("{table}\n");
    };
    Ok(())
}

fn show_binary_info(file_path: &str) -> anyhow::Result<()> {
    let ret = FIGfont::standard();
    let standard_font = match ret {
        Ok(font) => font,
        Err(err) => {
            println!("error:{:?}", err);
            return Err(anyhow::anyhow!(err));
        }
    };
    let ret = standard_font.convert("Bin Info");
    if let Some(figure) = ret {
        println!("{}", figure);
    };

    show_binary_base_info(file_path)?;

    let info = extract_binary_info(file_path)?;

    let _ = show_binary_execute_info(&info);
    let _ = show_binary_section(&info);
    let _ = show_binary_import(&info);
    let _ = show_binary_export(&info);
    let _ = show_pe_sign(file_path);

    Ok(())
}


fn show_binary_info_json(file_path: &str) -> anyhow::Result<()> {
    let ret = get_file_size(file_path);
    let file_size = match ret {
        Ok(size) => size,
        Err(err) => {
            println!("error:{:?}", err);
            return anyhow::Result::Err(err);
        }
    };

    let ret = calc_file_hashes(file_path);
    let (md5, sha1, sha256) = match ret {
        Ok(hashes) => hashes,
        Err(err) => {
            println!("error:{:?}", err);
            return anyhow::Result::Err(err);
        }
    };

    let ret = calc_file_ssdeep(file_path);
    let ssdeep = match ret {
        Ok(ssdeep) => ssdeep,
        Err(err) => {
            println!("error:{:?}", err);
            return anyhow::Result::Err(err);
        }
    };

    let ret = get_file_type(file_path);
    let file_type = match ret {
        Ok(file_type) => file_type,
        Err(err) => {
            println!("error:{:?}", err);
            return anyhow::Result::Err(err);
        }
    };

    let ret = extract_binary_info(file_path);

    let binary_info = match ret {
        Ok(info) => Some(info),
        Err(_) => None,
    };

    let ret = extract_pe_sign(file_path);
    let cert_infos = match ret {
        Ok(cert_infos) => cert_infos,
        Err(_) => None,
    };

    let user = BinaryAllInfo {
        file_size,
        md5,
        sha1,
        sha256,
        ssdeep,
        file_type,
        binary_info,
        cert_infos
    };

    
    let json = serde_json::to_string_pretty(&user)?;
    println!("{}", json);

    Ok(())
}

fn main() -> anyhow::Result<()> {
    let args = Args::parse();

    if !file_exists(&args.path) {
        return Err(anyhow::anyhow!("file not exists"));
    }

    if args.strings {
        return show_binary_strings(&args.path);
    } 

    if args.json {
        return show_binary_info_json(&args.path);
    } else {
        let _ = show_binary_info(&args.path);
    }

    Ok(())
}
