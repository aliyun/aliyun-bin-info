use goblin::{elf, mach, Object, pe};
use std::collections::{HashMap, HashSet};
use std::fs::File;
use std::io::Read;
use serde::{Serialize, Deserialize};


#[derive(Serialize, Deserialize, Debug)]
pub struct SectionInfo {
    pub name: String,
    pub virtual_address: u64,
    pub virtual_size: u64,
    pub raw_address: u64,
    pub raw_size: u64,
    pub characteristics_num: u32,
    pub characteristics_str: String,
}

impl SectionInfo {
    pub fn display_info(&self) {
        println!("Section Name: {}", self.name);
        println!("Virtual Address: {:#x}", self.virtual_address);
        println!("Virtual Size: {}", self.virtual_size);
        println!("Raw Address: {:#x}", self.raw_address);
        println!("Raw Size: {}", self.raw_size);
        println!("Characteristics Num: {}", self.characteristics_num);
        println!("Characteristics Str: {}", self.characteristics_str);
    }
}

#[derive(Serialize, Deserialize, Debug)]
pub struct BinaryInfo {
    pub format: String,
    pub entry: String,
    pub architecture: String,
    pub size: u64,
    pub sections: Vec<SectionInfo>,
    pub imports: HashMap<String, HashSet<String>>,
    pub exports: HashSet<String>,
}

impl BinaryInfo {
    pub fn display_info(&self) {
        println!("Format: {}", self.format);
        println!("Entry: {}", self.entry);
        println!("Architecture: {}", self.architecture);
        println!("Size: {}", self.size);
        println!("Sections: {:?}", self.sections);
        println!("Imports: {:?}", self.imports);
        println!("Exports: {:?}", self.exports);
    }
}

fn decode_characteristics(characteristics: u32) -> String {
    let mut flags = Vec::new();

    if characteristics & 0x00000020 != 0 {
        flags.push("CNT_CODE");
    }
    if characteristics & 0x20000000 != 0 {
        flags.push("MEM_EXECUTE");
    }
    if characteristics & 0x40000000 != 0 {
        flags.push("MEM_READ");
    }
    if characteristics & 0x80000000 != 0 {
        flags.push("MEM_WRITE");
    }

    flags.join("|")
}

fn parse_elf(elf: &elf::Elf, buffer: &[u8]) -> BinaryInfo {
    let mut sections = Vec::new();

    for sh in &elf.section_headers {
        let name = if let Some(name) = elf.shdr_strtab.get_at(sh.sh_name) {
            name.to_string()
        } else {
            String::new()
        };

        let section_info = SectionInfo {
            name,
            virtual_address: sh.sh_addr,
            virtual_size: sh.sh_size,
            raw_address: sh.sh_offset,
            raw_size: sh.sh_size,
            characteristics_num: 0,
            characteristics_str: String::new(),
        };

        sections.push(section_info);
    }
    let architecture = elf::header::machine_to_str(elf.header.e_machine);

    let mut imports: HashMap<String, HashSet<String>> = HashMap::new();
    let mut exports = HashSet::new();

    let mut needed_libraries = Vec::new();
    if let Some(dynamic) = &elf.dynamic {
        needed_libraries = dynamic.get_libraries(&elf.dynstrtab);
    }

    let mut needed_libraries_str = String::new();
    for library in needed_libraries {
        if needed_libraries_str.is_empty() {
            needed_libraries_str = library.to_string();
        } else {
            needed_libraries_str += "\n";
            needed_libraries_str += library;
        }
    }

    let mut imports_str = String::new();

    for dynsym in elf.dynsyms.iter() {
        let Some(name) = elf.dynstrtab.get_at(dynsym.st_name) else {
            continue;
        };
        if name.is_empty() {
            continue;
        }
        if dynsym.is_import() {
            if imports_str.is_empty() {
                imports_str = name.to_string();
            } else {
                imports_str += "\n";
                imports_str += name;
            }
        } else {
            exports.insert(name.to_string());
        }
    }

    imports.insert(needed_libraries_str.clone(), HashSet::new());
    if let Some(entry) = imports.get_mut(&needed_libraries_str) {
        entry.insert(imports_str);
    }

    BinaryInfo {
        format: "ELF".to_string(),
        entry: format!("0x{:x}", elf.header.e_entry),
        architecture: architecture.to_string(),
        size: buffer.len() as u64,
        sections,
        imports,
        exports,
    }
}


fn parse_pe(pe: &pe::PE) -> BinaryInfo {
    let mut sections = Vec::new();

    for s in &pe.sections {
        let name = String::from_utf8_lossy(&s.name);
        let trimmed_name = name.trim_end_matches('\0');
        let section_info = SectionInfo {
            name: trimmed_name.to_string(),
            virtual_address: s.virtual_address as u64,
            virtual_size: s.virtual_size as u64,
            raw_address: s.pointer_to_raw_data as u64,
            raw_size: s.size_of_raw_data as u64,
            characteristics_num: s.characteristics,
            characteristics_str: decode_characteristics(s.characteristics),
        };

        sections.push(section_info);
    }

    let mut imports: HashMap<String, HashSet<String>> = HashMap::new();
    for import in &pe.imports {
        let dll_name = import.dll.to_string();
        if !imports.contains_key(&dll_name) {
            imports.insert(dll_name.clone(), HashSet::new());
        }

        if let Some(entry) = imports.get_mut(&dll_name) {
            entry.insert(import.name.to_string());
        }
    }

    let mut exports = HashSet::new();
    for export in &pe.exports {
        if let Some(name) = &export.name {
            exports.insert(name.to_string());
        }
    }

    let architecture = pe::header::machine_to_str(pe.header.coff_header.machine);

    BinaryInfo {
        format: "PE".to_string(),
        entry: format!("0x{:x}", pe.entry),
        architecture: architecture.to_string(),
        size: pe.header.optional_header.map_or(0, |h| h.windows_fields.size_of_image as u64),
        sections,
        imports,
        exports,
    }
}

fn handle_macho_binary(
    macho: &mach::MachO,
    sections: &mut Vec<SectionInfo>,
    architecture: &mut String,
    entry_string: &mut String,
    imports_result: &mut HashMap<String, HashSet<String>>,
    exports_result: &mut HashSet<String>,
) {
    if entry_string.is_empty() {
        *entry_string = format!("0x{:x}", macho.entry);
    } else {
        *entry_string += ",";
        *entry_string += &format!("0x{:x}", macho.entry);
    }

    for segment in &macho.segments {
        let Ok(sects) = segment.sections() else {
            continue;
        };

        for (section, _) in sects {
            let section_info = SectionInfo {
                name: section.name().unwrap_or("").to_string(),
                virtual_address: section.addr,
                virtual_size: section.size,
                raw_address: section.offset as u64,
                raw_size: section.size,
                characteristics_num: 0,
                characteristics_str: String::new(),
            };

            sections.push(section_info);
        }
    }

    let arch = match macho.header.cputype {
        mach::cputype::CPU_TYPE_X86 => "x86",
        mach::cputype::CPU_TYPE_X86_64 => "x86_64",
        mach::cputype::CPU_TYPE_ARM => "ARM",
        mach::cputype::CPU_TYPE_ARM64 => "ARM64",
        mach::cputype::CPU_TYPE_POWERPC => "PowerPC",
        mach::cputype::CPU_TYPE_POWERPC64 => "PowerPC64",
        _ => "unknown",
    };
    if architecture.is_empty() {
        *architecture = arch.to_string();
    } else {
        *architecture += ",";
        *architecture += arch;
    }

    if let Ok(exports) = macho.exports() {
        for export in exports {
            exports_result.insert(export.name);
        }
    }

    if let Ok(dyld_info) = macho.imports() {
        for import in dyld_info {
            if !imports_result.contains_key(import.dylib) {
                imports_result.insert(import.dylib.to_string(), HashSet::new());
            }
    
            let Some(entry) = imports_result.get_mut(import.dylib) else {
                continue;
            };

            entry.insert(import.name.to_string());
        }
    }

}

fn parse_macho(mach: &mach::Mach, buffer: &[u8]) -> BinaryInfo {
    let mut sections = Vec::new();
    let mut architecture = String::new();
    let mut entry_string = String::new();
    let mut imports: HashMap<String, HashSet<String>> = HashMap::new();
    let mut exports = HashSet::new();

    match mach {
        mach::Mach::Fat(fat) => {
            if let Ok(arches) = fat.arches() {
                for arch in arches {
                    let size = arch.size as usize;
                    let offset = arch.offset as usize;
                    if offset + size > buffer.len() {
                        continue;
                    }

                    let Ok(macho) = mach::Mach::parse(&buffer[offset..offset + size]) else {
                        continue;
                    };

                    let mach::Mach::Binary(macho_binary) = macho else {
                        continue;
                    };
                    handle_macho_binary(
                        &macho_binary,
                        &mut sections,
                        &mut architecture,
                        &mut entry_string,
                        &mut imports, 
                        &mut exports
                    );
                }
            }
        }
        mach::Mach::Binary(macho) => {
            handle_macho_binary(
                macho,
                &mut sections,
                &mut architecture, 
                &mut entry_string,
                &mut imports, 
                &mut exports
            );
        }
    }

    if architecture.is_empty() {
        architecture = "unknown".to_string();
    }

    BinaryInfo {
        format: "Mach-O".to_string(),
        entry: entry_string,
        architecture,
        size: buffer.len() as u64,
        sections,
        imports,
        exports,
    }
}

pub fn extract_binary_info(file_path: &str) -> anyhow::Result<BinaryInfo> {
    let mut file = File::open(file_path)?;
    let mut buffer = Vec::new();
    file.read_to_end(&mut buffer)?;

    let ret = Object::parse(&buffer);
    let obj = match ret {
        Ok(obj) => obj,
        Err(err) => {
            return Err(anyhow::anyhow!("get_binary_info faild: {}", err));
        }
    };

    match obj {
        Object::Elf(elf) => Ok(parse_elf(&elf, &buffer)),
        Object::PE(pe) => Ok(parse_pe(&pe)),
        Object::Mach(mach) => Ok(parse_macho(&mach, &buffer)),
        _ => {
            Err(anyhow::anyhow!("not support binary fotmat"))
        },
    }
}
