use std::{fmt::Debug, io::Read, mem};

use crate::elf::{Elf64Header, ElfClass, ElfIdent, Encoding, OsAbi};

#[cfg(test)]
mod tests;

pub struct ObjectFile {
    pub header: Elf64Header,
    pub data: Vec<u8>,
    // pub sections_headers: Vec<Elf64SectionHeader>,
    // pub segments: Vec<Box<[u8]>>,
    // pub program_headers: Vec<Elf64ProgramHeader>,
}

impl Debug for ObjectFile {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ObjectFile")
            .field("header", &self.header)
            .finish_non_exhaustive()
    }
}

impl ObjectFile {
    pub fn from_reader(mut reader: impl Read) -> Result<Self, String> {
        let mut ident = [0; mem::size_of::<ElfIdent>()];
        let mut count = 0;
        while count < ident.len() {
            match reader.read(&mut ident[count..]) {
                Ok(0) => return Err(format!("ident contains {} bytes", count)),
                Ok(n) => count += n,
                Err(e) => return Err(e.to_string()),
            }
        }
        let ident = ElfIdent::from_bytes(ident)?;

        if ident.class != ElfClass::Class64
            || ident.data != Encoding::LSB2
            || ident.osabi != OsAbi::SysV
        {
            return Err("unsupported format".into());
        }

        let mut left = [0; mem::size_of::<Elf64Header>() - mem::size_of::<ElfIdent>()];
        let mut count = 0;
        while count < left.len() {
            match reader.read(&mut left[count..]) {
                Ok(0) => return Err("invalid ELF header".into()),
                Ok(n) => count += n,
                Err(e) => return Err(e.to_string()),
            }
        }

        let header = Elf64Header::from_bytes(ident, left)?;
        let mut data = vec![];
        if let Err(e) = reader.read_to_end(&mut data) {
            return Err(e.to_string());
        }

        Ok(ObjectFile { header, data })
    }
}
