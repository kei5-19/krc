use std::{fmt::Debug, io::Read, mem};

use crate::{
    elf::{
        Elf64Header, Elf64ProgramHeader, Elf64SectionHeader, ElfClass, ElfIdent, Encoding, OsAbi,
        SectionFlag64, SectionType, SegmentFlag, SegmentType,
    },
    util::FromBytes as _,
};

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
        let mut debug = f.debug_struct("ObjectFile");
        debug.field("header", &self.header);

        let section_headers: Result<Vec<_>, _> = self.section_headers().collect();
        match section_headers {
            Ok(headers) => debug.field("section_headers", &headers),
            Err(e) => debug.field("section_headers", &format!("Err({})", e)),
        };

        let program_headers: Result<Vec<_>, _> = self.program_headers().collect();
        match program_headers {
            Ok(headers) => debug.field("program_headers", &headers),
            Err(e) => debug.field("program_headers", &format!("Err({})", e)),
        };

        debug.finish_non_exhaustive()
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

    pub fn section_headers(&self) -> SectionHeaderIter {
        if self.header.shoff != 0 {
            SectionHeaderIter {
                head: &self.data[self.header.shoff as usize - mem::size_of_val(&self.header)..],
                len: self.header.shnum,
                pos: 0,
            }
        } else {
            SectionHeaderIter {
                head: &self.data,
                len: 0,
                pos: 0,
            }
        }
    }

    pub fn program_headers(&self) -> ProgramHeaderIter {
        if self.header.phoff != 0 {
            ProgramHeaderIter {
                head: &self.data[self.header.phoff as usize - mem::size_of_val(&self.header)..],
                len: self.header.phnum,
                pos: 0,
            }
        } else {
            ProgramHeaderIter {
                head: &self.data,
                len: 0,
                pos: 0,
            }
        }
    }
}

pub struct SectionHeaderIter<'a> {
    head: &'a [u8],
    len: u16,
    pos: usize,
}

impl<'a> Iterator for SectionHeaderIter<'a> {
    type Item = Result<Elf64SectionHeader, String>;

    fn next(&mut self) -> Option<Self::Item> {
        let size = mem::size_of::<Elf64SectionHeader>();

        if self.pos >= size * self.len as usize {
            return None;
        }

        if self.head[self.pos..].len() < size {
            return Some(Err("the size of a section header is invalid".into()));
        }

        let mut header = &self.head[self.pos..self.pos + size];
        let name = u32::read_le_bytes(&mut header);

        let ty = match SectionType::try_from(u32::read_le_bytes(&mut header)) {
            Ok(t) => t,
            Err(e) => return Some(Err(e)),
        };

        let flags = u64::read_le_bytes(&mut header);
        let Some(flags) = SectionFlag64::from_bits(flags) else {
            return Some(Err(format!("a section has invalid flags: 0x{:x}", flags)));
        };

        self.pos += size;

        Some(Ok(Elf64SectionHeader {
            name,
            ty,
            flags,
            addr: u64::read_le_bytes(&mut header),
            offset: u64::read_le_bytes(&mut header),
            size: u64::read_le_bytes(&mut header),
            link: u32::read_le_bytes(&mut header),
            info: u32::read_le_bytes(&mut header),
            addralign: u64::read_le_bytes(&mut header),
            entsize: u64::read_le_bytes(&mut header),
        }))
    }
}

pub struct ProgramHeaderIter<'a> {
    head: &'a [u8],
    len: u16,
    pos: usize,
}

impl<'a> Iterator for ProgramHeaderIter<'a> {
    type Item = Result<Elf64ProgramHeader, String>;

    fn next(&mut self) -> Option<Self::Item> {
        let size = mem::size_of::<Elf64ProgramHeader>();
        if self.pos >= size * self.len as usize {
            return None;
        }

        if self.head[self.pos..].len() < size {
            return Some(Err("the size of a program header is invalid".into()));
        }

        let mut head = &self.head[self.pos..];

        let ty = match SegmentType::try_from(u32::read_le_bytes(&mut head)) {
            Ok(t) => t,
            Err(e) => return Some(Err(e)),
        };

        let flags = u32::read_le_bytes(&mut head);
        let flags = match SegmentFlag::from_bits(flags) {
            Some(f) => f,
            None => return Some(Err(format!("a section has invalid flags: {:x}", flags))),
        };

        self.pos += size;

        Some(Ok(Elf64ProgramHeader {
            ty,
            flags,
            offset: u64::read_le_bytes(&mut head),
            vaddr: u64::read_le_bytes(&mut head),
            paddr: u64::read_le_bytes(&mut head),
            filesz: u64::read_le_bytes(&mut head),
            memsz: u64::read_le_bytes(&mut head),
            align: u64::read_le_bytes(&mut head),
        }))
    }
}
