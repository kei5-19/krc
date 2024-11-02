//! See [Executable and Linking Format (ELF) Specification] and [ELF-64 Object File Format].
//!
//! [Executable and Linking Format (ELF) Specification]:
//! https://refspecs.linuxfoundation.org/elf/elf.pdf
//! [ELF-64 Object File Format]: https://uclibc.org/docs/elf-64-gen.pdf

use std::mem;

use bitflags::bitflags;
use enum_try_from::impl_enum_try_from;

/// SHN_UNDEF
///
/// Represents undefined section.
pub const SECTION_HEADER_NUMBER_UNDEF: u16 = 0;

#[derive(Debug, Default, Clone)]
pub struct Elf64Header {
    /// Marks the file as an object file and provides machine-independent data with which to decode
    /// and interpret the file's contents.
    pub ident: ElfIdent,

    /// Identifies the object file type.
    pub ty: ObjectFileType,

    /// Specifies the required architecture for an individual file.
    pub machine: Machine,

    /// Identifies the object file version.
    pub version: u32,

    /// Gives the virtual address to which the system first transfers control, ths starting the
    /// process. If the file has no asscoated entry point, this member holds zero.
    pub entry: u64,

    /// Holds the program header table's file offset in bytes. If the file has no program header
    /// table, this member holds zero.
    pub phoff: u64,

    /// Holds the section header table's file offset in bytes. If the file has no
    /// section header table, this member holds zero.
    pub shoff: u64,

    /// Holds processor-specific flags associated with the file.
    pub flags: u32,

    /// Holds the ELF header's size in bytes.
    pub ehsize: u16,

    /// Holds the size in bytes of one entry in the file's program header table; all entries are
    /// the same size.
    pub phentsize: u16,

    /// Holds the number of entries in the program header table. If a file has no program header
    /// table, holds the value zero.
    pub phnum: u16,

    /// Holds a section header's size in bytes. A section header is one entry in the section header
    /// table; all entries are the same size.
    pub shentsize: u16,

    /// Holds the number of entries in the section header table. If a file has no section header
    /// table, holds the value zero.
    pub shnum: u16,

    /// Holds the section header table index of the entry associated with the section name string
    /// table. If the file has no section name string table, holds the value
    /// [SECTION_HEADER_NUMBER_UNDEF].
    pub shstrndx: u16,
}

impl Elf64Header {
    pub fn from_bytes(
        ident: ElfIdent,
        left: [u8; mem::size_of::<Self>() - mem::size_of::<ElfIdent>()],
    ) -> Result<Self, String> {
        let ty = ObjectFileType::try_from(u16::from_le_bytes([left[0], left[1]]))?;
        let machine = Machine::try_from(u16::from_le_bytes([left[2], left[3]]))?;

        let version = u32::from_le_bytes([left[4], left[5], left[6], left[7]]);
        if version != ElfVersion::Current as _ {
            return Err("invalid ELF version".into());
        }

        Ok(Self {
            ident,
            ty,
            machine,
            version,
            entry: u64::from_le_bytes([
                left[8], left[9], left[10], left[11], left[12], left[13], left[14], left[15],
            ]),
            phoff: u64::from_le_bytes([
                left[16], left[17], left[18], left[19], left[20], left[21], left[22], left[23],
            ]),
            shoff: u64::from_le_bytes([
                left[24], left[25], left[26], left[27], left[28], left[29], left[30], left[31],
            ]),
            flags: u32::from_le_bytes([left[32], left[33], left[34], left[35]]),
            ehsize: u16::from_le_bytes([left[36], left[37]]),
            phentsize: u16::from_le_bytes([left[38], left[39]]),
            phnum: u16::from_le_bytes([left[40], left[41]]),
            shentsize: u16::from_le_bytes([left[42], left[43]]),
            shnum: u16::from_le_bytes([left[44], left[45]]),
            shstrndx: u16::from_le_bytes([left[46], left[47]]),
        })
    }
}

/// The initial bytes of the ELF file.
///
/// Specifies how to intepret the file, independent of the
/// processor on which the inquiry is made and independent of the file's remaining contents, to
/// support multiple processors, multiple data encodings and multiple classes of machines.
#[derive(Debug, Clone)]
pub struct ElfIdent {
    /// EI_MAG0 to EI_MAG3
    ///
    /// Magic number, identifying the file as an ELF object file.
    pub magic: [u8; 4],

    /// EI_CLASS
    ///
    ///Identifies the file's class, or capacity.
    pub class: ElfClass,

    /// EI_DATA
    ///
    ///Specifies the data encoding of the processor-specific data in the object file.
    pub data: Encoding,

    /// EI_VERSION
    ///
    /// Specifies the ELF header version number. Currently, this value must be
    /// [ElfVersion::Current].
    pub version: ElfVersion,

    /// Identifies the operating system and ABI for which the object if prepared.
    pub osabi: OsAbi,

    /// Identifies the version of the ABI for which the object is prepared.
    pub abi_version: u8,

    /// EI_PAD...
    ///
    /// Unused bytes. These bytes are reserved and set to zero; programs that read object files
    /// should ignore them.
    pub pad: [u8; 7],
}

impl ElfIdent {
    pub const fn new() -> Self {
        Self {
            magic: *b"\x7fELF",
            class: ElfClass::None,
            data: Encoding::None,
            version: ElfVersion::Current,
            osabi: OsAbi::SysV,
            abi_version: 0,
            pad: [0; 7],
        }
    }
}

impl Default for ElfIdent {
    fn default() -> Self {
        Self::new()
    }
}

impl_enum_try_from! {
    #[repr(u8)]
    #[derive(Debug, Default, Clone, Copy, PartialEq, Eq, Hash)]
    pub enum ElfClass {
        /// ELFCLASSNONE
        ///
        /// Invalid class.
        #[default]
        None = 0,

        /// ELFCLASS32
        ///
        /// 32-bit objects.
        Class32 = 1,

        /// ELFCLASS64
        ///
        /// 64-bit objects.
        Class64 = 2,
    },
    u8,
    String,
    "invalid ELF class".into()
}

impl_enum_try_from! {
    #[repr(u8)]
    #[derive(Debug, Default, Clone, Copy, PartialEq, Eq, Hash)]
    pub enum Encoding {
        /// ELFCLASSNONE
        ///
        /// Invalid class.
        #[default]
        None = 0,

        /// ELFDATA2LSB
        ///
        /// Specifies 2's complement values, with the least significant byte occupying the lowest
        /// address.
        LSB2 = 1,

        /// ELFDATA2MSB
        ///
        /// Specifies 2's complement values, with the most significant byte occupying the lowest
        /// address.
        MSB2 = 2,
    },
    u8,
    String,
    "invaild encoding".into()
}

impl_enum_try_from! {
    #[repr(u8)]
    #[derive(Debug, Default, Clone, Copy, PartialEq, Eq, Hash)]
    pub enum ElfVersion {
        /// Invalid version.
        None = 0,

        /// Current version.
        #[default]
        Current = 1,
    },
    u8,
    String,
    "not supported ELF version".into()
}

impl_enum_try_from! {
    #[repr(u8)]
    #[derive(Debug, Default, Clone, Copy, PartialEq, Eq, Hash)]
    pub enum OsAbi {
        /// ELFOSABI_SYSV
        ///
        /// System V ABI.
        #[default]
        SysV = 0,

        /// ELFOSABI_HPUX
        ///
        /// HP-UX operating system.
        HpUx = 1,

        /// ELFOSABI_STANDALONE
        ///
        /// Standalone (embedded) application.
        Standalone = 255,
    },
    u8,
    String,
    "not supported OS or ABI".into()
}

impl_enum_try_from! {
    #[repr(u16)]
    #[derive(Debug, Default, Clone, Copy, PartialEq, Eq, Hash)]
    pub enum ObjectFileType {
        /// ET_NONE
        ///
        /// No file type.
        #[default]
        None = 0,

        /// ET_REL
        ///
        /// Relocatable file.
        Rel = 1,

        /// ET_EXEC
        ///
        /// Executable file.
        Exec = 2,

        /// ET_DYN
        ///
        /// Shared object file.
        Dyn = 3,

        /// ET_CORE
        ///
        /// Core file.
        Core = 4,
    },
    u16,
    String,
    "invalid object file type".into()
}

impl_enum_try_from! {
    #[derive(Debug, Default, Clone, Copy, PartialEq, Eq, Hash)]
    #[repr(u16)]
    pub enum Machine {
        /// EM_NONE
        ///
        /// No macnihe.
        #[default]
        None = 0,

        /// EM_M32
        ///
        /// AT&T WE 32100
        M32 = 1,

        /// EM_SPARC
        ///
        /// SPARC.
        Sparc = 2,

        /// EM_386
        ///
        /// Intel 80386.
        I386 = 3,

        /// EM_68K
        ///
        /// Motorola 68000.
        Motorola68K = 4,

        /// EM_88K
        ///
        /// Motorola 88000
        Motorola88K = 5,

        /// EM_860
        ///
        /// Intel 80860
        I860 = 7,

        /// EM_MIPS
        ///
        /// MIPS RS3000
        Mips = 8,
    },
    u16,
    String,
    "invalid machine".into()
}

pub struct Elf64SectionHeader {
    /// Specifies the name of the section. Its value is an index into the section header string
    /// table section, giving the location of a null-terminated string.
    pub name: u32,

    /// Categorizes the section's contents and segmantics.
    pub ty: SectionType,

    /// Specifies 1-bit flags that describe miscellaneous attributes.
    pub flags: SectionFlag64,

    /// Gives the address at which the section's first byte should reside, if the section will
    /// apperar in the memory image of a process.
    pub addr: u64,

    /// Gives the byte offset from the beginning of the file to the first byte in the section.
    pub offset: u64,

    /// Gives the section's size in bytes.
    pub size: u64,

    /// Holds a section header table index link, whose interpretation depends on the section type.
    ///
    /// | Section | Interpretation |
    /// | :------ | :------------- |
    /// | [Dynamic][SectionType::Dynamic] | The section header index of the string table used by entries in the section. |
    /// | [Hash][SectionType::Hash] | The section header index of the symbol table to which the hash table applies. |
    /// | [Rel][SectionType::Rel] & [Rela][SectionType::Rela] | The section header index of the associated symbol table. |
    /// | [Symtab][SectionType::Symtab] & [Dynsym][SectionType::Dynsym] | This information is operating system specific. |
    /// | other | [SECTION_HEADER_NUMBER_UNDEF] |
    pub link: u32,

    /// Holds exrtra information, whose interpretation depends on the section type.
    ///
    /// | Section | Interpretation |
    /// | :------ | :------------- |
    /// | [Rel][SectionType::Rel] & [Rela][SectionType::Rela] | The section header index of the section to which the relocation applies. |
    /// | [Symtab][SectionType::Symtab] & [Dynsym][SectionType::Dynsym] | This information is operating system specific. |
    /// | other | 0 |
    pub info: u32,

    /// Gives the address alignment constraints. Only 0 and positive integral powers of two are
    /// allowed. Values 0 and 1 mean the section has no alignment constraints.
    pub addralign: u64,

    /// Gives the size in bytes of each entry, if the section holds a table of fixed-size entries.
    /// Value 0 means the section does not hold a table of fixed-size entries.
    pub entsize: u64,
}

impl_enum_try_from! {
    #[repr(u32)]
    pub enum SectionType {
        ///
        /// Marks the section header as inactive; it does not have an associated section. Other members
        /// of the section header have undefined values.
        Null = 0,

        /// SHT_PROGBITS
        ///
        /// The section holds information defined by the program, whose format and meaning are
        /// determined solely by the program.
        Progbits = 1,

        /// SHT_SYMTAB
        ///
        /// The section holds a symbol table.
        Symtab = 2,

        /// SHT_STRTAB
        ///
        /// The section holds a string table.
        Strtab = 3,

        /// SHT_RELA
        ///
        /// The section holds relocation entries with explicit addends, such as type `Elf32_Rela` for
        /// the 32-bit class of object files.
        Rela = 4,

        /// SHT_HASH
        ///
        /// The section holds a symbol hash table.
        Hash = 5,

        /// SHT_DYNAMIC
        ///
        /// The section holds information for dynamic linking.
        Dynamic = 6,

        /// SHT_NOTE
        ///
        /// The section holds information that marks the file in some way.
        Note = 7,

        /// SHT_NOBITS
        ///
        /// A section of this type ocuupies no space in the file but otherwise resembles
        /// `SHT_PROGBITS`. Although this section contains no bytes, the sh_offset member contains the
        /// conceptual file offset.
        Nobits = 8,

        /// SHT_REL
        ///
        /// The section holds relocation entries without explicit addends, such as type `Elf32_Rel` for
        /// the 32-bit class of object files. An object file may have multiple relocation sections.
        Rel = 9,

        /// SHT_SHLIB
        ///
        /// This section type is reserved but has unspecified semantics.
        Shlib = 10,

        /// SHT_DYNSYM
        ///
        /// Holds a symbol table.
        Dynsym = 11,
    },
    u32,
    String,
    "invalid section type".into()
}

bitflags! {
    pub struct SectionFlag64: u64 {
        /// SHF_WRITE
        ///
        /// The section contains data that should be writable during process exectuion.
        const WRITE = 0x1;

        /// SHF_ALLOC
        ///
        /// The section occupies memory during process execution. Some control sections do not
        /// reside in the memory image of an object file; this attribute is off for those sections.
        const ALLOC = 0x2;

        /// SHF_EXECINSTR
        ///
        /// The section contains executable machine instructions.
        const EXECINSTR = 0x4;

        // Makes these bits known. They are reserved for processor-specific semantics.
        const _ = 0xF000_0000;

        // Makes these bits known. They are reserved for environment-specific semantics.
        const _ = 0x0F00_0000;
    }
}

pub struct Elf64ProgramHeader {
    pub ty: SegmentType,
    pub flags: SegmentFlag,
    pub offset: u64,
    pub vaddr: u64,
    pub paddr: u64,
    pub filesz: u64,
    pub memsz: u64,
    pub align: u64,
}

impl_enum_try_from! {
    #[repr(u32)]
    pub enum SegmentType {
        Null = 0,
        Load = 1,
        Dynamic = 2,
        Interp = 3,
        Note = 4,
        Shlib = 5,
        Phdr = 6,
    },
    u32,
    String,
    "invalid segment type".into()
}

bitflags! {
    pub struct SegmentFlag: u32 {
        const X = 0x1;
        const W = 0x2;
        const R = 0x4;

        const _ = 0xF000_0000;
    }
}
