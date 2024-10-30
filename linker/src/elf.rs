//! See [Executable and Linking Format (ELF) Specification] and [ELF-64 Object File Format].
//!
//! [Executable and Linking Format (ELF) Specification]:
//! https://refspecs.linuxfoundation.org/elf/elf.pdf
//! [ELF-64 Object File Format]: https://uclibc.org/docs/elf-64-gen.pdf

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
    /// table. If the file has no section name string table, holds the value SHN_UNDEF.
    // TODO: Do not use SHN_UNDEF here.
    pub shstrndx: u16,
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
}

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
}

#[repr(u8)]
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq, Hash)]
pub enum ElfVersion {
    /// Invalid version.
    None = 0,

    /// Current version.
    #[default]
    Current = 1,
}

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
}

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
}

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
}
