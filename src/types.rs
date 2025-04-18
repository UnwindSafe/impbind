#![allow(non_camel_case_types)]
#![allow(non_snake_case)]

#[repr(C, packed(2))]
#[derive(Debug)]
pub struct IMAGE_DOS_HEADER {
    pub e_magic: u16,
    pub e_cblp: u16,
    pub e_cp: u16,
    pub e_crlc: u16,
    pub e_cparhdr: u16,
    pub e_minalloc: u16,
    pub e_maxalloc: u16,
    pub e_ss: u16,
    pub e_sp: u16,
    pub e_csum: u16,
    pub e_ip: u16,
    pub e_cs: u16,
    pub e_lfarlc: u16,
    pub e_ovno: u16,
    pub e_res: [u16; 4],
    pub e_oemid: u16,
    pub e_oeminfo: u16,
    pub e_res2: [u16; 10],
    pub e_lfanew: i32,
}

#[repr(C)]
#[derive(Debug)]
pub struct IMAGE_NT_HEADERS64 {
    pub Signature: u32,
    pub FileHeader: IMAGE_FILE_HEADER,
    pub OptionalHeader: IMAGE_OPTIONAL_HEADER64,
}

#[repr(C)]
#[derive(Debug)]
pub struct IMAGE_FILE_HEADER {
    pub Machine: u16,
    pub NumberOfSections: u16,
    pub TimeDateStamp: u32,
    pub PointerToSymbolTable: u32,
    pub NumberOfSymbols: u32,
    pub SizeOfOptionalHeader: u16,
    pub Characteristics: u16,
}

#[repr(C, packed(4))]
#[derive(Debug)]
pub struct IMAGE_OPTIONAL_HEADER64 {
    pub Magic: u16,
    pub MajorLinkerVersion: u8,
    pub MinorLinkerVersion: u8,
    pub SizeOfCode: u32,
    pub SizeOfInitializedData: u32,
    pub SizeOfUninitializedData: u32,
    pub AddressOfEntryPoint: u32,
    pub BaseOfCode: u32,
    pub ImageBase: u64,
    pub SectionAlignment: u32,
    pub FileAlignment: u32,
    pub MajorOperatingSystemVersion: u16,
    pub MinorOperatingSystemVersion: u16,
    pub MajorImageVersion: u16,
    pub MinorImageVersion: u16,
    pub MajorSubsystemVersion: u16,
    pub MinorSubsystemVersion: u16,
    pub Win32VersionValue: u32,
    pub SizeOfImage: u32,
    pub SizeOfHeaders: u32,
    pub CheckSum: u32,
    pub Subsystem: u16,
    pub DllCharacteristics: u16,
    pub SizeOfStackReserve: u64,
    pub SizeOfStackCommit: u64,
    pub SizeOfHeapReserve: u64,
    pub SizeOfHeapCommit: u64,
    pub LoaderFlags: u32,
    pub NumberOfRvaAndSizes: u32,
    pub DataDirectory: [IMAGE_DATA_DIRECTORY; 16],
}

#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct IMAGE_DATA_DIRECTORY {
    pub VirtualAddress: u32,
    pub Size: u32,
}

pub mod IMAGE_DIRECTORY_ENTRY {
    pub const EXPORT: usize = 0;
    pub const IMPORT: usize = 1;
    pub const RESOURCE: usize = 2;
    pub const EXCEPTION: usize = 3;
    pub const SECURITY: usize = 4;
    pub const BASERELOC: usize = 5;
    pub const DEBUG: usize = 6;
    pub const ARCHITECTURE: usize = 7;
    pub const GLOBALPTR: usize = 8;
    pub const TLS: usize = 9;
    pub const LOAD_CONFIG: usize = 10;
    pub const BOUND_IMPORT: usize = 11;
    pub const IAT: usize = 12;
    pub const DELAY_IMPORT: usize = 13;
    pub const COM_DESCRIPTOR: usize = 14;
}

pub const IMAGE_NUMBER_OF_DIRECTORY_ENTRIES: usize = 16;

#[repr(C)]
pub struct IMAGE_SECTION_HEADER {
    pub Name: [u8; 8],
    pub Misc: IMAGE_SECTION_HEADER_0,
    pub VirtualAddress: u32,
    pub SizeOfRawData: u32,
    pub PointerToRawData: u32,
    pub PointerToRelocations: u32,
    pub PointerToLinenumbers: u32,
    pub NumberOfRelocations: u16,
    pub NumberOfLinenumbers: u16,
    pub Characteristics: u32,
}

impl IMAGE_SECTION_HEADER {
    pub fn get_name(&self) -> String {
        String::from_utf8_lossy(&self.Name).to_string()
    }
}

#[repr(C)]
pub union IMAGE_SECTION_HEADER_0 {
    pub PhysicalAddress: u32,
    pub VirtualSize: u32,
}

#[repr(C)]
pub struct IMAGE_IMPORT_DESCRIPTOR {
    pub Anonymous: IMAGE_IMPORT_DESCRIPTOR_0,
    pub TimeDateStamp: u32,
    pub ForwarderChain: u32,
    pub Name: u32,
    pub FirstThunk: u32,
}

#[repr(C)]
pub union IMAGE_IMPORT_DESCRIPTOR_0 {
    pub Characteristics: u32,
    pub OriginalFirstThunk: u32,
}

#[repr(C)]
pub struct IMAGE_THUNK_DATA64 {
    pub u1: IMAGE_THUNK_DATA64_0,
}

#[repr(C)]
pub union IMAGE_THUNK_DATA64_0 {
    pub ForwarderString: u64,
    pub Function: u64,
    pub Ordinal: u64,
    pub AddressOfData: u64,
}
