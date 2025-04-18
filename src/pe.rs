use core::panic;
use std::{isize, path::PathBuf};

use thiserror::Error;

use crate::types::{
    IMAGE_DIRECTORY_ENTRY, IMAGE_DOS_HEADER, IMAGE_IMPORT_BY_NAME, IMAGE_IMPORT_DESCRIPTOR,
    IMAGE_NT_HEADERS64, IMAGE_SECTION_HEADER, IMAGE_THUNK_DATA64,
};

#[derive(Error, Debug)]
pub enum PeError {
    #[error(transparent)]
    IOError(#[from] std::io::Error),
    #[error("Invalid PE file.")]
    Invalid,
    #[error("RVA is not inside of a section.")]
    NotInSection,
}

type Result<T> = std::result::Result<T, PeError>;

/// This is an abstraction of a PE file on disk.
pub struct Pe {
    bytes: Vec<u8>,
}

impl Pe {
    pub fn from(path: PathBuf) -> Result<Self> {
        Ok(Self {
            bytes: std::fs::read(path)?,
        })
    }

    pub fn get_dos_header(&self) -> IMAGE_DOS_HEADER {
        unsafe { (self.bytes.as_ptr() as *const IMAGE_DOS_HEADER).read_unaligned() }
    }

    pub fn get_nt_headers_ptr(&self) -> *const IMAGE_NT_HEADERS64 {
        // get the dos header so we can find the nt headers through it.
        let dos_header = self.get_dos_header();

        unsafe { self.bytes.as_ptr().add(dos_header.e_lfanew as _) as *const IMAGE_NT_HEADERS64 }
    }

    pub fn get_nt_headers(&self) -> IMAGE_NT_HEADERS64 {
        unsafe { self.get_nt_headers_ptr().read_unaligned() }
    }

    /// Ensure that this is actually a PE file.
    pub fn verify(&self) -> Result<()> {
        // make sure the DOS header magic number is valid.
        if self.get_dos_header().e_magic != 0x5A4D {
            return Err(PeError::Invalid);
        }

        // ensure that both fields have their magic numbers correctly set.
        if self.get_nt_headers().Signature != 0x4550
            || self.get_nt_headers().OptionalHeader.Magic != 0x20B
        {
            return Err(PeError::Invalid);
        }

        Ok(())
    }

    pub fn get_section_headers(&self) -> Result<Vec<IMAGE_SECTION_HEADER>> {
        // get the address of the optional header.
        let oh_ptr =
            unsafe { std::ptr::addr_of!((*self.get_nt_headers_ptr()).OptionalHeader) } as *const u8;

        // get the nt headers so we can get header count and location.
        let nt = self.get_nt_headers();

        // get the number of sections in the exe.
        let section_counter = nt.FileHeader.NumberOfSections;

        // get the size of the optional header.
        let optional_header_sz = nt.FileHeader.SizeOfOptionalHeader as usize;

        let section_header_ptr =
            unsafe { oh_ptr.add(optional_header_sz) as *const IMAGE_SECTION_HEADER };

        // here we will put our collected section headers.
        let mut section_header: Vec<IMAGE_SECTION_HEADER> = Vec::new();

        for i in 0..section_counter as usize {
            // manually dereference (actually a copy) each header in the array.
            section_header.push(unsafe { section_header_ptr.add(i).read_unaligned() });
        }

        Ok(section_header)
    }

    /// Return a poninter, that points to an address inside of a section specified by the RVA.
    pub fn get_pointer_from_section(&self, rva: u32) -> Result<*const u8> {
        for section in self.get_section_headers()? {
            let start_address = section.VirtualAddress;
            let end_address = section.VirtualAddress + section.SizeOfRawData;

            // if the rva is in the range of the section.
            if rva >= start_address && rva < end_address {
                // get offset of the target from the section.
                let delta = rva as usize - section.VirtualAddress as usize;

                unsafe {
                    return Ok(self
                        .bytes
                        .as_ptr()
                        .add(section.PointerToRawData as usize + delta));
                }
            }
        }

        Err(PeError::NotInSection)
    }

    pub fn get_import_descriptors(&self) -> Result<Vec<IMAGE_IMPORT_DESCRIPTOR>> {
        // get the import data directory.
        let import_directory =
            self.get_nt_headers().OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY::IMPORT];

        if import_directory.VirtualAddress == 0 {
            todo!("make it so that we create our own directory.");
        }

        // get a pointer to the image import descriptor.
        let mut pointer = self.get_pointer_from_section(import_directory.VirtualAddress)?
            as *const IMAGE_IMPORT_DESCRIPTOR;

        let mut import_descriptors: Vec<_> = Vec::new();

        loop {
            // deref the current descriptor.
            let descriptor = unsafe { pointer.read_unaligned() };

            // if there is no name specified the descriptor is probably empty.
            if descriptor.Name == 0 {
                break;
            }

            import_descriptors.push(descriptor);

            unsafe {
                // advance the pointer to the next descriptor.
                pointer = pointer.add(1);
            }
        }

        Ok(import_descriptors)
    }

    /// Given a descriptor, return a vector of all of its ILT 'Thunks'.
    pub fn get_ilt_thunks(
        &self,
        descriptor: &IMAGE_IMPORT_DESCRIPTOR,
    ) -> Result<Vec<IMAGE_THUNK_DATA64>> {
        let mut thunk_ptr = unsafe {
            self.get_pointer_from_section(descriptor.Anonymous.OriginalFirstThunk)?
                as *const IMAGE_THUNK_DATA64
        };

        let mut thunks: Vec<_> = Vec::new();

        loop {
            // deref thunk so we can read its data.
            let thunk = unsafe { thunk_ptr.read_unaligned() };

            // ensure that the current thunk is valid.
            if unsafe { thunk.u1.AddressOfData } == 0 {
                break;
            }

            thunks.push(thunk);

            unsafe {
                // advance the pointer to the next thunk.
                thunk_ptr = thunk_ptr.add(1);
            }
        }

        Ok(thunks)
    }

    pub fn get_thunk_function_name(&self, thunk: &IMAGE_THUNK_DATA64) -> Result<String> {
        // this will actually fail if it's an ordinal, pretty cool.
        let pointer = self.get_pointer_from_section(unsafe { thunk.u1.AddressOfData as _ })?
            as *const IMAGE_IMPORT_BY_NAME;

        // a pointer to the name part of the struct.
        // this struct uses the 1 element array C idiom thing.
        let name_ptr = unsafe { &(*pointer).Name as *const i8 };

        // get the length of the string.
        let length = (0..)
            .take_while(|&i| unsafe { *name_ptr.add(i) } != 0)
            .count();

        let name_slice = unsafe { std::slice::from_raw_parts(name_ptr as *const u8, length) };

        Ok(String::from_utf8_lossy(name_slice).to_string())
    }

    /// Given an RVA, return a string from its location.
    pub fn get_string_at_rva(&self, rva: u32) -> Result<String> {
        // get a pointer to the string.
        let string_pointer = self.get_pointer_from_section(rva)?;

        let length = unsafe {
            // find the null byte from the start of the pointer.
            std::slice::from_raw_parts(string_pointer, isize::MAX as usize)
                .iter()
                .position(|&byte| byte == 0)
                .unwrap_or(0)
        };

        // NOTE: for some reason using string from raw parts crashes it.
        let slice = unsafe { std::slice::from_raw_parts(string_pointer, length) };

        Ok(String::from_utf8_lossy(slice).to_string())
    }
}
