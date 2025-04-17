use std::path::PathBuf;

use thiserror::Error;
use tracing::trace;

use crate::types::{IMAGE_DOS_HEADER, IMAGE_NT_HEADERS64, IMAGE_SECTION_HEADER};
use std::ptr::addr_of;

#[derive(Error, Debug)]
pub enum PeError {
    #[error(transparent)]
    IOError(#[from] std::io::Error),
    #[error("Invalid PE file.")]
    Invalid,
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
}
