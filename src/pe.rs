use std::path::PathBuf;

use thiserror::Error;

use crate::types::{IMAGE_DOS_HEADER, IMAGE_NT_HEADERS64};

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

    pub fn get_nt_headers(&self) -> IMAGE_NT_HEADERS64 {
        // get the dos header so we can find the nt headers through it.
        let dos_header = self.get_dos_header();

        unsafe {
            (self.bytes.as_ptr().add(dos_header.e_lfanew as _) as *const IMAGE_NT_HEADERS64)
                .read_unaligned()
        }
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
}
