use thiserror::Error;

use crate::{
    Arguments,
    pe::{Pe, PeError},
    types::{IMAGE_DIRECTORY_ENTRY, IMAGE_IMPORT_DESCRIPTOR},
};

#[derive(Error, Debug)]
pub enum BindError {
    #[error("PE doesn't have import directory.")]
    NoImportDirectory,
    #[error(transparent)]
    PeError(#[from] PeError),
}

pub fn bind(args: Arguments) -> Result<(), BindError> {
    // create the PE object from file.
    let pe = Pe::from(args.file)?;

    // ensure that the pe file is valid.
    pe.verify()?;

    // get the import data directory.
    let import_directory =
        pe.get_nt_headers().OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY::IMPORT];

    if import_directory.VirtualAddress == 0 {
        return Err(BindError::NoImportDirectory);
    }

    // get a pointer to the image import descriptor.
    let pointer = pe.get_pointer_from_section(import_directory.VirtualAddress)?
        as *const IMAGE_IMPORT_DESCRIPTOR;

    let name = unsafe { (*pointer).Name };

    unsafe { println!("{:X?}", (*pointer).Name) }
    println!("{:?}", pe.get_string_at_rva(name));

    Ok(())
}
