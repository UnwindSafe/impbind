use thiserror::Error;
use tracing::{Level, error, info, trace};

use crate::{
    Arguments,
    pe::{Pe, PeError},
    types::IMAGE_DIRECTORY_ENTRY,
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

    info!("verifying file is an executable ...");

    // ensure that the pe file is valid.
    pe.verify()?;

    // get the import data directory.
    let import_directory =
        pe.get_nt_headers().OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY::IMPORT];

    if import_directory.VirtualAddress == 0 {
        return Err(BindError::NoImportDirectory);
    }

    pe.get_section_headers().unwrap();

    Ok(())
}
