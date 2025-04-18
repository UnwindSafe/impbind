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

    for x in pe.get_import_descriptors()? {
        println!("{}", pe.get_string_at_rva(x.Name)?);
    }

    Ok(())
}
