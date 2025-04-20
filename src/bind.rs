use comfy_table::{Table, modifiers::UTF8_ROUND_CORNERS, presets::UTF8_FULL};
use thiserror::Error;

use crate::{
    Arguments,
    pe::{Pe, PeError},
};

#[derive(Error, Debug)]
pub enum BindError {
    #[error(transparent)]
    PeError(#[from] PeError),
}

fn list_imports(pe: &Pe) -> Result<(), BindError> {
    let mut table = Table::new();

    // configure the table style.
    table
        .load_preset(UTF8_FULL)
        .apply_modifier(UTF8_ROUND_CORNERS)
        .set_header(vec!["DLL", "Function(s)"]);

    for desc in pe.get_import_descriptors()? {
        let functions = pe
            .get_ilt_thunks(&desc)?
            .iter()
            .map(|t| pe.get_thunk_function_name(t).unwrap_or_default())
            .collect::<Vec<_>>()
            .join("\n");

        // add the dll name and its functions to a row.
        table.add_row(vec![pe.get_string_at_rva(desc.Name)?, functions]);
    }

    println!("{table}");

    Ok(())
}

pub fn bind(args: Arguments) -> Result<(), BindError> {
    // create the PE object from file.
    let mut pe = Pe::from(args.file.clone())?;

    // ensure that the pe file is valid.
    pe.verify()?;

    // specified through the command line.
    if args.list_imports {
        return list_imports(&pe);
    }

    let section = pe.add_new_import_section(Some(".idata"), 0x1000)?;

    pe.copy_imports_to_rva(section.VirtualAddress)?;

    pe.set_import_directory_rva(section.VirtualAddress);

    pe.export(&format!(
        "{}.imp.exe",
        args.file.file_stem().unwrap().to_string_lossy()
    ))?;

    Ok(())
}
