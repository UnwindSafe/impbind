use std::{collections::HashMap, task::Wake};

use comfy_table::{Table, modifiers::UTF8_ROUND_CORNERS, presets::UTF8_FULL};
use log::info;
use thiserror::Error;

use crate::{
    Arguments,
    pe::{Pe, PeError},
    types::Import,
};

#[derive(Error, Debug)]
pub enum BindError {
    #[error(transparent)]
    PeError(#[from] PeError),
    #[error("Could not parse import '{0}'.")]
    InvalidImport(String),
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

/// This will turn an import string into an `Import`.
///
/// e.g. "kernel32.exe!ReadProcessMemory" -> Import
fn parse_user_imports(imports: &Vec<String>) -> Result<Vec<Import>, BindError> {
    // this will map a dll name to function names.
    let mut map: HashMap<&str, Vec<String>> = HashMap::new();

    for import in imports {
        let (module, function) = import
            .split_once('!')
            .ok_or(BindError::InvalidImport(import.clone()))?;

        // add this function for the module key.
        map.entry(module)
            .or_insert_with(Vec::new)
            .push(function.to_string());
    }

    Ok(map
        .iter()
        .map(|(k, v)| Import {
            file: k.to_string(),
            functions: v.clone(),
        })
        .collect())
}

pub fn bind(args: Arguments) -> Result<(), BindError> {
    // create the PE object from file.
    let mut pe = Pe::from(args.file.clone())?;

    info!("verifying file.");

    // ensure that the pe file is valid.
    pe.verify()?;

    // specified through the command line.
    if args.list {
        info!(
            "showing the list of '{}' imports.",
            args.file.to_string_lossy()
        );
        return list_imports(&pe);
    }

    parse_user_imports(&args.imports);

    let mut x = Vec::new();

    for _ in 0..2 {
        x.push("LOOOOOOOOOOOL".to_string())
    }

    let import_2 = Import::new("ntdll.dll".to_string(), x);

    let size = pe.get_custom_import_size(vec![import_2.clone()])?;

    let section = pe.add_new_import_section(Some(".idata"), size as _)?;

    pe.copy_imports_to_rva(section.VirtualAddress)?;

    pe.set_import_directory_rva(section.VirtualAddress);

    pe.add_imports_for_section(None, vec![import_2])?;

    pe.export(&format!(
        "{}.imp.exe",
        args.file.file_stem().unwrap().to_string_lossy()
    ))?;

    Ok(())
}
