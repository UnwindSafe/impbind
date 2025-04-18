pub mod bind;
pub mod pe;
pub mod types;

use clap::Parser;
use std::{error::Error, path::PathBuf, process};

/// impbind - PE import spoofer tool.
#[derive(Parser, Debug)]
#[command(version, about, long_about = None)]
pub struct Arguments {
    #[arg(index = 1)]
    pub file: PathBuf,
}

fn main() -> Result<(), Box<dyn Error>> {
    // parse the command line arguments.
    let args = Arguments::parse();

    if let Err(e) = bind::bind(args) {
        println!("ERROR: {e}");
        process::exit(-1);
    }

    Ok(())
}
