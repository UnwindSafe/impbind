pub mod bind;
pub mod pe;
pub mod types;

use clap::Parser;
use log::{LevelFilter, debug, error, info, trace, warn};
use std::{error::Error, path::PathBuf, process};

/// impbind - PE import spoofer tool.
#[derive(Parser, Debug)]
#[command(version, about, long_about = None)]
pub struct Arguments {
    #[arg(index = 1)]
    pub file: PathBuf,

    /// Show the current imports for target file.
    #[arg(short, long)]
    list: bool,

    /// The list of imports you want to add to target file.
    #[arg(short, long, value_delimiter = ',', required = true)]
    pub imports: Vec<String>,
}

fn main() -> Result<(), Box<dyn Error>> {
    // set the environment variable so that it always prints logs, maybe a better way.
    unsafe { std::env::set_var("RUST_LOG", "trace") };

    pretty_env_logger::init();

    // parse the command line arguments.
    let args = Arguments::parse();

    if let Err(e) = bind::bind(args) {
        error!("ERROR: {e:?}");
        process::exit(-1);
    }

    Ok(())
}
