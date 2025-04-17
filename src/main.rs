mod pe;
mod types;

use clap::{Args, Parser, ValueEnum};
use pe::Pe;
use std::{error::Error, path::PathBuf, process};
use tracing::{Level, error, trace};
use tracing_subscriber::FmtSubscriber;

/// impbind - PE import spoofer tool.
#[derive(Parser, Debug)]
#[command(version, about, long_about = None)]
struct Arguments {
    #[arg(index = 1)]
    file: PathBuf,
}

fn main() -> Result<(), Box<dyn Error>> {
    // create a new subscriber for tracing.
    let subscriber = FmtSubscriber::builder()
        .with_max_level(Level::TRACE)
        .without_time()
        .finish();

    // set it so that the newly created subscriber is the global default.
    tracing::subscriber::set_global_default(subscriber)?;

    // parse the command line arguments.
    let args = Arguments::parse();

    if let Err(e) = impbind(args) {
        error!("{e}");
        process::exit(-1);
    }

    Ok(())
}

fn impbind(args: Arguments) -> Result<(), Box<dyn Error>> {
    // create the PE object from file.
    let pe = Pe::from(args.file)?;

    println!("{:X?}", pe.get_dos_header());

    Ok(())
}
