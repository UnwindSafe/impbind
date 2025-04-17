pub mod bind;
pub mod pe;
pub mod types;

use clap::{Args, Parser, ValueEnum};
use std::{error::Error, path::PathBuf, process};
use tracing::{Level, error, info, trace};
use tracing_subscriber::FmtSubscriber;

/// impbind - PE import spoofer tool.
#[derive(Parser, Debug)]
#[command(version, about, long_about = None)]
pub struct Arguments {
    #[arg(index = 1)]
    pub file: PathBuf,
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

    info!("selected {:?}", args.file.clone());

    if let Err(e) = bind::bind(args) {
        error!("{e}");
        process::exit(-1);
    }

    Ok(())
}
