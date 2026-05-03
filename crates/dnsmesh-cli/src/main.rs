//! `dnsmesh` — DMP command-line interface.
//!
//! Thin shell over the `DmpClient` async API. The interesting work lives
//! in the submodules: clap definitions in `cli`, config plumbing in
//! `config`, client construction in `client_factory`, and per-command
//! dispatch in `commands`.

use std::process::ExitCode;

use clap::Parser;

mod cli;
mod client_factory;
mod commands;
mod config;
mod mua;

fn main() -> ExitCode {
    init_tracing();
    let args = cli::Args::parse();

    let runtime = match tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
    {
        Ok(rt) => rt,
        Err(e) => {
            eprintln!("dnsmesh: failed to start tokio runtime: {e}");
            return ExitCode::from(2);
        }
    };

    match runtime.block_on(commands::dispatch(args)) {
        Ok(()) => ExitCode::SUCCESS,
        Err(err) => {
            eprintln!("dnsmesh: {err:#}");
            ExitCode::from(1)
        }
    }
}

/// Initialise the global tracing subscriber.
///
/// Defaults to `warn` so the CLI stays quiet enough to be a sendmail
/// transport. `RUST_LOG` overrides for debugging. Errors here are
/// silently ignored — never block startup over telemetry plumbing.
fn init_tracing() {
    use tracing_subscriber::EnvFilter;
    let filter = EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("warn"));
    let _ = tracing_subscriber::fmt()
        .with_env_filter(filter)
        .with_writer(std::io::stderr)
        .try_init();
}
