//! Per-subcommand entry points.
//!
//! Every command receives the parsed clap [`Args`] and returns
//! `Result<()>`. The dispatcher in [`dispatch`] lifts that into the
//! process exit code at the top of `main`.

use anyhow::Result;

use crate::cli::{Args, Command};

pub mod contacts;
pub mod doctor;
pub mod identity;
pub mod init;
pub mod intro;
pub mod purge;
pub mod recv;
pub mod register;
pub mod send;

pub async fn dispatch(args: Args) -> Result<()> {
    let config_override = args.config.clone();
    let passphrase_env = args.insecure_passphrase_env.clone();

    match args.command {
        Command::Init(a) => {
            init::run(a, config_override.as_deref(), passphrase_env.as_deref()).await
        }
        Command::Identity(c) => {
            identity::run(c, config_override.as_deref(), passphrase_env.as_deref()).await
        }
        Command::Contacts(c) => {
            contacts::run(c, config_override.as_deref(), passphrase_env.as_deref()).await
        }
        Command::Intro(c) => {
            intro::run(c, config_override.as_deref(), passphrase_env.as_deref()).await
        }
        Command::Send(a) => {
            send::run(a, config_override.as_deref(), passphrase_env.as_deref()).await
        }
        Command::Recv(a) => {
            recv::run(a, config_override.as_deref(), passphrase_env.as_deref()).await
        }
        Command::Doctor => doctor::run(config_override.as_deref(), passphrase_env.as_deref()).await,
        Command::Purge(a) => {
            purge::run(a, config_override.as_deref(), passphrase_env.as_deref()).await
        }
        Command::Register(a) => {
            register::run_register(a, config_override.as_deref(), passphrase_env.as_deref()).await
        }
        Command::Tsig(c) => {
            register::run_tsig(c, config_override.as_deref(), passphrase_env.as_deref()).await
        }
    }
}
