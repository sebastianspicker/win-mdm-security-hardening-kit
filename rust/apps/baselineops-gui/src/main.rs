//! Native, read-only `BaselineOps` v3 Windows launcher.

#![cfg_attr(windows, windows_subsystem = "windows")]

#[cfg(any(windows, test))]
mod controller;

#[cfg(windows)]
mod platform;
#[cfg(windows)]
mod view;

#[cfg(not(windows))]
fn main() {
    eprintln!("baselineops-gui is supported only on Windows 11 x64");
    std::process::exit(baselineops_domain::ExitCode::Unsupported.as_i32());
}

#[cfg(windows)]
fn main() -> windows::core::Result<()> {
    platform::run()
}
