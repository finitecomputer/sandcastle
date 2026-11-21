//! `nitro-probe`: a Nitro Sandbox guest's init (docs/nitro-spike.md).

#[cfg(target_os = "linux")]
fn main() {
    sandcastle_nitro_probe::guest::main()
}

#[cfg(not(target_os = "linux"))]
fn main() {
    eprintln!("nitro-probe is a Linux guest's init");
    std::process::exit(2);
}
