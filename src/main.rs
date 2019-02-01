#![allow(warnings)]
#[macro_use]
extern crate log;

mod sets;
mod util;

fn main() -> Result<(), Box<std::error::Error>> {
    simplelog::CombinedLogger::init(vec![simplelog::WriteLogger::new(
        log::LevelFilter::Debug,
        simplelog::Config::default(),
        std::io::stdout(),
        //File::create("../log").unwrap(),
    )])?;
    println!("Run \"cargo test\"");
    Ok(())
}
