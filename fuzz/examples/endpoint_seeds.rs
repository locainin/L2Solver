use l2solver_fuzz::endpoint_seeds::write_seed_files;
use std::{env, error::Error, path::Path};

fn main() -> Result<(), Box<dyn Error>> {
    let mut arguments = env::args_os().skip(1);
    let output_directory = arguments
        .next()
        .ok_or("usage: endpoint_seeds <ignored-output-directory>")?;
    if arguments.next().is_some() {
        return Err("usage: endpoint_seeds <ignored-output-directory>".into());
    }
    let paths = write_seed_files(Path::new(&output_directory))?;
    for path in paths {
        println!("{}", path.display());
    }
    Ok(())
}
