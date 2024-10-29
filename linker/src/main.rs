use std::{env, process};

fn main() {
    let code = linker::main(env::args().collect());
    process::exit(code);
}
