use std::{env, process};

fn main() {
    let code = linker::main(env::args().into_iter().collect());
    process::exit(code);
}
