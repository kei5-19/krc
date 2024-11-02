use std::fs::File;

use super::ObjectFile;

#[test]
fn input_test() {
    let file = File::open("/usr/bin/cat").unwrap();
    let obj_file = ObjectFile::from_reader(file).unwrap();

    eprintln!("{:#x?}", obj_file);
}
