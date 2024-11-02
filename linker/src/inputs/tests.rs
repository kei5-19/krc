use std::fs::File;

use super::ObjectFile;

#[test]
fn input_test() {
    let file = File::open("/usr/bin/cat").unwrap();
    let _ = ObjectFile::from_reader(file).unwrap();
}
