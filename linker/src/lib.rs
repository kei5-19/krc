use std::{
    fs::OpenOptions,
    os::unix::fs::{OpenOptionsExt, PermissionsExt},
};

pub mod elf;

pub fn main(_args: Vec<String>) -> i32 {
    let filename = "a.out";
    let file = match OpenOptions::new()
        .create(true)
        .truncate(true)
        .write(true)
        .mode(0o777)
        .open(filename)
    {
        Ok(file) => file,
        Err(e) => {
            eprintln!("cannot open file: {}", e);
            return 1;
        }
    };
    let mut perm = match file.metadata() {
        Ok(meta) => meta.permissions(),
        Err(e) => {
            eprintln!("failed to get metadata: {}", e);
            return 1;
        }
    };
    perm.set_mode(0o777);
    if let Err(e) = file.set_permissions(perm) {
        eprintln!("failed to set permissions: {}", e);
        return 1;
    }

    0
}
