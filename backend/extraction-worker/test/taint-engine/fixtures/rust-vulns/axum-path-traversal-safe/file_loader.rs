use std::fs::File;
use std::io::Read;

pub fn read_user_file(path: &str) -> Vec<u8> {
    let mut file = File::open(path).expect("open failed");
    let mut buf = Vec::new();
    file.read_to_end(&mut buf).expect("read failed");
    buf
}
