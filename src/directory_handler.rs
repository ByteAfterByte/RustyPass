use directories::ProjectDirs;
use std::path::PathBuf;

pub fn get_directory() -> PathBuf {
    let dirs = ProjectDirs::from("com", "ByteAfterByte", "RustyPass").expect("Could not determine the application data directory.");

    let data_directory = dirs.data_dir();

    std::fs::create_dir_all(data_directory).expect("Failed to create RustyPass data directory.");

    data_directory.to_path_buf()
}