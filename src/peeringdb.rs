use log::set_logger_racy;
use serde_json;
use std::fs;

pub(crate) fn load_pdb_json_from_file(file_path: &str) -> std::io::Result<()> {
    let data = fs::read_to_string(file_path).expect("Unable to read file");

    let json: serde_json::Value =
        serde_json::from_str(&data).expect("JSON does not have correct format.");
    println!("{:?}", json);
    Ok(())
}
