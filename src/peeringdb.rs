use log::set_logger_racy;
use serde_json;
use std::collections::HashSet;
use std::fs;

pub(crate) fn load_pdb_json_from_file(file_path: &str) -> serde_json::Value {
    let data = fs::read_to_string(file_path).expect("Unable to read file");
    serde_json::from_str(&data).expect("JSON does not have correct format.")
}

pub(crate) fn extract_route_servers(
    json: serde_json::Value,
    router_servers_ipv4: &mut HashSet<u32>,
    router_servers_ipv6: &mut HashSet<u32>,
) {
    // go through all the data
    for elem in json["net"]["data"]
        .as_array()
        .expect("Provided json file does not contain a list at the key chain json[net][data].")
    {
        if elem["info_type"].as_str() != Some("Route Server") {
            continue;
        }
        router_servers_ipv4.insert(
            elem["asn"]
                .as_u64()
                .expect("Expected Route Server ASN to be u64 convertable.") as u32,
        );
        if elem["info_ipv6"].as_bool() == Some(true) {
            router_servers_ipv6.insert(
                elem["asn"]
                    .as_u64()
                    .expect("Expected Route Server ASN to be u64 convertable.")
                    as u32,
            );
        }
    }
}