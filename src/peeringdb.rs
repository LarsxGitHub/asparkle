use chrono::{Datelike, Duration, TimeZone, Utc};
use futures_util::StreamExt;
use indicatif::{ProgressBar, ProgressStyle};
use log::set_logger_racy;
use serde_json;
use std::collections::HashSet;
use std::fs;
use std::future::Future;
use std::io::Read;
use tokio;

static APP_USER_AGENT: &str = "aSparkle 0.1.0";

pub(crate) fn load_pdb_json_from_file(file_path: &str) -> serde_json::Value {
    let data = fs::read_to_string(file_path).expect("Unable to read file");
    serde_json::from_str(&data).expect("JSON does not have correct format.")
}

pub(crate) async fn loading_pdb_json_from_repo(ts: i64) {
    let date_time = Utc.timestamp_opt(ts, 0).unwrap();
    let yday = date_time - Duration::days(1);
    let url = format!(
        "https://publicdata.caida.org/datasets/peeringdb/{}/{:02}/peeringdb_2_dump_{}_{:02}_{:02}.json",
        yday.year(),
        yday.month(),
        yday.year(),
        yday.month(),
        yday.day()
    );

    // get a well-configured client
    // file is ~80MB; yet the repo's edge only provides few hundred KB/s -> multiple minutes.
    let client = reqwest::Client::builder()
        .user_agent(APP_USER_AGENT)
        .connect_timeout(std::time::Duration::from_secs(10))
        .timeout(std::time::Duration::from_secs(60 * 15))
        .build()
        .expect("Unable to build reqwest client.");

    // send the request
    let resp = client
        .get(&url)
        .send()
        .await
        .expect(&format!("Unable to read PeeringDB dump from '{}'.", &url));

    // figure out total content size
    let total_size: u64 = resp
        .content_length()
        .expect(&format!("Failed to get content length from '{}'", &url));

    // Indicatif setup
    let pb = ProgressBar::new(total_size);
    pb.set_style(ProgressStyle::default_bar()
        .template("{msg}\n{spinner:.green} [{elapsed_precise}] [{wide_bar:.cyan/blue}] {bytes}/{total_bytes} ({bytes_per_sec}, {eta})")
        .progress_chars("#>-"));
    pb.set_message(&format!("Downloading {}", url));

    let mut stream = resp.bytes_stream();
    let mut content_buffer: Vec<u8> = Vec::with_capacity(total_size as usize);
    while let Some(item) = stream.next().await {
        let chunk = item.expect(&format!("Failed to obtain chunk from '{}'", &url));
        content_buffer.extend_from_slice(&chunk);
        pb.set_position(
            content_buffer
                .len()
                .try_into()
                .expect("Message too large for progress bar."),
        );
    }
    pb.finish_with_message(&format!(
        "Successfully downloaded {} Bytes from {}.",
        content_buffer.len(),
        url
    ));

    serde_json::from_slice(content_buffer.as_slice())
        .expect(&format!("Unable to decode Json Message from '{}.'", &url))
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

pub(crate) fn load_routeservers_from_dump(
    file_path: &str,
    router_servers_ipv4: &mut HashSet<u32>,
    router_servers_ipv6: &mut HashSet<u32>,
) {
    let json = load_pdb_json_from_file(file_path);
    extract_route_servers(json, router_servers_ipv4, router_servers_ipv6);
}

#[cfg(test)]
mod tests {
    use crate::peeringdb::*;
    use tokio::task::spawn_blocking;

    #[ignore]
    #[tokio::test]
    async fn test_json_remote() {
        let data = loading_pdb_json_from_repo(1686787200).await;
        println!("{:#?}", data);
    }
}
