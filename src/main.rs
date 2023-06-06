use bgpkit_broker::{BgpkitBroker, BrokerItem, QueryParams};
use bgpkit_parser::BgpkitParser;
use chrono::{DateTime, FixedOffset, NaiveDate};
use mysql;

use rpki::repository::aspa::{AsProviderAttestation, Aspa};
use rpki::repository::resources::AddressFamily;
use std::any::Any;

use crate::aspa::UpstreamExtractionResult;
use clap::{Arg, ArgMatches};
use inc_stats::Percentiles;
use itertools::Itertools;
use std::collections::{HashMap, HashSet};
use std::error::Error;
use std::fmt::Display;
use std::fs;
use std::path::PathBuf;
use std::process::exit;

use serde::{Deserialize, Serialize};
use serde_yaml::{self};

// the percentiles that will be calculated in addition to min and max.
const PERCENTILE_LIST: [f64; 7] = [0.05, 0.10, 0.25, 0.5, 0.75, 0.90, 0.95];

mod aspa;
mod db;
mod peeringdb;
mod pipeline;
mod utils;

#[macro_export]
/// macro that logs an error message bevor exiting.
macro_rules! exit_msg {
    ($($msg:tt)*) => {
        println!($($msg)*);
        exit(1);
    }
}

/// parses the input date and provides the timestamp for start-of-day DateTime.
fn parse_input_ts(cli_args: &ArgMatches) -> i64 {
    let date_str: &String;
    match cli_args.get_one::<String>("date") {
        Some(d) => date_str = d,
        None => {
            exit_msg!("ERROR: Required parameter 'date' was not provided.");
        }
    };

    // check if date is malformatted.
    if let Err(e) = NaiveDate::parse_from_str(date_str, "%Y-%m-%d") {
        exit_msg!("ERROR: Date is incorrectly formatted, see: {}", e);
    }

    // extend date to start-of-day DateTimeit push origin
    let date_str = String::from(date_str) + " 00:00:00.000 +0000";
    let date: DateTime<FixedOffset>;
    match DateTime::parse_from_str(&date_str, "%Y-%m-%d %H:%M:%S%.3f %z") {
        Ok(dt) => date = dt,
        Err(e) => {
            // this should never happen
            exit_msg!("ERROR: NaiveDate to DateTime conversion failed, see: {}", e);
        }
    }

    date.timestamp()
}

fn parse_file_with_ext(cli_args: &ArgMatches, file_key: &str, extension: &str) -> String {
    // get path from cli args
    let file = cli_args.get_one::<String>(&file_key).expect(&format!(
        "Required parameter '{}' was not provided.",
        file_key
    ));

    // canonicalize the path
    let file_canon =
        fs::canonicalize(file).expect(&format!("Unable to canonicalize path {:?}", file));

    // check whether path is a file
    if !PathBuf::from(&file_canon).is_file() {
        exit_msg!(
            "ERROR: Required parameter '{}' was set to {}, which is not a file.",
            file_key,
            file
        );
    }

    // check that extension is .json
    if !file.ends_with(extension) {
        exit_msg!(
            "ERROR: Required parameter '{}' was set to {}, which does not have a {} suffix.",
            file_key,
            file,
            extension
        );
    }

    file_canon.into_os_string().into_string().expect(&format!(
        "Unable to get os string from {} ({})",
        file_key, file
    ))
}

fn parse_aspa_dir(cli_args: &ArgMatches) -> String {
    // get path from cli args
    let aspa_dir = cli_args
        .get_one::<String>("aspa_dir")
        .expect("Required parameter 'aspa_dir' was not provided.");

    // canonicalize the path
    let aspa_dir_canon =
        fs::canonicalize(aspa_dir).expect(&format!("Unable to canonicalize path {:?}", aspa_dir));

    // check whether path is a directory
    if !PathBuf::from(&aspa_dir_canon).is_dir() {
        exit_msg!(
            "ERROR: Required parameter 'aspa_dir' was set to {}, which is not a directory.",
            aspa_dir
        );
    }

    let mut has_some_asa_file = false;
    for entry in fs::read_dir(&aspa_dir_canon).expect(&format!(
        "Unable to read contents of aspa_dir directory {}",
        aspa_dir
    )) {
        let link = entry
            .expect(&format!(
                "Unable to obtain path for spme file in aspa_dir ({}).",
                aspa_dir
            ))
            .path()
            .into_os_string()
            .into_string()
            .expect(&format!(
                "Unable to obtain os string for some file in aspa_dir ({}).",
                aspa_dir
            ));
        // ensure it's an .asa file, then append to vector.
        if link.ends_with(".asa") {
            has_some_asa_file = true;
            break;
        }
    }

    if !has_some_asa_file {
        exit_msg!(
            "ERROR: Can't find any *.asa files in aspa_dir ({})",
            aspa_dir
        );
    }

    aspa_dir_canon
        .into_os_string()
        .into_string()
        .expect(&format!(
            "Unable to get os string from aspa_dir {}",
            aspa_dir
        ))
}

/// Gets CLI parameters passed to the binary
fn get_cli_parameters() -> ArgMatches {
    clap::Command::new("asparkle")
        .about("Deployment and compliance statistic for ASPA records at your fingertips.")
        .author("Lars Prehn")
        .version("0.1.0")
        // Logging settings
        .arg(
            Arg::new("date")
                .short('d')
                .long("date")
                .required(true)
                .value_parser(clap::builder::NonEmptyStringValueParser::new())
                .help("The date for which you want to calculate statistics."),
        )
        .arg(
            Arg::new("aspa_dir")
                .short('a')
                .long("aspa_dir")
                .required(true)
                .value_parser(clap::builder::NonEmptyStringValueParser::new())
                .help("the path to a directory containing .asa aspa files."),
        )
        .arg(
            Arg::new("pdb_dump")
                .short('p')
                .long("pdb_dump")
                .required(true)
                .value_parser(clap::builder::NonEmptyStringValueParser::new())
                .help("the path to a PeeringDB Json dump file."),
        )
        .arg(
            Arg::new("config")
                .short('c')
                .long("config")
                .required(true)
                .value_parser(clap::builder::NonEmptyStringValueParser::new())
                .help("the path to the config.yaml file."),
        )
        .get_matches()
}

/// Caluclates the min, percentiles within @percentile_list, and max of the set sizes within the
/// values of the @themap map. Returns an vector with only zeros if @themap has no value sets.
fn calc_set_site_percentiles<T, U>(
    themap: &HashMap<T, HashSet<U>>,
    percentile_list: &[f64],
) -> Vec<usize> {
    let mut percs = Percentiles::new();
    let mut max: usize = 0;
    let mut min: Option<usize> = None;
    for (_, value_set) in themap.iter() {
        let n = value_set.len();
        // add to percentile calulcation
        percs.add(n as f32);

        // set the maximum
        if max < n {
            max = n;
        }

        // set the minimum accurately.
        if let Some(m) = min {
            if n < m {
                min = Some(n);
            }
        } else {
            min = Some(n);
        }
    }

    let mut result_vec: Vec<usize> = Vec::new();

    // add the min value.
    if let Some(m) = min {
        result_vec.push(m)
    } else {
        // unable to calc anything on empty map, return [0, 0, ..., 0]
        for i in 1..percentile_list.len() + 2 {
            result_vec.push(0);
        }
        return result_vec;
    }

    // add the percentiles
    for value in percs
        .percentiles(percentile_list)
        .expect("Unable to calculate percentile statistics.")
        .expect("Percentile calculation did not result in usable metric.")
        .iter()
    {
        result_vec.push(value.round() as usize);
    }

    // add the max value.
    result_vec.push(max);
    result_vec
}

fn derive_attestation_statistics(attestations: &Vec<AsProviderAttestation>) {
    // number of attestations
    let num_attests_total = attestations.len();
    let mut num_attests_ipv4: usize = 0;
    let mut num_attests_ipv6: usize = 0;
    let mut num_attests_both: usize = 0;

    // providers per customer
    let mut providers_per_customer_total: HashMap<u32, HashSet<u32>> = HashMap::new();
    let mut providers_per_customer_ipv4: HashMap<u32, HashSet<u32>> = HashMap::new();
    let mut providers_per_customer_ipv6: HashMap<u32, HashSet<u32>> = HashMap::new();
    let mut providers_per_customer_both: HashMap<u32, HashSet<u32>> = HashMap::new();

    for attest in attestations {
        let customer = attest.customer_as().into_u32();
        let mut uses_afi_limit_ipv4 = false;
        let mut uses_afi_limit_ipv6 = false;
        for provider_as_set in attest.provider_as_set().iter() {
            let provider: u32 = provider_as_set.provider().into_u32();
            utils::add_to_hashmap_set(&mut providers_per_customer_total, &customer, &provider);

            if let Some(family) = provider_as_set.afi_limit() {
                // afi limited records
                match family {
                    AddressFamily::Ipv4 => {
                        uses_afi_limit_ipv4 = true;
                        utils::add_to_hashmap_set(
                            &mut providers_per_customer_ipv4,
                            &customer,
                            &provider,
                        );
                    }
                    AddressFamily::Ipv6 => {
                        uses_afi_limit_ipv6 = true;
                        utils::add_to_hashmap_set(
                            &mut providers_per_customer_ipv6,
                            &customer,
                            &provider,
                        );
                    }
                }
            } else {
                // not afi_limited record
                utils::add_to_hashmap_set(&mut providers_per_customer_ipv4, &customer, &provider);
                utils::add_to_hashmap_set(&mut providers_per_customer_ipv6, &customer, &provider);
            }
        }

        // count the afi usage.
        if uses_afi_limit_ipv4 && uses_afi_limit_ipv6 {
            num_attests_both += 1;
        }
        if uses_afi_limit_ipv4 {
            num_attests_ipv4 += 1
        }
        if uses_afi_limit_ipv6 {
            num_attests_ipv6 += 1
        }
    }
    println!("Attestations in total: {}.", num_attests_total);
    println!("Attestations with IPv4 AFI_LIMITs: {}.", num_attests_ipv4);
    println!("Attestations with IPv6 AFI_LIMITs: {}.", num_attests_ipv6);
    println!(
        "Attestations with IPv4 and IPv6 AFI_LIMITs: {}.",
        num_attests_both
    );

    // calc the overlap between ipv4 and ipv6 hashmap sets.
    utils::intersect_hashmap_sets(
        &providers_per_customer_ipv4,
        &providers_per_customer_ipv6,
        &mut providers_per_customer_both,
    );

    let distr_provsetlen_total =
        calc_set_site_percentiles(&providers_per_customer_total, &PERCENTILE_LIST);
    let distr_provsetlen_ipv4 =
        calc_set_site_percentiles(&providers_per_customer_ipv4, &PERCENTILE_LIST);
    let distr_provsetlen_ipv6 =
        calc_set_site_percentiles(&providers_per_customer_ipv6, &PERCENTILE_LIST);
    let distr_provsetlen_both =
        calc_set_site_percentiles(&providers_per_customer_both, &PERCENTILE_LIST);

    println!(
        "Distr. approx. for number of providers per customer, all attestations: {:?}",
        distr_provsetlen_total
    );
    println!(
        "Distr. approx. for number of providers per customer with Ipv4 attestations: {:?}",
        distr_provsetlen_ipv4
    );
    println!(
        "Distr. approx. for number of providers per customer with Ipv6 attestations: {:?}",
        distr_provsetlen_ipv6
    );
    println!(
        "Distr. approx. for number of providers per customer with IPv4 and IPv6 attestations: {:?}",
        distr_provsetlen_both
    );

    println!(
        "Number of Customer ASes with attestations: {}",
        providers_per_customer_total.len()
    );
    println!(
        "Number of Customer ASes with IPv4 attestations: {}",
        providers_per_customer_ipv4.len()
    );
    println!(
        "Number of Customer ASes with IPv6 attestations: {}",
        providers_per_customer_ipv6.len()
    );
    println!(
        "Number of Customer ASes with IPv4 and IPv6 attestations: {}",
        providers_per_customer_both.len()
    );
    println!(
        "Number of unique Provider ASes mentioned in any attestation: {}.",
        utils::collaps_hashmap_sets_via_union(&providers_per_customer_total).len()
    );
    println!(
        "Number of unique Provider ASes mentioned in IPv4 attestations: {}.",
        utils::collaps_hashmap_sets_via_union(&providers_per_customer_ipv4).len()
    );
    println!(
        "Number of unique Provider ASes mentioned in IPv6 attestations: {}.",
        utils::collaps_hashmap_sets_via_union(&providers_per_customer_ipv6).len()
    );
    println!(
        "Number of unique Provider ASes mentioned in IPv4 and IPv6 attestations: {}.",
        utils::collaps_hashmap_sets_via_union(&providers_per_customer_both).len()
    );
}

#[derive(Debug, Serialize, Deserialize)]
pub(crate) struct Config {
    db_out_mysql_server: String,
    db_out_mysql_port: u32,
    db_out_db_name: String,
    db_out_db_user: String,
    db_out_db_pwd: String,
    pipeline_num_bgpkit_workers: u32,
}

/// loads the yaml config file.
fn load_yaml_config(file_name: &str) -> Config {
    let f = std::fs::File::open(file_name)
        .expect(&format!("Could not open config file at {}", file_name));
    serde_yaml::from_reader(f).expect("Could not read values from config file at ./data/config.yml")
}

fn main() {
    let cli_params = get_cli_parameters();
    let config_file = parse_file_with_ext(&cli_params, "config", ".yml");
    let config = load_yaml_config(&config_file);

    println!("{:?}", config);
    let start_ts = parse_input_ts(&cli_params);
    let aspa_dir = parse_aspa_dir(&cli_params);
    let pdb_file = parse_file_with_ext(&cli_params, "pdb_dump", ".json");

    let conn_pool = db::get_db_connection_pool(&config);

    /*
    let aspa_files = aspa::get_asa_files("./data/asa_samples/").unwrap();
    let attestations: Vec<AsProviderAttestation> = aspa::read_aspa_records(&aspa_files).unwrap();
    let rib_urls = bgpkit_get_ribs_size_ordered(start_ts);
    for broker_item in rib_urls {
        bgpkit_get_routes(&broker_item, &attestations);
        break;
    }

    let file_path =
        "/Users/lprehn/CLionProjects/aspa-observatory/data/pdb/peeringdb_2_dump_2023_05_01.json";
    let pdb_json = peeringdb::load_pdb_json_from_file(file_path);

    let mut route_servers_v4: HashSet<u32> = HashSet::new();
    let mut route_servers_v6: HashSet<u32> = HashSet::new();
    peeringdb::extract_route_servers(pdb_json, &mut route_servers_v4, &mut route_servers_v6);
    println!(
        "Read {} IPv4 and {} IPv6 Route Server ASNs.",
        route_servers_v4.len(),
        route_servers_v6.len()
    )
    */
    //pipeline::run_pipeline(start_ts, &aspa_dir, &pdb_file, &config);
    // derive_attestation_statistics(&attestations);
}
