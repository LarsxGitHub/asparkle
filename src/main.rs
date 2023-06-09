use bgpkit_broker::{BgpkitBroker, BrokerItem, QueryParams};
use bgpkit_parser::BgpkitParser;
use chrono::{DateTime, FixedOffset, NaiveDate, Timelike};
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

use crate::utils::intersect_hashmap_sets;
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
    match cli_args.get_one::<String>("datetime") {
        Some(d) => date_str = d,
        None => {
            exit_msg!("ERROR: Required parameter 'datetime' was not provided.");
        }
    };

    // check if date is malformatted.
    if let Err(e) = NaiveDate::parse_from_str(date_str, "%Y-%m-%d_%H") {
        exit_msg!(
            "ERROR: Date is incorrectly formatted, should be %Y-%m-%d_%H, is {}",
            date_str
        );
    }

    // extend date to start-of-day DateTimeit push origin
    let date_str = String::from(date_str) + ":00:00.000 +0000";
    let datetime: DateTime<FixedOffset>;
    match DateTime::parse_from_str(&date_str, "%Y-%m-%d_%H:%M:%S%.3f %z") {
        Ok(dt) => {
            if !(vec![0, 8, 16]).contains(&dt.hour()) {
                exit_msg!(
                    "The datetime string {} has an hour different from 0, 8, and 16.",
                    date_str
                );
            }

            datetime = dt
        }
        Err(e) => {
            // this should never happen
            exit_msg!("ERROR: NaiveDate to DateTime conversion failed, see: {}", e);
        }
    }

    datetime.timestamp()
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

fn parse_dir(cli_args: &ArgMatches, dir_key: &str, extension: Option<&str>) -> String {
    // get path from cli args
    let dir = cli_args
        .get_one::<String>(dir_key)
        .expect(&format!("Required parameter {} was not provided.", dir_key));

    // canonicalize the path
    let dir_canon = fs::canonicalize(dir).expect(&format!("Unable to canonicalize path {:?}", dir));

    // check whether path is a directory
    if !PathBuf::from(&dir_canon).is_dir() {
        exit_msg!(
            "ERROR: Required parameter '{}' was set to {}, which is not a directory.",
            dir_key,
            dir
        );
    }

    // do we expect files with extensions to be in the dir?
    if let Some(suffix) = extension {
        let mut has_some_file = false;
        for entry in fs::read_dir(&dir_canon).expect(&format!(
            "Unable to read contents of {} directory ({}).",
            dir_key, dir
        )) {
            let link = entry
                .expect(&format!(
                    "Unable to obtain path for some file in '{}' ({}).",
                    dir_key, dir
                ))
                .path()
                .into_os_string()
                .into_string()
                .expect(&format!(
                    "Unable to obtain os string for some file in '{}' ({}).",
                    dir_key, dir
                ));
            // ensure file has right extension
            if link.ends_with(suffix) {
                has_some_file = true;
                break;
            }
        }

        if !has_some_file {
            exit_msg!(
                "ERROR: Can't find any *{} files in {} ({}).",
                suffix,
                dir_key,
                dir
            );
        }
    }

    dir_canon.into_os_string().into_string().expect(&format!(
        "Unable to get os string from '{}' ({}).",
        dir_key, dir
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
            Arg::new("datetime")
                .short('d')
                .long("datetime")
                .required(true)
                .value_parser(clap::builder::NonEmptyStringValueParser::new())
                .help("The date and hour for which you want to calculate statistics (formatted as %Y-%m-%d_%H). As hours only 0, 8, and 16 are accepted options."),
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
            Arg::new("json_out_dir")
                .short('j')
                .long("json_out_dir")
                .required(true)
                .value_parser(clap::builder::NonEmptyStringValueParser::new())
                .help("the path to a directory in which you want to dump the resulting json file."),
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
    pipeline_num_bgpkit_workers: u32,
}

/// loads the yaml config file.
fn load_yaml_config(file_name: &str) -> Config {
    let f = std::fs::File::open(file_name)
        .expect(&format!("Could not open config file at {}", file_name));
    serde_yaml::from_reader(f).expect("Could not read values from config file at ./data/config.yml")
}

fn get_json_output_filename(cli_args: &ArgMatches) -> String {
    // get the output dir
    let json_out_dir = parse_dir(cli_args, "json_out_dir", None);

    // get the datetime => was already validated earlier.
    let datetime_str: &String;
    match cli_args.get_one::<String>("datetime") {
        Some(d) => datetime_str = d,
        None => {
            exit_msg!("ERROR: Required parameter 'date' was not provided.");
        }
    };

    format!("{}/aspa_observatory_{}.json", json_out_dir, datetime_str)
}

fn main() {
    let cli_params = get_cli_parameters();
    let config_file = parse_file_with_ext(&cli_params, "config", ".yml");
    let config = load_yaml_config(&config_file);

    println!("{:?}", config);
    let start_ts = parse_input_ts(&cli_params);
    let aspa_dir = parse_dir(&cli_params, "aspa_dir", Some(".asa"));
    let pdb_file = parse_file_with_ext(&cli_params, "pdb_dump", ".json");
    let json_out_fn = get_json_output_filename(&cli_params);

    pipeline::run_pipeline(start_ts, &aspa_dir, &pdb_file, &json_out_fn, &config);
}
