use chrono::{DateTime, FixedOffset, NaiveDate};
use clap::{Arg, ArgMatches};
use rpki::repository::aspa::{AsProviderAttestation, Aspa};
use rpki::repository::resources::AddressFamily;
use std::error::Error;
use std::fmt::Display;
use std::fs;
use std::path::PathBuf;
use std::process::exit;

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
            exit_msg!("Required parameter 'date' was not provided.");
        }
    };

    // check if date is malformatted.
    if let Err(e) = NaiveDate::parse_from_str(date_str, "%Y-%m-%d") {
        exit_msg!("Date is incorrectly formatted, see: {}", e);
    }

    // extend date to start-of-day DateTimeit push origin
    let date_str = String::from(date_str) + " 00:00:00.000 +0000";
    let date: DateTime<FixedOffset>;
    match DateTime::parse_from_str(&date_str, "%Y-%m-%d %H:%M:%S%.3f %z") {
        Ok(dt) => date = dt,
        Err(e) => {
            // this should never happen
            exit_msg!("NaiveDate to DateTime conversion failed, see: {}", e);
        }
    }

    date.timestamp()
}

/// Gets CLI parameters passed to the binary
fn get_cli_parameters() -> ArgMatches {
    clap::Command::new("asparkle")
        .about("Deployment and compliance statistic for ASPA records at your fingertips. ")
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
        .get_matches()
}

/// returns a vector of .asa file paths for an input dir.
fn get_asa_files(dir: &str) -> Result<Vec<String>, Box<dyn Error>> {
    // read the dir.
    let paths = fs::read_dir(dir).expect(&format!("Unable to read directory {}", dir));

    // parse and filter entries and append them to files vector.
    let mut files = Vec::new();
    for dir_entry in paths {
        // parse the path
        let path = dir_entry
            .expect(&format!("Unable to obtain path for file in {}.", dir))
            .path();
        let link = path.into_os_string().into_string().expect(&format!(
            "Unable to obtain os string for some file in {}.",
            dir
        ));
        // ensure it's an .asa file, then append to vector.
        if link.ends_with(".asa") {
            files.push(String::from(link));
        }
    }
    Ok(files)
}

/// Returns a Vector containing the AsProviderAttestations within all provided files
fn read_aspa_records(files: &Vec<String>) -> Result<Vec<AsProviderAttestation>, Box<dyn Error>> {
    let mut attestations: Vec<AsProviderAttestation> = Vec::new();
    for filepath in files {
        let data = fs::read(filepath)?;
        let aspa = Aspa::decode(data.as_ref(), true)?;
        attestations.push(aspa.content().clone());
    }
    Ok(attestations)
}

fn derive_attestation_statistics(attestations: &Vec<AsProviderAttestation>) {
    let num_attests_total = attestations.len();
    let mut num_attests_ipv4: usize = 0;
    let mut num_attests_ipv6: usize = 0;
    let mut num_attests_both: usize = 0;

    for attest in attestations {
        let customer = attest.customer_as().into_u32();
        let mut uses_afi_limit_ipv4 = false;
        let mut uses_afi_limit_ipv6 = false;
        for provider_as_set in attest.provider_as_set().iter() {
            let asn: u32 = provider_as_set.provider().into_u32();
            if let Some(family) = provider_as_set.afi_limit() {
                // afi limited records
                match family {
                    AddressFamily::Ipv4 => uses_afi_limit_ipv4 = true,
                    AddressFamily::Ipv6 => uses_afi_limit_ipv6 = true,
                }
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
}
fn main() {
    let cli_params = get_cli_parameters();
    let start_ts = parse_input_ts(&cli_params);

    let aspa_files = get_asa_files("./data/asa_samples/").unwrap();
    let attestations: Vec<AsProviderAttestation> = read_aspa_records(&aspa_files).unwrap();
    derive_attestation_statistics(&attestations);
    println!("{:?}", aspa_files);
    println!("{}", start_ts);
}
