use bgpkit_parser::AsPath;
use bgpkit_parser::AsPathSegment::AsSequence;
use rpki::repository::aspa::{AsProviderAttestation, Aspa};
use rpki::repository::resources::AddressFamily;
use std::collections::{HashMap, HashSet};
use std::error::Error;
use std::fs;

use crate::utils;

enum OpportunisticAspaValidationState {
    Valid,
    InvalidAsset,
    InvalidPeerasn,
    InvalidAspa,
    Unknown,
    NoOpportunity,
}

enum UpstreamExtractionResult {
    SuccessTierone(Vec<u32>),     // Successful inference based on a Tier 1 ASN.
    SuccessAttestation(Vec<u32>), // Successful inference based on an ASPA attestation.
    SuccessRouteserver(Vec<u32>), // Successful inference based on a route server.
    FailureAsset,                 // AS path contains AS_SET.
    FailureInsufficient,          // successful AS match, yet match was at origin (has no sub path)
    FailureEmpty,                 // AS path is empty.
    FailureUncertain,             // Unable to make any opportunistic inference
}

/// This object opportunistically infers the ASPA state of AS_PATHs.
/// In the real world, a validating router would know its business relationships and whether it is
/// part of the down or upstream of the route. As this validator looks at paths sampled from "random"
/// ASes (that peer with route collectors), it does not have the luxury of knowing its validation
/// environment and can not rely on knowing the business relationships for some links.
/// Hence, this validator needs to infer which part of the path belongs to the
/// upstream and which part belongs to the downstream. It does so opportunistically and performs
/// ASPA validation on the upstream part of the path.
struct OpportunisticAspaPathValidator {
    // attestation lookups per afi
    upstreams_ipv4: HashMap<u32, HashSet<u32>>,
    upstreams_ipv6: HashMap<u32, HashSet<u32>>,
    // lists of provider-free ASNs per afi -> used for up/down stream inference.
    tier_ones_ipv4: HashSet<u32>,
    tier_ones_ipv6: HashSet<u32>,
    // lists of route server ASNs per afi -> used for up/down stream inference.
    route_servers_ipv4: HashSet<u32>,
    route_servers_ipv6: HashSet<u32>,
}

impl OpportunisticAspaPathValidator {
    pub(crate) fn new(
        attestations: Vec<AsProviderAttestation>,
    ) -> Result<OpportunisticAspaPathValidator, Box<dyn Error>> {
        let mut upstreams_ipv4: HashMap<u32, HashSet<u32>> = HashMap::new();
        let mut upstreams_ipv6: HashMap<u32, HashSet<u32>> = HashMap::new();

        // parse attestations
        for attest in attestations {
            let customer = attest.customer_as().into_u32();
            for provider_as_set in attest.provider_as_set().iter() {
                let provider: u32 = provider_as_set.provider().into_u32();

                // is there an afi_limit set on this relationship?
                if let Some(family) = provider_as_set.afi_limit() {
                    match family {
                        AddressFamily::Ipv4 => {
                            utils::add_to_hashmap_set(&mut upstreams_ipv4, &customer, &provider);
                        }
                        AddressFamily::Ipv6 => {
                            utils::add_to_hashmap_set(&mut upstreams_ipv6, &customer, &provider);
                        }
                    }
                } else {
                    // no afi_limit set, add to both.
                    utils::add_to_hashmap_set(&mut upstreams_ipv4, &customer, &provider);
                    utils::add_to_hashmap_set(&mut upstreams_ipv6, &customer, &provider);
                }
            }
        }

        // Lists of Tier 1 networks, taken from https://en.wikipedia.org/wiki/Tier_1_network
        let tier_ones_ipv4: HashSet<u32> = HashSet::from([
            174, 701, 1239, 1299, 2828, 2914, 3257, 3320, 3356, 3491, 5511, 6453, 6461, 6762, 6830,
            7018, 7922, 12956,
        ]);
        let tier_ones_ipv6: HashSet<u32> = HashSet::from([
            701, 1239, 1299, 2914, 3257, 3320, 3356, 3491, 5511, 6453, 6461, 6762, 6830, 7018,
            7922, 12956,
        ]);

        // Lists of Tier 1 networks, taken from https://en.wikipedia.org/wiki/Tier_1_network
        let route_servers_ipv4: HashSet<u32> = HashSet::new();
        let route_servers_ipv6: HashSet<u32> = HashSet::new();

        return Ok(OpportunisticAspaPathValidator {
            upstreams_ipv4,
            upstreams_ipv6,
            tier_ones_ipv4,
            tier_ones_ipv6,
            route_servers_ipv4,
            route_servers_ipv6,
        });
    }

    /// infers maximum upstream sequence from origin.
    pub(crate) fn extract_max_upstream(
        self,
        as_path: &AsPath,
        afi: AddressFamily,
    ) -> UpstreamExtractionResult {
        // setup resource pointers.
        match afi {
            AddressFamily::Ipv4 => {
                let upstreams = self.upstreams_ipv4;
                let tier_ones = self.tier_ones_ipv4;
                let route_servers = self.route_servers_ipv4;
            }
            AddressFamily::Ipv6 => {
                let upstreams = self.upstreams_ipv4;
                let tier_ones = self.tier_ones_ipv4;
                let route_servers = self.route_servers_ipv6;
            }
        }

        // Facilitate the path object. ASPA filtering does not allow for AS_SETs, so we can simply
        // generate a clean vector containing only the ASNs.
        let mut path_dense: Vec<u32> = Vec::new();
        for segment in &as_path.segments {
            match segment {
                AsSequence(sequence) => {
                    for asn_obj in sequence {
                        // is this path prepending? If so, skip adding the asn again.
                        if !path_dense.is_empty() {
                            // unwrap only safe if nested. No laze evaluation.
                            if asn_obj.asn.eq(path_dense.last().unwrap()) {
                                continue;
                            }
                        }
                        path_dense.push(asn_obj.asn as u32);
                    }
                }
                _ => return UpstreamExtractionResult::FailureAsset,
            }
        }

        // is the path empty after converting it?
        if path_dense.is_empty() {
            return UpstreamExtractionResult::FailureEmpty;
        }

        // inference starting from origin.
        let n = path_dense.len();
        for (idx, asn) in path_dense.into_iter().enumerate().rev() {
            // we hit a Tier 1 ASN, can't go higher (by definition).
            if tier_ones.contains(asn) {
                // unwrap safe as it returns at least itself.
                let upstream = path_dense.get(idx..).unwrap();
                if upstream.len().eq(1) {
                    return UpstreamExtractionResult::FailureEmpty; // upstream too short.
                }
                return UpstreamExtractionResult::SuccessTierone(Vec::from(upstream));
            }

            // we hit a non-transparent route server, this should be part of aspa attestation.
            if route_servers.contains(asn) {
                // unwrap safe as it returns at least itself.
                let upstream = path_dense.get(idx..).unwrap();
                if upstream.len().eq(1) {
                    return UpstreamExtractionResult::FailureEmpty; // upstream too short.
                }
                return UpstreamExtractionResult::SuccessTierone(Vec::from(upstream));
            }
            // ToDo: check attestations. you need to get the left-most one if there are multiuple.
            // needs variable outside of loop.
        }

        // No opportunity to infer upstream.
        UpstreamExtractionResult::FailureUncertain
    }

    pub(crate) fn validate(as_path: AsPath) -> OpportunisticAspaValidationState {
        // Todo: run opportunistic validation
        OpportunisticAspaValidationState::Unknown
    }
}

/// Returns a Vector containing the AsProviderAttestations within all provided files
pub(crate) fn read_aspa_records(
    files: &Vec<String>,
) -> Result<Vec<AsProviderAttestation>, Box<dyn Error>> {
    let mut attestations: Vec<AsProviderAttestation> = Vec::new();
    for filepath in files {
        let data = fs::read(filepath)?;
        let aspa = Aspa::decode(data.as_ref(), true)?;
        attestations.push(aspa.content().clone());
    }
    Ok(attestations)
}

/// returns a vector of .asa file paths for an input dir.
pub(crate) fn get_asa_files(dir: &str) -> Result<Vec<String>, Box<dyn Error>> {
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
