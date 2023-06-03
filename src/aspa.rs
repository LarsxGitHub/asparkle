use bgpkit_parser::models::AsPathSegment;
use bgpkit_parser::BgpElem;
use ipnet::IpNet;
use rpki::repository::aspa::{AsProviderAttestation, Aspa};
use rpki::repository::resources::AddressFamily;
use std::collections::{HashMap, HashSet};
use std::error::Error;
use std::fs;

use crate::utils;

#[derive(Debug, PartialEq)]
pub(crate) enum OpportunisticAspaValidationState {
    Valid,
    InvalidAsset,
    InvalidPeerasn,
    InvalidAspa,
    Unknown,
    NoOpportunity,
}

#[derive(Debug, PartialEq)]
pub(crate) enum UpInfSuccessReason {
    SuccessTierone,        // Successful inference based on a Tier 1 ASN.
    SuccessTieronePeer,    // Successful inference based on the next hop of a Tier 1 ASN.
    SuccessRcpTierone, // Successful inference based the Route collector peer being a Tier 1 ASN.
    SuccessAttestation, // Successful inference based on an ASPA attestation.
    SuccessRouteserver, // Successful inference based on a route server.
    SuccessRcpRouteserver, // Successful inference based on Route collector peer being a route server.
    SuccessOtc,            // Successful inference based on only-to-customer attribute.
}

#[derive(Debug, PartialEq)]
pub(crate) enum UpInfFailReason {
    FailureAsset,        // AS path contains AS_SET.
    FailureInsufficient, // successful AS match, yet match was at origin (has no sub path)
    FailureEmpty,        // AS path is empty or None
    FailureUncertain,    // Unable to make any opportunistic inference
    FailureNone,         // the is not Some(as_path) in the BgpElem.
}

#[derive(Debug, PartialEq)]
pub(crate) enum UpstreamExtractionResult {
    Success(Vec<u32>, UpInfSuccessReason),
    Failure(UpInfFailReason),
}

/// This object opportunistically infers the ASPA state of AS_PATHs.
/// In the real world, a validating router would know its business relationships and whether it is
/// part of the down or upstream of the route. As this validator looks at paths sampled from "random"
/// ASes (that peer with route collectors), it does not have the luxury of knowing its validation
/// environment and can not rely on knowing the business relationships for some links.
/// Hence, this validator needs to infer which part of the path belongs to the
/// upstream and which part belongs to the downstream. It does so opportunistically and performs
/// ASPA validation on the upstream part of the path.
pub(crate) struct OpportunisticAspaPathValidator {
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
    pub(crate) fn new() -> OpportunisticAspaPathValidator {
        // Set of Providers for Customer ASes.
        let mut upstreams_ipv4: HashMap<u32, HashSet<u32>> = HashMap::new();
        let mut upstreams_ipv6: HashMap<u32, HashSet<u32>> = HashMap::new();

        // Set of router server ASNs.
        let route_servers_ipv4: HashSet<u32> = HashSet::new();
        let route_servers_ipv6: HashSet<u32> = HashSet::new();

        // Lists of Tier 1 networks, taken from https://en.wikipedia.org/wiki/Tier_1_network
        let tier_ones_ipv4 = HashSet::from([
            174, 701, 1239, 1299, 2828, 2914, 3257, 3320, 3356, 3491, 5511, 6453, 6461, 6762, 6830,
            7018, 7922, 12956,
        ]);
        let tier_ones_ipv6 = HashSet::from([
            701, 1239, 1299, 2914, 3257, 3320, 3356, 3491, 5511, 6453, 6461, 6762, 6830, 7018,
            7922, 12956,
        ]);

        OpportunisticAspaPathValidator {
            upstreams_ipv4,
            upstreams_ipv6,
            tier_ones_ipv4,
            tier_ones_ipv6,
            route_servers_ipv4,
            route_servers_ipv6,
        }
    }

    /// Extends the Provider sets that are used for inference and validation.
    ///
    /// Deeply personal comment: While this function might be handy in awkward situations, you'd
    /// rather use the add_upstreams_from_attestations(...) function in most situations (as it
    /// allows you to skip juggling around the AsProviderAttestation yourself after reading them,
    /// e.g., from a file. This function primarily exists as, for the life of me, I couldn't figure
    /// out a way to craft AsProviderAttestation objects for testing. I know that the rpki library
    /// shows how to do it at https://docs.rs/rpki/latest/src/rpki/repository/aspa.rs.html#536, but
    /// the crate misses to make some of the important objects publically available, and, ohh boy,
    /// I am not willing to port over and maintain hundreds of lines of code just for testing...
    pub(crate) fn add_upstreams_directly(
        &mut self,
        upstreams_ipv4: &HashMap<u32, HashSet<u32>>,
        upstreams_ipv6: &HashMap<u32, HashSet<u32>>,
    ) {
        // update ipv4 upstream sets
        for (key, value_set) in upstreams_ipv4.iter() {
            for value in value_set.iter() {
                utils::add_to_hashmap_set(&mut self.upstreams_ipv4, key, value);
            }
        }

        // update ipv6 upstream sets
        for (key, value_set) in upstreams_ipv6.iter() {
            for value in value_set.iter() {
                utils::add_to_hashmap_set(&mut self.upstreams_ipv6, key, value);
            }
        }
    }

    /// Reads Set of Providers for Customer ASes from a vector of AsProviderAttestation.
    pub(crate) fn add_upstreams_from_attestations(
        &mut self,
        attestations: &Vec<AsProviderAttestation>,
    ) {
        // parse attestations
        for attest in attestations {
            let customer = attest.customer_as().into_u32();
            for provider_as_set in attest.provider_as_set().iter() {
                let provider: u32 = provider_as_set.provider().into_u32();

                // is there an afi_limit set on this relationship?
                if let Some(family) = provider_as_set.afi_limit() {
                    match family {
                        AddressFamily::Ipv4 => {
                            utils::add_to_hashmap_set(
                                &mut self.upstreams_ipv4,
                                &customer,
                                &provider,
                            );
                        }
                        AddressFamily::Ipv6 => {
                            utils::add_to_hashmap_set(
                                &mut self.upstreams_ipv6,
                                &customer,
                                &provider,
                            );
                        }
                    }
                } else {
                    // no afi_limit set, add to both.
                    utils::add_to_hashmap_set(&mut self.upstreams_ipv4, &customer, &provider);
                    utils::add_to_hashmap_set(&mut self.upstreams_ipv6, &customer, &provider);
                }
            }
        }
    }

    /// Adds sets of route server ASNs for the validation.
    pub(crate) fn add_route_servers(
        &mut self,
        route_servers_ipv4: &HashSet<u32>,
        route_servers_ipv6: &HashSet<u32>,
    ) {
        self.route_servers_ipv4.extend(route_servers_ipv4);
        self.route_servers_ipv6.extend(route_servers_ipv6);
    }

    /// infers maximum upstream sequence from origin.
    pub(crate) fn extract_max_upstream(&self, elem: &BgpElem) -> UpstreamExtractionResult {
        // if no path is included, we can't infer upstream.
        if elem.as_path.is_none() {
            return UpstreamExtractionResult::Failure(UpInfFailReason::FailureNone);
        }

        // setup resource pointers for correct afi.
        let mut upstreams = &self.upstreams_ipv4;
        let mut tier_ones = &self.tier_ones_ipv4;
        let mut route_servers = &self.route_servers_ipv4;
        if let IpNet::V6(_) = elem.prefix.prefix {
            upstreams = &self.upstreams_ipv6;
            tier_ones = &self.tier_ones_ipv6;
            route_servers = &self.route_servers_ipv6;
        }

        // Facilitate the path object. ASPA filtering does not allow for AS_SETs, so we can simply
        // generate a clean vector containing only the ASNs.
        let mut path_dense: Vec<u32> = Vec::new();
        for segment in &elem.as_path.as_ref().unwrap().segments {
            match segment {
                AsPathSegment::AsSequence(sequence) => {
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
                _ => return UpstreamExtractionResult::Failure(UpInfFailReason::FailureAsset),
            }
        }

        // is the path empty after converting it?
        if path_dense.is_empty() {
            return UpstreamExtractionResult::Failure(UpInfFailReason::FailureEmpty);
        }

        // Dense, non-empty AS path -> now we can check for opportunities to infer the upstream
        // 1. RC peer is Tier 1 network, return full path
        if tier_ones.contains(&elem.peer_asn.asn) {
            if path_dense.len() > 1 {
                return UpstreamExtractionResult::Success(
                    path_dense,
                    UpInfSuccessReason::SuccessRcpTierone,
                );
            } else {
                return UpstreamExtractionResult::Failure(UpInfFailReason::FailureInsufficient);
            }
        }

        // 2. RC peer is a Route Server (either in-list, or peer_asn is not first_hop)
        if (route_servers.contains(&elem.peer_asn.asn)) | (path_dense[0] != elem.peer_asn.asn) {
            if path_dense.len() > 1 {
                return UpstreamExtractionResult::Success(
                    path_dense,
                    UpInfSuccessReason::SuccessRcpRouteserver,
                );
            } else {
                return UpstreamExtractionResult::Failure(UpInfFailReason::FailureInsufficient);
            }
        }

        // 3. in Only-to-Customer we trust.
        if let Some(top_asn) = elem.only_to_customer {
            //  check whether the contained ASN is actually part of the path.
            if let Some(idx) = path_dense.iter().position(|&asn| asn == top_asn) {
                if path_dense.len() > 1 {
                    return UpstreamExtractionResult::Success(
                        Vec::from(path_dense.get(idx..).unwrap()),
                        UpInfSuccessReason::SuccessOtc,
                    );
                } else {
                    return UpstreamExtractionResult::Failure(UpInfFailReason::FailureInsufficient);
                }
            }
        }

        // On-path inference starts here, opportunities 4, 5, and 6.
        let mut last_valid_upstream_idx: Option<usize> = None;
        for (idx, asn) in path_dense.clone().into_iter().enumerate().rev() {
            // 4. we hit a Tier 1 ASN, can't go higher.
            if tier_ones.contains(&asn) {
                let mut start_idx = idx;
                // can't go up, but how about sideways?
                if idx > 0 {
                    let next_hop = path_dense.get(idx - 1).unwrap();
                    if tier_ones.contains(next_hop) | route_servers.contains(next_hop) {
                        start_idx = idx - 1;
                    }
                }
                // unwrap safe as it returns at least itself.
                let upstream = path_dense.get(start_idx..).unwrap();

                // path is too short for aspa validation ...
                if upstream.len() == 1 {
                    return UpstreamExtractionResult::Failure(UpInfFailReason::FailureInsufficient);
                }

                // make sure to report the correct reasoning.
                if idx == start_idx {
                    return UpstreamExtractionResult::Success(
                        Vec::from(upstream),
                        UpInfSuccessReason::SuccessTierone,
                    );
                } else {
                    return UpstreamExtractionResult::Success(
                        Vec::from(upstream),
                        UpInfSuccessReason::SuccessTieronePeer,
                    );
                }
            }

            // 5. we hit a non-transparent route server (which might be part of an aspa attestation.)
            if route_servers.contains(&asn) {
                // unwrap safe as it returns at least itself.
                let upstream = path_dense.get(idx..).unwrap();
                if upstream.len() == 1 {
                    return UpstreamExtractionResult::Failure(UpInfFailReason::FailureInsufficient);
                }
                return UpstreamExtractionResult::Success(
                    Vec::from(upstream),
                    UpInfSuccessReason::SuccessRouteserver,
                );
            }

            // make sure we are not at the left-most link and that this asn has an ASPA record.
            if (idx == 0) | !upstreams.contains_key(&asn) {
                continue;
            }

            // 6. check if next ASN is an aspa-valid upstream.
            // unwrap safe due to previous check + iteration order
            let asn_up = path_dense.get(idx - 1).unwrap();
            if upstreams.get(&asn).unwrap().contains(asn_up) {
                // next asn is a valid upstream. Remember for now as we may be able to get higher up.
                last_valid_upstream_idx = Some(idx - 1);
            }
        }

        // There was a valid upstream somewhere in the path.
        if let Some(idx) = last_valid_upstream_idx {
            // unwrap safe, contains at least two ASNs.
            let upstream = path_dense.get(idx..).unwrap();
            return UpstreamExtractionResult::Success(
                Vec::from(upstream),
                UpInfSuccessReason::SuccessAttestation,
            );
        }

        // No opportunity to infer upstream.
        UpstreamExtractionResult::Failure(UpInfFailReason::FailureUncertain)
    }

    pub(crate) fn validate(&self, elem: BgpElem) -> OpportunisticAspaValidationState {
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

#[cfg(test)]
mod tests {
    use crate::aspa::{
        OpportunisticAspaPathValidator, UpInfFailReason, UpInfSuccessReason,
        UpstreamExtractionResult,
    };
    use crate::utils;
    use bgpkit_parser::models::{AsPath, AsPathSegment, NetworkPrefix};
    use bgpkit_parser::BgpElem;
    use std::collections::{HashMap, HashSet};
    use std::str::FromStr;

    /// Sets up a simple OpportunisticAspaPathValidator object for testing.
    fn setup_validator() -> OpportunisticAspaPathValidator {
        // generating attestations, testing asn ranges (64496 - 64511) as defined in RFC 5398.
        let mut upstreams_v4: HashMap<u32, HashSet<u32>> = HashMap::new();
        utils::add_to_hashmap_set(&mut upstreams_v4, &64499, &64500);
        utils::add_to_hashmap_set(&mut upstreams_v4, &64500, &64509);
        utils::add_to_hashmap_set(&mut upstreams_v4, &64499, &64504);
        let mut upstreams_v6: HashMap<u32, HashSet<u32>> = HashMap::new();
        utils::add_to_hashmap_set(&mut upstreams_v6, &64499, &64500);
        utils::add_to_hashmap_set(&mut upstreams_v6, &64500, &64509);
        utils::add_to_hashmap_set(&mut upstreams_v6, &64499, &64506);

        // generating route servers
        let mut route_servers_v4: HashSet<u32> = HashSet::new();
        route_servers_v4.insert(64510);
        let mut route_servers_v6: HashSet<u32> = HashSet::new();
        route_servers_v6.insert(64511);

        // instantiate OpportunisticAspaPathValidator
        let mut aspa_val = OpportunisticAspaPathValidator::new();
        aspa_val.add_upstreams_directly(&upstreams_v4, &upstreams_v6);
        aspa_val.add_route_servers(&route_servers_v4, &route_servers_v6);
        aspa_val
    }

    /// Convenience function that derives a BgpElem object from the input parameters.
    fn elem_from_specification(
        segment_path: &[u32],
        peer_asn: u32,
        ipv4: bool,
        otc: Option<u32>,
    ) -> BgpElem {
        // convert as path to correct form.
        let path = segment_path.iter().map(|asn| (*asn).into()).collect();

        // Generate default BgpElem and overwrite the important fields.
        let mut elem: BgpElem = Default::default();
        elem.as_path = Some(AsPath {
            segments: vec![AsPathSegment::AsSequence(path)],
        });
        elem.prefix = match ipv4 {
            true => NetworkPrefix::from_str("0.0.0.0/0").unwrap(),
            false => NetworkPrefix::from_str("0::/0").unwrap(),
        };
        elem.only_to_customer = otc;
        elem.peer_asn = peer_asn.into();
        elem
    }

    fn assert_success(
        aspa_val: &OpportunisticAspaPathValidator,
        elem: &BgpElem,
        upstream_expected: Vec<u32>,
        reason_expected: UpInfSuccessReason,
    ) {
        match aspa_val.extract_max_upstream(&elem) {
            UpstreamExtractionResult::Success(upstream, reason) => {
                assert_eq!(
                    upstream_expected, upstream,
                    "Expected upstream {:?}, got upstream {:?}",
                    upstream_expected, upstream
                );
                assert_eq!(
                    reason_expected, reason,
                    "Expected Success reason {:?}, got success reason {:?} for upstream {:?}",
                    reason_expected, reason, upstream
                );
            }
            UpstreamExtractionResult::Failure(reason) => {
                panic!("Expected Success, got Failure with reason {:?}", reason)
            }
        }
    }

    fn assert_failure(
        aspa_val: &OpportunisticAspaPathValidator,
        elem: &BgpElem,
        reason_expected: UpInfFailReason,
    ) {
        match aspa_val.extract_max_upstream(&elem) {
            UpstreamExtractionResult::Success(upstream, reason) => panic!(
                "Expected no upstream, got upstream {:?} with reason {:?}",
                upstream, reason
            ),
            UpstreamExtractionResult::Failure(reason) => {
                assert_eq!(
                    reason_expected, reason,
                    "Expected failure reason {:?}, got failure reason {:?}",
                    reason_expected, reason
                )
            }
        }
    }

    #[test]
    fn test_extract_max_upstream_success_tierone() {
        // provide setup
        let aspa_val = setup_validator();

        // success test
        let elem = elem_from_specification(&[64503, 64502, 174, 64501, 64500], 64503, true, None);
        assert_success(
            &aspa_val,
            &elem,
            vec![174, 64501, 64500],
            UpInfSuccessReason::SuccessTierone,
        );

        // Failure test
        let elem = elem_from_specification(&[64503, 64502, 174], 64503, true, None);
        assert_failure(&aspa_val, &elem, UpInfFailReason::FailureInsufficient);
    }

    #[test]
    fn test_extract_max_upstream_success_routeserver() {
        // provide setup
        let aspa_val = setup_validator();

        // success test, non-transparent route server
        let elem = elem_from_specification(&[64503, 64510, 64502, 64501, 64500], 64503, true, None);
        assert_success(
            &aspa_val,
            &elem,
            vec![64510, 64502, 64501, 64500],
            UpInfSuccessReason::SuccessRouteserver,
        );

        // Failure test
        let elem = elem_from_specification(&[64502, 64510], 64502, true, None);
        assert_failure(&aspa_val, &elem, UpInfFailReason::FailureInsufficient);
    }

    #[test]
    fn test_extract_max_upstream_success_tieronepeer() {
        // provide setup
        let aspa_val = setup_validator();

        // success test route server v4
        let elem = elem_from_specification(&[64503, 64510, 701, 64501, 64500], 64503, true, None);
        assert_success(
            &aspa_val,
            &elem,
            vec![64510, 701, 64501, 64500],
            UpInfSuccessReason::SuccessTieronePeer,
        );

        // success test route server v6
        let elem = elem_from_specification(&[64503, 64511, 701, 64501, 64500], 64503, false, None);
        assert_success(
            &aspa_val,
            &elem,
            vec![64511, 701, 64501, 64500],
            UpInfSuccessReason::SuccessTieronePeer,
        );

        // success test second tier 1
        let elem = elem_from_specification(&[64503, 174, 701, 64501, 64500], 64503, true, None);
        assert_success(
            &aspa_val,
            &elem,
            vec![174, 701, 64501, 64500],
            UpInfSuccessReason::SuccessTieronePeer,
        );

        // success test second tier 1, yet only one of them is also a tier 1 in ipv6
        let elem = elem_from_specification(&[64503, 174, 701, 64501, 64500], 64503, false, None);
        assert_success(
            &aspa_val,
            &elem,
            vec![701, 64501, 64500],
            UpInfSuccessReason::SuccessTierone,
        );
    }

    #[test]
    fn test_extract_max_upstream_success_rcptierone() {
        // provide setup
        let aspa_val = setup_validator();

        // success test
        let elem = elem_from_specification(&[701, 64503, 64502, 64501, 64500], 701, true, None);
        assert_success(
            &aspa_val,
            &elem,
            vec![701, 64503, 64502, 64501, 64500],
            UpInfSuccessReason::SuccessRcpTierone,
        );

        // Failure test
        let elem = elem_from_specification(&[701], 701, true, None);
        assert_failure(&aspa_val, &elem, UpInfFailReason::FailureInsufficient);
    }

    #[test]
    fn test_extract_max_upstream_success_rcprouteserver() {
        // provide setup
        let aspa_val = setup_validator();

        // success test, non-transparent route server
        let elem = elem_from_specification(&[64510, 64503, 64502, 64501, 64500], 64510, true, None);
        assert_success(
            &aspa_val,
            &elem,
            vec![64510, 64503, 64502, 64501, 64500],
            UpInfSuccessReason::SuccessRcpRouteserver,
        );

        // success test, transparent route server
        let elem = elem_from_specification(&[64503, 64502, 64501, 64500], 64510, true, None);
        assert_success(
            &aspa_val,
            &elem,
            vec![64503, 64502, 64501, 64500],
            UpInfSuccessReason::SuccessRcpRouteserver,
        );

        // Failure test
        let elem = elem_from_specification(&[64510], 64510, true, None);
        assert_failure(&aspa_val, &elem, UpInfFailReason::FailureInsufficient);
    }

    #[test]
    fn test_extract_max_upstream_success_otc() {
        // provide setup
        let aspa_val = setup_validator();

        // success test
        let elem = elem_from_specification(&[64503, 64502, 64501, 64500], 64503, true, Some(64502));
        assert_success(
            &aspa_val,
            &elem,
            vec![64502, 64501, 64500],
            UpInfSuccessReason::SuccessOtc,
        );

        // Failure test as 64504 is not on-path.
        let elem = elem_from_specification(&[64503, 64502, 64501, 64500], 64503, true, Some(64504));
        assert_failure(&aspa_val, &elem, UpInfFailReason::FailureUncertain);

        // Failure test
        let elem = elem_from_specification(&[64504], 64504, true, Some(64504));
        assert_failure(&aspa_val, &elem, UpInfFailReason::FailureInsufficient);
    }

    #[test]
    fn test_extract_max_upstream_success_attestation() {
        // provide setup
        let aspa_val = setup_validator();

        // success test, some attestation
        let elem = elem_from_specification(&[64503, 64501, 64500, 64499], 64503, true, None);
        assert_success(
            &aspa_val,
            &elem,
            vec![64500, 64499],
            UpInfSuccessReason::SuccessAttestation,
        );

        // success test, multiple attestations
        let elem = elem_from_specification(&[64503, 64509, 64500, 64499], 64503, true, None);
        assert_success(
            &aspa_val,
            &elem,
            vec![64509, 64500, 64499],
            UpInfSuccessReason::SuccessAttestation,
        );

        // success test, attest in ipv6 but not ipv4
        let elem = elem_from_specification(&[64505, 64506, 64499], 64505, false, None);
        assert_success(
            &aspa_val,
            &elem,
            vec![64506, 64499],
            UpInfSuccessReason::SuccessAttestation,
        );

        // failure test, attest in ipv6 but not ipv4
        let elem = elem_from_specification(&[64505, 64506, 64499], 64505, true, None);
        assert_failure(&aspa_val, &elem, UpInfFailReason::FailureUncertain)
    }
}
