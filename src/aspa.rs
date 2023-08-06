use bgpkit_parser::models::AsPathSegment;
use bgpkit_parser::BgpElem;
use ipnet::IpNet;
use itertools::Itertools;
use rpki::repository::aspa::{AsProviderAttestation, Aspa};
use rpki::repository::resources::AddressFamily;
use std::collections::{HashMap, HashSet};
use std::error::Error;
use std::fs;

#[macro_use]
use serde::{Deserialize, Serialize};

use crate::utils;

/// Witness that can either confirm or offend an ASPA Attestation
#[derive(Debug, PartialEq)]
pub(crate) enum AspaAttestWitness {
    AspaAttestOffense(RampDirection, u32, u32),
    AspaAttestConfirmation(RampDirection, u32, u32),
}

/// Offense against an ASPA attestation
#[derive(Debug, PartialEq)]
pub(crate) struct AspaAttestOffense {
    pub dir: RampDirection,
    pub cas: u32,
    pub pas_off: u32,
}

/// Confirmation for an ASPA attestation
#[derive(Debug, PartialEq)]
pub(crate) struct AspaAttestConfirmation {
    pub dir: RampDirection,
    pub cas: u32,
    pub pas: u32,
}

/// whether the Witness was derived from the up or downstream.
#[derive(Debug, PartialEq, Deserialize, Serialize, Clone)]
pub(crate) enum RampDirection {
    Up,
    Down,
}

/// Per-Route ASPA validation witnesses.
#[derive(Debug, PartialEq)]
pub(crate) struct AspaValidatedRoute {
    pub pfx: ipnet::IpNet,
    pub path: Vec<u32>,

    pub apex: Vec<u32>,
    pub apex_reason: UpInfSuccessReason,
    pub witnesses: Vec<AspaAttestWitness>,
}

#[derive(Debug, PartialEq)]
pub(crate) enum HopCheckOutcome {
    NoAttestation,
    ProviderPlus,
    NotProviderPlus,
}

#[derive(Debug, PartialEq)]
pub(crate) enum OpportunisticAspaValidationState {
    Valid(AspaValidatedRoute),
    InvalidAsset,
    // InvalidPeerasn, would delete all RC peers that are RSes.
    InvalidAspa(AspaValidatedRoute),
    Unknown,
    NoOpportunity,
    Insufficient,
}

#[derive(Debug, PartialEq, Deserialize, Serialize, Clone, Copy)]
pub(crate) enum UpInfSuccessReason {
    SuccessTierone,        // Successful inference based on a Tier 1 ASN.
    SuccessTieronePeer,    // Successful inference based on the next hop of a Tier 1 ASN.
    SuccessRcpTierone, // Successful inference based the Route collector peer being a Tier 1 ASN.
    SuccessAttestation, // Successful inference based on an ASPA attestation.
    SuccessRouteserver, // Successful inference based on a route server.
    SuccessRcpRouteserver, // Successful inference based on Route collector peer being a route server.
    SuccessOtc,            // Successful inference based on only-to-customer attribute.
    SuccessOtcAttestMix, // Successful inference based on only-to-customer attribute & attestations
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
    Success(Vec<u32>, Vec<u32>, Vec<u32>, UpInfSuccessReason),
    Failure(UpInfFailReason),
}

/// Please note, ASPA became AFI-agnostic in latest draft.
pub(crate) fn lookup_from_attests(
    attestations: &Vec<(AsProviderAttestation, String)>,
) -> HashMap<u32, HashMap<u32, HashSet<&String>>> {
    let mut lookup: HashMap<u32, HashMap<u32, HashSet<&String>>> = HashMap::new();

    // parse attestations
    for (attest, file) in attestations.into_iter() {
        let customer = attest.customer_as().into_u32();
        for provider_as_set in attest.provider_as_set().iter() {
            let provider: u32 = provider_as_set.provider().into_u32();
            utils::add_to_double_nested_hashset(&mut lookup, &customer, &provider, &file);
        }
    }

    lookup
}

/// This object opportunistically infers the ASPA state of AS_PATHs.
/// In the real world, a validating router would know its business relationships and whether it is
/// part of the down or upstream of the route. As this validator looks at paths sampled from "random"
/// ASes (that peer with route collectors), it does not have the luxury of knowing its validation
/// environment and can not rely on knowing the business relationships for some links.
/// Hence, this validator needs to infer which part of the path belongs to the
/// upstream and which part belongs to the downstream. It does so opportunistically and performs
/// ASPA validation on the upstream part of the path.
#[derive(Debug, Clone)]
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
        attestations: &Vec<(AsProviderAttestation, String)>,
    ) {
        // parse attestations
        for (attest, _) in attestations {
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

    fn rule_match_vp_tier_one(
        &self,
        elem: &BgpElem,
        path_dense: &Vec<u32>,
        tier_ones: &HashSet<u32>,
    ) -> Option<UpstreamExtractionResult> {
        // 1. RC peer is Tier 1 network, return full path
        if tier_ones.contains(&elem.peer_asn.asn) {
            if path_dense.len() > 1 {
                return Some(UpstreamExtractionResult::Success(
                    Vec::from(path_dense.get(..1).unwrap()),
                    Vec::from(path_dense.get(..1).unwrap()),
                    path_dense.clone(),
                    UpInfSuccessReason::SuccessRcpTierone,
                ));
            } else {
                return Some(UpstreamExtractionResult::Failure(
                    UpInfFailReason::FailureInsufficient,
                ));
            }
        }
        None
    }

    fn rule_match_vp_rs(
        &self,
        elem: &BgpElem,
        path_dense: &Vec<u32>,
        route_servers: &HashSet<u32>,
    ) -> Option<UpstreamExtractionResult> {
        // 2. RC peer is a Route Server (either in-list, or peer_asn is not first_hop)
        // Even though these two cases look different on paper, they are actually the same.
        // if the RS is transparent, it is not part of the path. If it is non-transparent,
        // it is part of the path. In both cases, the first ASN on the path is the apex.
        if (route_servers.contains(&elem.peer_asn.asn)) | (path_dense[0] != elem.peer_asn.asn) {
            if path_dense.len() > 1 {
                return Some(UpstreamExtractionResult::Success(
                    Vec::from(path_dense.get(..1).unwrap()),
                    Vec::from(path_dense.get(..1).unwrap()),
                    path_dense.clone(),
                    UpInfSuccessReason::SuccessRcpRouteserver,
                ));
            } else {
                return Some(UpstreamExtractionResult::Failure(
                    UpInfFailReason::FailureInsufficient,
                ));
            }
        }
        None
    }

    fn rule_match_onpath_tier_one(
        &self,
        path_dense: &Vec<u32>,
        tier_ones: &HashSet<u32>,
        route_servers: &HashSet<u32>,
    ) -> Option<UpstreamExtractionResult> {
        for (start, asn) in path_dense.iter().enumerate() {
            // no tier-1, continue.
            if !tier_ones.contains(asn) {
                continue;
            }

            // this is a tier-1, forward search to unravel complete apex
            let mut end = start;
            for curr in start + 1..path_dense.len() {
                // apex still continues
                if tier_ones.contains(&path_dense[curr]) | route_servers.contains(&path_dense[curr])
                {
                    continue;
                }
                // end of apex
                end = curr;
                break;
            }

            // also backwards looking for route server...
            let mut real_start = start;
            for curr in (0..start).rev() {
                // apex already started earlier.
                if tier_ones.contains(&path_dense[curr]) | route_servers.contains(&path_dense[curr])
                {
                    continue;
                }
                // curr is now the first non-rs/tier1 asn
                real_start = curr + 1;
                break;
            }

            if path_dense.len() > 1 {
                return Some(UpstreamExtractionResult::Success(
                    Vec::from(path_dense.get(..real_start + 1).unwrap()),
                    Vec::from(path_dense.get(real_start..end).unwrap()),
                    Vec::from(path_dense.get(end - 1..).unwrap()),
                    UpInfSuccessReason::SuccessTierone,
                ));
            } else {
                return Some(UpstreamExtractionResult::Failure(
                    UpInfFailReason::FailureInsufficient,
                ));
            }
        }
        None
    }

    fn rule_match_onpath_route_server(
        &self,
        path_dense: &Vec<u32>,
        route_servers: &HashSet<u32>,
    ) -> Option<UpstreamExtractionResult> {
        for (idx, asn) in path_dense.iter().enumerate() {
            // no non-transparent routeserver, continue.
            if !route_servers.contains(asn) {
                continue;
            }

            return Some(UpstreamExtractionResult::Success(
                Vec::from(path_dense.get(..idx + 1).unwrap()),
                vec![*path_dense.get(idx).unwrap()],
                Vec::from(path_dense.get(idx..).unwrap()),
                UpInfSuccessReason::SuccessRouteserver,
            ));
        }
        None
    }

    fn rule_match_mixed_hopcheck_otc(
        &self,
        elem: &BgpElem,
        path_dense: &Vec<u32>,
        upstreams: &HashMap<u32, HashSet<u32>>,
    ) -> Option<UpstreamExtractionResult> {
        // check the downstream via OTC attribute
        let mut downstream_top_otc: Option<usize> = None;
        if let Some(top_asn) = elem.only_to_customer {
            //  check whether the contained ASN is actually part of the path.
            if let Some(idx) = path_dense.iter().position(|&asn| asn == top_asn) {
                downstream_top_otc = Some(idx);
            }
        }

        // check the downstream via attestations
        let mut downstream_top_aspa: Option<usize> = None;
        for (idx, asn) in path_dense.iter().enumerate().rev() {
            if idx == 0 {
                continue; // need 2 consecutive ASNs for hop-check
            }
            // perform reverse hop-check.
            if upstreams.contains_key(&path_dense[idx - 1]) {
                if upstreams.get(&path_dense[idx - 1]).unwrap().contains(asn) {
                    // right-most reverse Hop-Check with outcome "Provider+"
                    downstream_top_aspa = Some(idx);
                    break;
                }
            }
        }

        // check the upstream via attestations
        let mut upstream_top_aspa: Option<usize> = None;
        for (idx, asn) in path_dense.iter().enumerate() {
            if idx == 0 {
                continue; // need 2 consecutive ASNs for hop-check
            }
            // perform hop-check.
            if upstreams.contains_key(&asn) {
                if upstreams.get(&asn).unwrap().contains(&path_dense[idx - 1]) {
                    // left-most Hop-Check with outcome "Provider+"
                    upstream_top_aspa = Some(idx - 1);
                    break;
                }
            }
        }

        // no inferences possible.
        if downstream_top_otc.is_none()
            & upstream_top_aspa.is_none()
            & downstream_top_aspa.is_none()
        {
            return None;
        }

        // extract highest found downstream/upstream top.
        let mut max_downstream_idx: usize = 0;
        if let Some(idx) = downstream_top_aspa {
            max_downstream_idx = idx;
        }
        let mut otc_used = false;
        if let Some(idx) = downstream_top_otc {
            if idx > max_downstream_idx {
                otc_used = true;
                max_downstream_idx = idx;
            }
        }
        let mut max_upstream_idx: usize = path_dense.len();
        if let Some(idx) = upstream_top_aspa {
            max_upstream_idx = idx;
        }

        // extract up/downstreams
        let mut downstream: Vec<u32> = if (max_downstream_idx == 0) & (max_upstream_idx != 0) {
            vec![]
        } else {
            // remember: if whole path is upstream, the apex is the first hop and should be part of
            // downstream as well
            Vec::from(path_dense.get(..max_downstream_idx + 1).unwrap())
        };

        let mut upstream: Vec<u32> = match upstream_top_aspa {
            Some(idx) => Vec::from(path_dense.get(idx..).unwrap()),
            None => vec![],
        };

        println!(
            "{:?}, {:?}, {:?}, {:?}, {:?}, {:?}",
            max_upstream_idx,
            upstream_top_aspa,
            upstream,
            max_downstream_idx,
            downstream_top_aspa,
            downstream
        );
        // check if apex is available
        let mut apex: Vec<u32> = vec![];
        println!("apex: {:?}", apex);
        if max_upstream_idx == max_downstream_idx {
            println!("case 1");
            // overlap in one ASN
            apex.push(*path_dense.get(max_upstream_idx).unwrap());
        } else if max_downstream_idx == path_dense.len() - 1 {
            println!("case 2");

            // the whole path is an downstream
            let asn = *path_dense.get(path_dense.len() - 1).unwrap();
            apex.push(asn);
            upstream.push(asn);
        } else if max_upstream_idx == 0 {
            // the whole path is a downstream
            println!("case 3");
            // the whole path is an upstream
            let asn = *path_dense.get(0).unwrap();
            apex.push(asn);
            downstream.push(asn);
        }
        println!("apex: {:?}", apex);
        let mut reason;
        if otc_used {
            if (downstream_top_aspa.is_none() & upstream_top_aspa.is_none()) {
                reason = UpInfSuccessReason::SuccessOtc;
            } else {
                reason = UpInfSuccessReason::SuccessOtcAttestMix;
            }
        } else {
            reason = UpInfSuccessReason::SuccessAttestation;
        }

        Some(UpstreamExtractionResult::Success(
            downstream, apex, upstream, reason,
        ))
    }

    /// infers maximum upstream sequence from origin.
    pub(crate) fn extract_up_and_down_stream(&self, elem: &BgpElem) -> UpstreamExtractionResult {
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

        // Opportunity 1: Tier-1 vantage point
        if let Some(result) = self.rule_match_vp_tier_one(&elem, &path_dense, tier_ones) {
            return result;
        }

        // Opportunity 2: RS vantage point
        if let Some(result) = self.rule_match_vp_rs(&elem, &path_dense, route_servers) {
            return result;
        }

        // Opportunity 3: intermediate Tier-1 apex
        if let Some(result) = self.rule_match_onpath_tier_one(&path_dense, tier_ones, route_servers)
        {
            return result;
        }

        // Opportunity 4: intermediate non-transparent Route Server apex
        if let Some(result) = self.rule_match_onpath_route_server(&path_dense, route_servers) {
            return result;
        }

        // Opportunity 5: OTC & validated Attests
        if let Some(result) = self.rule_match_mixed_hopcheck_otc(&elem, &path_dense, upstreams) {
            return result;
        }

        // No opportunity to infer upstream.
        UpstreamExtractionResult::Failure(UpInfFailReason::FailureUncertain)
    }

    /// performs the hop(AS(i), AS(j), AFI) function from figure 1 in
    /// https://datatracker.ietf.org/doc/html/draft-ietf-sidrops-aspa-verification-14
    fn hop_check(&self, cas: &u32, pas: &u32, is_ipv6: bool) -> HopCheckOutcome {
        let upstreams = match is_ipv6 {
            true => &self.upstreams_ipv6,
            false => &self.upstreams_ipv4,
        };

        // has no attestation
        if !upstreams.contains_key(cas) {
            return HopCheckOutcome::NoAttestation;
        }

        // has a matching attestation
        if upstreams.get(cas).unwrap().contains(pas) {
            return HopCheckOutcome::ProviderPlus;
        }

        // CAS has attestations, yet none of them matches.
        HopCheckOutcome::NotProviderPlus
    }

    pub(crate) fn validate_opportunistically(
        &self,
        elem: &BgpElem,
    ) -> OpportunisticAspaValidationState {
        let mut downstream: Vec<u32> = Vec::new();
        let mut apex: Vec<u32> = Vec::new();
        let mut upstream: Vec<u32> = Vec::new();
        let mut reason: UpInfSuccessReason;

        // extract down and upstreams (either might be empty).
        match self.extract_up_and_down_stream(&elem) {
            UpstreamExtractionResult::Success(
                downstream_inf,
                apex_inf,
                upstream_inf,
                reason_inf,
            ) => {
                downstream = downstream_inf;
                apex = apex_inf;
                upstream = upstream_inf;
                reason = reason_inf;
            }
            UpstreamExtractionResult::Failure(reason) => match reason {
                UpInfFailReason::FailureAsset => {
                    return OpportunisticAspaValidationState::InvalidAsset
                }
                UpInfFailReason::FailureUncertain => {
                    return OpportunisticAspaValidationState::NoOpportunity
                }
                // please note that the Insufficient outcome actually might represent a "valid"
                // outcome according to Algorithm for Upstream Paths (Rule 3). However, for the
                // dashboard do not really care about finding valid paths, but rather offending AS
                // hops, so we can ignore this inaccuracy.
                _ => return OpportunisticAspaValidationState::Insufficient,
            },
        }

        let is_ipv6 = matches!(elem.prefix.prefix, IpNet::V6(_));
        let mut witnesses: Vec<AspaAttestWitness> = Vec::new();
        let mut has_offense = false;

        // validate downstream
        for (cas, pas) in downstream.iter().tuple_windows() {
            match self.hop_check(cas, pas, is_ipv6) {
                HopCheckOutcome::NoAttestation => continue,
                HopCheckOutcome::ProviderPlus => {
                    witnesses.push(AspaAttestWitness::AspaAttestConfirmation(
                        RampDirection::Down,
                        *cas,
                        *pas,
                    ));
                }
                HopCheckOutcome::NotProviderPlus => {
                    has_offense = true;
                    witnesses.push(AspaAttestWitness::AspaAttestOffense(
                        RampDirection::Down,
                        *cas,
                        *pas,
                    ));
                }
            }
        }

        // validate upstream
        for (pas, cas) in upstream.iter().tuple_windows() {
            match self.hop_check(cas, pas, is_ipv6) {
                HopCheckOutcome::NoAttestation => continue,
                HopCheckOutcome::ProviderPlus => {
                    witnesses.push(AspaAttestWitness::AspaAttestConfirmation(
                        RampDirection::Up,
                        *cas,
                        *pas,
                    ));
                }
                HopCheckOutcome::NotProviderPlus => {
                    has_offense = true;
                    witnesses.push(AspaAttestWitness::AspaAttestOffense(
                        RampDirection::Up,
                        *cas,
                        *pas,
                    ));
                }
            }
        }

        // collected pieces together.
        let val_route = AspaValidatedRoute {
            pfx: elem.prefix.prefix,
            apex,
            apex_reason: reason,
            path: elem.as_path.as_ref().unwrap().to_u32_vec().unwrap(),
            witnesses,
        };

        // does this route have a tuple that offends an aspa attest?
        if has_offense {
            return OpportunisticAspaValidationState::InvalidAspa(val_route);
        }

        // if no offenses, are there any confirmed attests?
        if !val_route.witnesses.is_empty() {
            return OpportunisticAspaValidationState::Valid(val_route);
        }

        // if not, we can not really say anything.
        OpportunisticAspaValidationState::Unknown
    }
}

/// Returns a Vector containing the AsProviderAttestations within all provided files
pub(crate) fn read_aspa_records(
    files: &Vec<String>,
) -> Result<Vec<(AsProviderAttestation, String)>, Box<dyn Error>> {
    let mut attestations: Vec<(AsProviderAttestation, String)> = Vec::new();
    for filepath in files {
        let data = fs::read(filepath)?;
        let aspa = Aspa::decode(data.as_ref(), true)?;
        attestations.push((
            aspa.content().clone(),
            aspa.cert().signed_object().unwrap().to_string(),
        ));
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
        AspaAttestWitness, AspaValidatedRoute, OpportunisticAspaPathValidator,
        OpportunisticAspaValidationState, RampDirection, UpInfFailReason, UpInfSuccessReason,
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
        utils::add_to_hashmap_set(&mut upstreams_v4, &64509, &64500);
        utils::add_to_hashmap_set(&mut upstreams_v4, &64498, &64504);
        let mut upstreams_v6: HashMap<u32, HashSet<u32>> = HashMap::new();
        utils::add_to_hashmap_set(&mut upstreams_v6, &64499, &64500);
        utils::add_to_hashmap_set(&mut upstreams_v6, &64509, &64500);
        utils::add_to_hashmap_set(&mut upstreams_v6, &64498, &64506);

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
        downstream_expected: Vec<u32>,
        apex_expected: Vec<u32>,
        upstream_expected: Vec<u32>,
        reason_expected: UpInfSuccessReason,
    ) {
        match aspa_val.extract_up_and_down_stream(&elem) {
            UpstreamExtractionResult::Success(downstream, apex, upstream, reason) => {
                assert_eq!(
                    reason_expected, reason,
                    "Expected Success reason {:?}, got success reason {:?} for upstream {:?}",
                    reason_expected, reason, upstream
                );
                assert_eq!(
                    downstream_expected, downstream,
                    "Expected downstream {:?}, got downstream {:?}",
                    downstream_expected, downstream
                );
                assert_eq!(
                    apex_expected, apex,
                    "Expected apex {:?}, got apex {:?}",
                    apex_expected, apex
                );
                assert_eq!(
                    upstream_expected, upstream,
                    "Expected upstream {:?}, got upstream {:?}",
                    upstream_expected, upstream
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
        match aspa_val.extract_up_and_down_stream(&elem) {
            UpstreamExtractionResult::Success(downstream, apex, upstream, reason) => panic!(
                "Expected no upstream, got downstream {:?}, apex {:?}, and upstream {:?} with reason {:?}",
                downstream, apex, upstream, reason
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
    fn test_extraction_rule1() {
        // provide setup
        let aspa_val = setup_validator();

        // success test
        let elem = elem_from_specification(&[174, 64501, 64500], 174, true, None);
        assert_success(
            &aspa_val,
            &elem,
            vec![174],
            vec![174],
            vec![174, 64501, 64500],
            UpInfSuccessReason::SuccessRcpTierone,
        );
    }

    #[test]
    fn test_extraction_rule2_nontransparent() {
        // provide setup
        let aspa_val = setup_validator();

        // success test
        let elem = elem_from_specification(&[64510, 64501, 64500], 64510, true, None);
        assert_success(
            &aspa_val,
            &elem,
            vec![64510],
            vec![64510],
            vec![64510, 64501, 64500],
            UpInfSuccessReason::SuccessRcpRouteserver,
        );
    }

    #[test]
    fn test_extraction_rule2_transparent_inrs() {
        // provide setup
        let aspa_val = setup_validator();

        // success test
        let elem = elem_from_specification(&[64502, 64501, 64500], 64510, true, None);
        assert_success(
            &aspa_val,
            &elem,
            vec![64502],
            vec![64502],
            vec![64502, 64501, 64500],
            UpInfSuccessReason::SuccessRcpRouteserver,
        );
    }

    #[test]
    fn test_extraction_rule2_transparent_notinrs() {
        // provide setup
        let aspa_val = setup_validator();

        // success test
        let elem = elem_from_specification(&[64502, 64501, 64500], 64503, true, None);
        assert_success(
            &aspa_val,
            &elem,
            vec![64502],
            vec![64502],
            vec![64502, 64501, 64500],
            UpInfSuccessReason::SuccessRcpRouteserver,
        );
    }

    #[test]
    fn test_extraction_rule3_single() {
        // provide setup
        let aspa_val = setup_validator();

        // success test
        let elem = elem_from_specification(&[64503, 64502, 174, 64501, 64500], 64503, true, None);
        assert_success(
            &aspa_val,
            &elem,
            vec![64503, 64502, 174],
            vec![174],
            vec![174, 64501, 64500],
            UpInfSuccessReason::SuccessTierone,
        );
    }

    #[test]
    fn test_extraction_rule3_double_wors() {
        // provide setup
        let aspa_val = setup_validator();

        // success test
        let elem =
            elem_from_specification(&[64503, 64502, 174, 701, 64501, 64500], 64503, true, None);
        assert_success(
            &aspa_val,
            &elem,
            vec![64503, 64502, 174],
            vec![174, 701],
            vec![701, 64501, 64500],
            UpInfSuccessReason::SuccessTierone,
        );
    }

    #[test]
    fn test_extraction_rule3_double_wrs_left() {
        // provide setup
        let aspa_val = setup_validator();

        // success test
        let elem =
            elem_from_specification(&[64503, 64502, 64510, 701, 64501, 64500], 64503, true, None);
        assert_success(
            &aspa_val,
            &elem,
            vec![64503, 64502, 64510],
            vec![64510, 701],
            vec![701, 64501, 64500],
            UpInfSuccessReason::SuccessTierone,
        );
    }

    #[test]
    fn test_extraction_rule3_double_wrs_right() {
        // provide setup
        let aspa_val = setup_validator();

        // success test
        let elem =
            elem_from_specification(&[64503, 64502, 701, 64510, 64501, 64500], 64503, true, None);
        assert_success(
            &aspa_val,
            &elem,
            vec![64503, 64502, 701],
            vec![701, 64510],
            vec![64510, 64501, 64500],
            UpInfSuccessReason::SuccessTierone,
        );
    }

    #[test]
    fn test_extraction_rule3_triple_wors() {
        // provide setup
        let aspa_val = setup_validator();

        // success test
        let elem = elem_from_specification(
            &[64503, 64502, 174, 7018, 701, 64501, 64500],
            64503,
            true,
            None,
        );
        assert_success(
            &aspa_val,
            &elem,
            vec![64503, 64502, 174],
            vec![174, 7018, 701],
            vec![701, 64501, 64500],
            UpInfSuccessReason::SuccessTierone,
        );
    }

    #[test]
    fn test_extraction_rule3_triple_wrs() {
        // provide setup
        let aspa_val = setup_validator();

        // success test
        let elem = elem_from_specification(
            &[64503, 64502, 174, 64510, 701, 64501, 64500],
            64503,
            true,
            None,
        );
        assert_success(
            &aspa_val,
            &elem,
            vec![64503, 64502, 174],
            vec![174, 64510, 701],
            vec![701, 64501, 64500],
            UpInfSuccessReason::SuccessTierone,
        );
    }

    #[test]
    fn test_extraction_rule4() {
        // provide setup
        let aspa_val = setup_validator();

        // success test
        let elem = elem_from_specification(&[64503, 64502, 64510, 64501, 64500], 64503, true, None);
        assert_success(
            &aspa_val,
            &elem,
            vec![64503, 64502, 64510],
            vec![64510],
            vec![64510, 64501, 64500],
            UpInfSuccessReason::SuccessRouteserver,
        );
    }

    #[test]
    fn test_extraction_rule5_otc_only_woapex() {
        // provide setup
        let aspa_val = setup_validator();

        // success test
        let elem = elem_from_specification(&[64502, 64501, 64500], 64502, true, Some(64501));
        assert_success(
            &aspa_val,
            &elem,
            vec![64502, 64501],
            vec![],
            vec![],
            UpInfSuccessReason::SuccessOtc,
        );
    }

    #[test]
    fn test_extraction_rule5_otc_only_wapex() {
        // provide setup
        let aspa_val = setup_validator();

        // success test
        let elem = elem_from_specification(&[64502, 64501, 64500], 64502, true, Some(64500));
        assert_success(
            &aspa_val,
            &elem,
            vec![64502, 64501, 64500],
            vec![64500],
            vec![64500],
            UpInfSuccessReason::SuccessOtc,
        );
    }

    #[test]
    fn test_extraction_rule5_upstream_only_woapex() {
        // provide setup
        let aspa_val = setup_validator();

        // success test
        let elem = elem_from_specification(&[64502, 64500, 64499], 64502, true, None);
        assert_success(
            &aspa_val,
            &elem,
            vec![],
            vec![],
            vec![64500, 64499],
            UpInfSuccessReason::SuccessAttestation,
        );
    }

    #[test]
    fn test_extraction_rule5_upstream_only_wapex() {
        // provide setup
        let aspa_val = setup_validator();

        // success test
        let elem = elem_from_specification(&[64500, 64499, 64502], 64500, true, None);
        assert_success(
            &aspa_val,
            &elem,
            vec![64500],
            vec![64500],
            vec![64500, 64499, 64502],
            UpInfSuccessReason::SuccessAttestation,
        );
    }

    #[test]
    fn test_extraction_rule5_downstream_only_woapex() {
        // provide setup
        let aspa_val = setup_validator();

        // success test
        let elem = elem_from_specification(&[64499, 64500, 64502], 64499, true, None);
        assert_success(
            &aspa_val,
            &elem,
            vec![64499, 64500],
            vec![],
            vec![],
            UpInfSuccessReason::SuccessAttestation,
        );
    }

    #[test]
    fn test_extraction_rule5_downstream_only_wapex() {
        // provide setup
        let aspa_val = setup_validator();

        // success test
        let elem = elem_from_specification(&[64502, 64499, 64500], 64502, true, None);
        assert_success(
            &aspa_val,
            &elem,
            vec![64502, 64499, 64500],
            vec![64500],
            vec![64500],
            UpInfSuccessReason::SuccessAttestation,
        );
    }

    #[test]
    fn test_extraction_rule5_bothstream_wapex() {
        // provide setup
        let aspa_val = setup_validator();

        // success test
        let elem = elem_from_specification(&[64499, 64500, 64509], 64499, true, None);
        assert_success(
            &aspa_val,
            &elem,
            vec![64499, 64500],
            vec![64500],
            vec![64500, 64509],
            UpInfSuccessReason::SuccessAttestation,
        );
    }

    #[test]
    fn test_extraction_rule5_bothstream_woapex() {
        // provide setup
        let aspa_val = setup_validator();

        // success test
        let elem = elem_from_specification(&[64499, 64500, 64504, 64498], 64499, true, None);
        assert_success(
            &aspa_val,
            &elem,
            vec![64499, 64500],
            vec![],
            vec![64504, 64498],
            UpInfSuccessReason::SuccessAttestation,
        );
    }

    #[test]
    fn test_extraction_rule5_bothplusotc_woapex() {
        // provide setup
        let aspa_val = setup_validator();

        // success test
        let elem = elem_from_specification(&[64499, 64500, 64504, 64498], 64499, true, Some(64500));
        assert_success(
            &aspa_val,
            &elem,
            vec![64499, 64500],
            vec![],
            vec![64504, 64498],
            UpInfSuccessReason::SuccessAttestation,
        );
    }

    #[test]
    fn test_extraction_rule5_bothplusotc_wapex() {
        // provide setup
        let aspa_val = setup_validator();

        // success test
        let elem = elem_from_specification(&[64499, 64500, 64504, 64498], 64499, true, Some(64504));
        assert_success(
            &aspa_val,
            &elem,
            vec![64499, 64500, 64504],
            vec![64504],
            vec![64504, 64498],
            UpInfSuccessReason::SuccessOtcAttestMix,
        );
    }

    #[test]
    fn test_extract_up_and_down_stream_failure_asset() {
        // provide setup
        let aspa_val = setup_validator();

        // Generate an BgpElem with AS_Set in path
        let mut elem: BgpElem = Default::default();
        elem.as_path = Some(AsPath {
            segments: vec![
                AsPathSegment::AsSet(vec![64501.into()]),
                AsPathSegment::AsSequence(
                    [64505, 64506, 64499]
                        .iter()
                        .map(|asn| (*asn).into())
                        .collect(),
                ),
            ],
        });
        elem.peer_asn = 64505.into();
        assert_failure(&aspa_val, &elem, UpInfFailReason::FailureAsset)
    }

    #[test]
    fn test_extract_up_and_down_stream_failure_none() {
        // provide setup
        let aspa_val = setup_validator();

        // Generate an BgpElem with AS_Set in path
        let mut elem: BgpElem = Default::default();
        assert_failure(&aspa_val, &elem, UpInfFailReason::FailureNone)
    }

    #[test]
    fn test_extract_up_and_down_stream_failure_empty() {
        // provide setup
        let aspa_val = setup_validator();

        // Generate an BgpElem with AS_Set in path
        let mut elem: BgpElem = Default::default();
        elem.as_path = Some(AsPath { segments: vec![] });
        assert_failure(&aspa_val, &elem, UpInfFailReason::FailureEmpty)
    }

    #[test]
    fn test_extract_up_and_down_stream_failure_uncertain() {
        // provide setup
        let aspa_val = setup_validator();

        // failure test, attest in ipv6 but not ipv4
        let elem = elem_from_specification(&[64505, 64506, 64499], 64505, true, None);
        assert_failure(&aspa_val, &elem, UpInfFailReason::FailureUncertain)
    }

    fn assert_no_witnesses(
        aspa_val: &OpportunisticAspaPathValidator,
        elem: &BgpElem,
        state_expected: OpportunisticAspaValidationState,
    ) {
        match aspa_val.validate_opportunistically(elem) {
            OpportunisticAspaValidationState::Valid(_)
            | OpportunisticAspaValidationState::InvalidAspa(_) => {
                panic!("Expected validation state without witnesses.")
            }

            other => assert_eq!(
                state_expected, other,
                "Expected state {:?} but got state {:?}",
                state_expected, other
            ),
        }
    }

    fn assert_witnesses(
        aspa_val: &OpportunisticAspaPathValidator,
        elem: &BgpElem,
        outcome_expected: &AspaValidatedRoute,
        valid_expected: bool,
    ) {
        match aspa_val.validate_opportunistically(elem) {
            OpportunisticAspaValidationState::Valid(outcome_inferred) => {
                if valid_expected {
                    assert_eq!(
                        *outcome_expected, outcome_inferred,
                        "Expected AspaValidatedRoute {:?}, got {:?}",
                        *outcome_expected, outcome_inferred
                    );
                } else {
                    panic!("Expected OpportunisticAspaValidationState::InvalidAspa but got OpportunisticAspaValidationState::Valid.");
                }
            }
            OpportunisticAspaValidationState::InvalidAspa(outcome_inferred) => {
                if !valid_expected {
                    assert_eq!(
                        *outcome_expected, outcome_inferred,
                        "Expected AspaValidatedRoute {:?}, got {:?}",
                        *outcome_expected, outcome_inferred
                    );
                } else {
                    panic!("Expected OpportunisticAspaValidationState::Valid but got OpportunisticAspaValidationState::InvalidAspa.");
                }
            }
            other => panic!("Expected state with witnesses, got {:?}", other),
        }
    }

    #[test]
    fn test_validate_opportunistically_valid() {
        // provide setup
        let aspa_val = setup_validator();
        let elem = elem_from_specification(&[64500, 64499], 64500, true, Some(64500));

        let witnesses = vec![AspaAttestWitness::AspaAttestConfirmation(
            RampDirection::Up,
            64499,
            64500,
        )];

        // collected pieces together.
        let val_route = AspaValidatedRoute {
            pfx: elem.prefix.prefix,
            path: elem.as_path.as_ref().unwrap().to_u32_vec().unwrap(),
            witnesses: witnesses,
            apex: vec![64500],
            apex_reason: UpInfSuccessReason::SuccessAttestation,
        };

        assert_witnesses(&aspa_val, &elem, &val_route, true)
    }

    #[test]
    fn test_validate_opportunistically_invalid_aspa() {
        // provide setup
        let aspa_val = setup_validator();
        let elem = elem_from_specification(&[701, 64508, 64499], 701, true, None);

        let witnesses = vec![AspaAttestWitness::AspaAttestOffense(
            RampDirection::Up,
            64499,
            64508,
        )];

        // collected pieces together.
        let val_route = AspaValidatedRoute {
            pfx: elem.prefix.prefix,
            path: elem.as_path.as_ref().unwrap().to_u32_vec().unwrap(),
            witnesses: witnesses,
            apex: vec![701],
            apex_reason: UpInfSuccessReason::SuccessRcpTierone,
        };

        assert_witnesses(&aspa_val, &elem, &val_route, false)
    }

    #[test]
    fn test_validate_opportunistically_invalid_asset() {
        // provide setup
        let aspa_val = setup_validator();
        // Generate an BgpElem with AS_Set in path
        let mut elem: BgpElem = Default::default();
        elem.as_path = Some(AsPath {
            segments: vec![
                AsPathSegment::AsSet(vec![64501.into()]),
                AsPathSegment::AsSequence(
                    [64505, 64506, 64499]
                        .iter()
                        .map(|asn| (*asn).into())
                        .collect(),
                ),
            ],
        });
        elem.peer_asn = 64505.into();
        assert_no_witnesses(
            &aspa_val,
            &elem,
            OpportunisticAspaValidationState::InvalidAsset,
        )
    }

    #[test]
    fn test_validate_opportunistically_unknown() {
        // provide setup
        let aspa_val = setup_validator();

        let elem = elem_from_specification(&[64503, 701, 64501], 64503, true, None);
        assert_no_witnesses(&aspa_val, &elem, OpportunisticAspaValidationState::Unknown)
    }

    #[test]
    fn test_validate_opportunistically_noopportunity() {
        // provide setup
        let aspa_val = setup_validator();

        let elem = elem_from_specification(&[64503, 64502, 64501], 64503, true, None);
        assert_no_witnesses(
            &aspa_val,
            &elem,
            OpportunisticAspaValidationState::NoOpportunity,
        )
    }
}
