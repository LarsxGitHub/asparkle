use crate::aspa;
use serde_derive::{Deserialize, Serialize};

#[derive(Deserialize, Serialize, Debug)]
pub(crate) enum JsonWitnessType {
    CONFIRMED,
    OFFENDED,
    UNSEEN,
}

#[derive(Deserialize, Serialize, Debug)]
pub(crate) struct JsonContainer {
    meta_data: MetaData,
    latest_details: LatestDetails,
    aspa_history: AspaHistory,
}

#[derive(Deserialize, Serialize, Debug)]
pub(crate) struct MetaData {
    timestamp: u32,
}

#[derive(Deserialize, Serialize, Debug)]
pub(crate) struct LatestDetails {
    attestation_file: String,
    cas: u32,
    pas: u32,
    witness_type: JsonWitnessType,
    example_route_pfx: String,
    example_route_path: String,
    example_route_apex: u32,
    example_route_apex_reason: aspa::UpInfSuccessReason,
}

#[derive(Deserialize, Serialize, Debug)]
pub(crate) struct AspaHistory {
    timestamp: u32,
    cnt_asa_files_total: u32,
    cnt_uniq_cas_any: u32,
    cnt_uniq_cas_ipv4: u32,
    cnt_uniq_cas_ipv6: u32,
    cnt_uniq_pas_any: u32,
    cnt_uniq_pas_ipv4: u32,
    cnt_uniq_pas_ipv6: u32,
    cnt_aspa_objects_total: u32,
    cnt_aspa_objects_only_both: u32,
    cnt_aspa_objects_with_ipv4_without_ipv6: u32,
    cnt_aspa_objects_without_ipv4_with_ipv6: u32,
    cnt_aspa_objects_with_dedicated_ipv4_and_ipv6: u32,
    cnt_aspa_objects_with_alo_confirm_witness: u32,
    cnt_aspa_objects_with_alo_offense_witness: u32,
    cnt_aspa_objects_with_alo_unseen_witness: u32,
    cnt_aspa_objects_with_unanimous_testimony: u32, // (every cas,pas-pair has a CONFIRM WITNESS, there are no OFFENSE_WITNESSes)
}
