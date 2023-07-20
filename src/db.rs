use crate::{aspa, utils};
use serde_json;
use std::collections::{HashMap, HashSet};
use std::fs;
use std::net::Shutdown::Write;

#[macro_use]
use serde::{Deserialize, Serialize};
use serde::de::Unexpected::Option;

#[derive(PartialEq, Deserialize, Serialize, Debug, Copy, Clone)]
pub(crate) enum JsonWitnessType {
    CONFIRMED,
    OFFENDED,
    UNSEEN,
}

#[derive(Deserialize, Serialize, Debug)]
pub(crate) struct JsonContainer {
    pub meta_data: MetaData,
    pub aspa_summary: AspaSummary,
    pub latest_details: Vec<LatestDetails>,
}

#[derive(Deserialize, Serialize, Debug)]
pub(crate) struct MetaData {
    pub(crate) timestamp: u32,
    pub(crate) routerservers_v4: Vec<u32>,
    pub(crate) routerservers_v6: Vec<u32>,
    pub(crate) seen_collectors: Vec<String>,
}

#[derive(Deserialize, Serialize, Debug, Clone)]
pub(crate) struct LatestDetails {
    pub attestation_files: Vec<String>,
    pub cas: u32,
    pub pas: u32,
    pub witness_type: JsonWitnessType,
    pub example_route_collector: String,
    pub example_route_pfx: String,
    pub example_route_path: String,
    pub example_route_apex: u32,
    pub example_route_apex_reason: aspa::UpInfSuccessReason,
    pub example_route_ramp_direction: aspa::RampDirection,
}

#[derive(Deserialize, Serialize, Debug)]
pub(crate) struct AspaSummary {
    pub cnt_asa_files_total: u32,
    pub cnt_uniq_cas: u32,
    pub cnt_uniq_pas: u32,
    pub cnt_aspa_objects_with_alo_confirm_witness: u32,
    pub cnt_aspa_objects_with_alo_offense_witness: u32,
    pub cnt_aspa_objects_with_alo_unseen_witness: u32,
    pub cnt_aspa_objects_with_unanimous_testimony: u32, // (every cas,pas-pair has a CONFIRM WITNESS, there are no OFFENSE_WITNESSes)
}

impl From<&Vec<LatestDetails>> for AspaSummary {
    fn from(rows: &Vec<LatestDetails>) -> Self {
        // get cnt_asa_files_total
        let mut asa_files: HashSet<&str> = HashSet::new();
        for row in rows {
            for file in &row.attestation_files {
                asa_files.insert(file);
            }
        }
        let cnt_asa_files_total = asa_files.len() as u32;
        drop(asa_files);

        // get cnt_uniq_cas
        let mut uniq_cas: HashSet<&u32> = HashSet::new();
        for row in rows {
            uniq_cas.insert(&row.cas);
        }
        let cnt_uniq_cas = uniq_cas.len() as u32;
        drop(uniq_cas);

        // get cnt_uniq_pas
        let mut uniq_pas: HashSet<&u32> = HashSet::new();
        for row in rows {
            uniq_pas.insert(&row.pas);
        }
        let cnt_uniq_pas = uniq_pas.len() as u32;
        drop(uniq_pas);

        //get cnt_aspa_objects_with_alo_confirm_witness
        let mut aspa_w_confirm: HashSet<&u32> = HashSet::new();
        for row in rows {
            if row.witness_type != JsonWitnessType::CONFIRMED {
                continue;
            }
            aspa_w_confirm.insert(&row.cas);
        }
        let cnt_aspa_objects_with_alo_confirm_witness = aspa_w_confirm.len() as u32;
        drop(aspa_w_confirm);

        //get cnt_aspa_objects_with_alo_offense_witness
        let mut aspa_w_offense: HashSet<&u32> = HashSet::new();
        for row in rows {
            if row.witness_type != JsonWitnessType::OFFENDED {
                continue;
            }
            aspa_w_offense.insert(&row.cas);
        }
        let cnt_aspa_objects_with_alo_offense_witness = aspa_w_offense.len() as u32;
        drop(aspa_w_offense);

        //get cnt_aspa_objects_with_alo_unseen_witness
        let mut aspa_w_unseen: HashSet<&u32> = HashSet::new();
        for row in rows {
            if row.witness_type != JsonWitnessType::UNSEEN {
                continue;
            }
            aspa_w_unseen.insert(&row.cas);
        }
        let cnt_aspa_objects_with_alo_unseen_witness = aspa_w_unseen.len() as u32;
        drop(aspa_w_unseen);

        // get cnt_aspa_objects_with_unanimous_testimony
        let mut offended_or_unseen_cas: HashSet<&u32> = HashSet::new();
        for row in rows {
            if row.witness_type == JsonWitnessType::CONFIRMED {
                continue;
            }
            offended_or_unseen_cas.insert(&row.cas);
        }
        let cnt_aspa_objects_with_unanimous_testimony =
            cnt_uniq_cas - (offended_or_unseen_cas.len() as u32);

        AspaSummary {
            cnt_asa_files_total,
            cnt_uniq_cas,
            cnt_uniq_pas,
            cnt_aspa_objects_with_alo_confirm_witness,
            cnt_aspa_objects_with_alo_offense_witness,
            cnt_aspa_objects_with_alo_unseen_witness,
            cnt_aspa_objects_with_unanimous_testimony,
        }
    }
}

pub(crate) fn dump_to_json(filename: &str, data: &JsonContainer) {
    let json_str = serde_json::to_string_pretty(data).expect("Not able to convert data to json");
    fs::write(filename, json_str).expect("Unable to write file");
}
