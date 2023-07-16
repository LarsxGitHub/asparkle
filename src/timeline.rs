use crate::db::JsonContainer;
use serde::{Deserialize, Serialize};
use std::fs;
use std::fs::File;
use std::io::BufReader;

#[derive(Deserialize, Serialize, Debug)]
pub(crate) struct TimeLineDataPoint {
    pub(crate) timestamp: u32,
    pub(crate) num_rs_v4: u32,
    pub(crate) num_rs_v6: u32,
    pub(crate) num_collectors: u32,
    pub(crate) cnt_asa_files_total: u32,
    pub(crate) cnt_uniq_cas: u32,
    pub(crate) cnt_uniq_pas: u32,
    pub(crate) cnt_aspa_objects_with_alo_confirm_witness: u32,
    pub(crate) cnt_aspa_objects_with_alo_offense_witness: u32,
    pub(crate) cnt_aspa_objects_with_alo_unseen_witness: u32,
    pub(crate) cnt_aspa_objects_with_unanimous_testimony: u32, // (every cas,pas-pair has a CONFIRM WITNESS, there are no OFFENSE_WITNESSes)
}

pub(crate) fn generate_timeline(inference_dir: &str, out_file_name: &str) {
    let mut timeline: Vec<TimeLineDataPoint> = Vec::new();
    for entry in fs::read_dir(inference_dir).expect(&format!(
        "Unable to read contents of inference directory ({}).",
        inference_dir
    )) {
        // extract full path of entry
        let link = entry
            .expect(&format!(
                "Unable to obtain path for some file in '{}'.",
                inference_dir
            ))
            .path()
            .into_os_string()
            .into_string()
            .expect(&format!(
                "Unable to obtain os string for some file in '{}'.",
                inference_dir
            ));

        // ignore non-json files
        if !link.ends_with("json") {
            continue;
        }

        // open the file and allocate a reader for it
        let file = File::open(&link).expect(&format!(
            "Unable to open file '{}' in '{}'.",
            link, inference_dir,
        ));
        let reader = BufReader::new(file);

        // parse the json file
        let json: JsonContainer = serde_json::from_reader(reader).expect(&format!(
            "Unable to parse JsonContainer Json format from '{}'.",
            link
        ));

        timeline.push(TimeLineDataPoint {
            timestamp: json.meta_data.timestamp,
            num_rs_v4: json.meta_data.routerservers_v4.len() as u32,
            num_rs_v6: json.meta_data.routerservers_v6.len() as u32,
            num_collectors: json.meta_data.seen_collectors.len() as u32,
            cnt_asa_files_total: json.aspa_summary.cnt_asa_files_total,
            cnt_uniq_cas: json.aspa_summary.cnt_uniq_cas,
            cnt_uniq_pas: json.aspa_summary.cnt_uniq_pas,
            cnt_aspa_objects_with_alo_confirm_witness: json
                .aspa_summary
                .cnt_aspa_objects_with_alo_confirm_witness,
            cnt_aspa_objects_with_alo_offense_witness: json
                .aspa_summary
                .cnt_aspa_objects_with_alo_offense_witness,
            cnt_aspa_objects_with_alo_unseen_witness: json
                .aspa_summary
                .cnt_aspa_objects_with_alo_unseen_witness,
            cnt_aspa_objects_with_unanimous_testimony: json
                .aspa_summary
                .cnt_aspa_objects_with_unanimous_testimony,
        });
    }

    // sort with increasing timestamp.
    timeline.sort_by(|a, b| a.timestamp.partial_cmp(&b.timestamp).unwrap());

    // get json & save to file
    let json_str =
        serde_json::to_string_pretty(&timeline).expect("Not able to convert data to json.");
    fs::write(out_file_name, json_str).expect("Unable to write file");
}
