use crate::aspa::{
    AspaAttestWitness, AspaValidatedRoute, OpportunisticAspaPathValidator,
    OpportunisticAspaValidationState, RampDirection, UpInfFailReason, UpInfSuccessReason,
};
use crate::db::{
    dump_to_json, AspaSummary, JsonContainer, JsonWitnessType, LatestDetails, MetaData,
};
use crate::peeringdb;
use crate::{aspa, Config};
use bgpkit_broker::{BgpkitBroker, BrokerItem};
use bgpkit_parser::BgpkitParser;
use crossbeam_channel::{unbounded, Receiver, Sender};
use itertools::Itertools;
use std::collections::{HashMap, HashSet};
use std::thread;
use threadpool::ThreadPool;

fn bgpkit_get_ribs_size_ordered(ts: i64) -> Vec<BrokerItem> {
    let broker = BgpkitBroker::new()
        .ts_start(&ts.to_string())
        .ts_end(&ts.to_string())
        .data_type("rib");

    broker
        .into_iter()
        .sorted_by_key(|item| -item.rough_size)
        .collect()
}

fn run_consumer(ch_in: Receiver<AspaValidatedRoute>) -> HashMap<u32, HashMap<u32, LatestDetails>> {
    let mut witness_map: HashMap<u32, HashMap<u32, LatestDetails>> = HashMap::new();

    let mut count = 0;
    loop {
        // pull in validated route, break once we hit the end of out recv()
        let mut val_route: AspaValidatedRoute;
        if let Ok(tmp) = ch_in.recv() {
            val_route = tmp;
        } else {
            break;
        }

        for witness in val_route.witnesses {
            // extract witness information
            let witness_type: JsonWitnessType;
            let cas: u32;
            let pas: u32;
            let direction: RampDirection;
            match witness {
                AspaAttestWitness::AspaAttestOffense(dir, c, p) => {
                    witness_type = JsonWitnessType::OFFENDED;
                    cas = c;
                    pas = p;
                    direction = dir;
                }
                AspaAttestWitness::AspaAttestConfirmation(dir, c, p) => {
                    witness_type = JsonWitnessType::CONFIRMED;
                    cas = c;
                    pas = p;
                    direction = dir;
                }
            }

            // ensure customer_as is inside.
            if !witness_map.contains_key(&cas) {
                witness_map.insert(cas, HashMap::new());
            }

            // if this (cas,pas)-pair has no example route yet, add one.
            if !witness_map.get_mut(&cas).unwrap().contains_key(&pas) {
                witness_map.get_mut(&cas).unwrap().insert(
                    pas,
                    LatestDetails {
                        attestation_file: "".to_string(),
                        cas: cas,
                        pas: pas,
                        witness_type: witness_type,
                        example_route_pfx: val_route.pfx.to_string(),
                        example_route_path: val_route
                            .path
                            .clone()
                            .into_iter()
                            .map(|i| i.to_string())
                            .join(" "),
                        example_route_apex: val_route.apex,
                        example_route_apex_reason: val_route.apex_reason,
                        example_route_ramp_direction: direction,
                    },
                );
            }
        }
    }
    witness_map
}

fn get_unseen_details(cas: &u32, pas: &u32, file: &String) -> LatestDetails {
    LatestDetails {
        attestation_file: String::from(file),
        cas: *cas,
        pas: *pas,
        witness_type: JsonWitnessType::UNSEEN,
        example_route_pfx: "".to_string(),
        example_route_path: "".to_string(),
        example_route_apex: 0,
        example_route_apex_reason: UpInfSuccessReason::SuccessAttestation,
        example_route_ramp_direction: RampDirection::Up,
    }
}

pub(crate) fn consolidate_results(
    attest_lookup: &HashMap<u32, HashSet<(u32, &String)>>,
    witness_map: &HashMap<u32, HashMap<u32, LatestDetails>>,
) -> Vec<LatestDetails> {
    let mut rows: Vec<LatestDetails> = Vec::new();
    for (cas, provider_set) in attest_lookup.into_iter() {
        // check from known attestations into witnesses -> matches only UNSEEN or CONFIRMED
        for (pas, file) in provider_set.into_iter() {
            if witness_map.contains_key(cas) {
                // we have had witnesses for at least some providers, unwrap is safe.
                if witness_map.get(cas).unwrap().contains_key(pas) {
                    // we also had a witness for this
                    let mut details = witness_map.get(cas).unwrap().get(pas).unwrap().clone();
                    details.attestation_file = String::from(*file);
                    rows.push(details);
                } else {
                    let details = get_unseen_details(cas, pas, file);
                    rows.push(details);
                }
            } else {
                // not even customer_as was seen ...
                let details = get_unseen_details(cas, pas, file);
                rows.push(details);
            }
        }
        // check for ASNs in witnesses but not attestations -> matches only Offenses.
        let spas_only: HashSet<u32> =
            HashSet::from_iter(provider_set.into_iter().map(|pair| pair.0).into_iter());

        if !witness_map.contains_key(cas) {
            continue;
        }

        for (pas, details) in witness_map.get(cas).unwrap().iter() {
            // if this pas is not in original spas, then it's an offense.
            if !spas_only.contains(pas) {
                let mut details = details.clone();
                details.attestation_file = "None".to_string();
                rows.push(details);
            }
        }
    }
    rows
}

pub(crate) fn run_pipeline(
    rib_ts: i64,
    aspa_dir: &str,
    pdb_file_path: &str,
    json_out_fn: &str,
    config: &Config,
) {
    // load route servers from PeeringDB file.
    let mut router_servers_ipv4: HashSet<u32> = HashSet::new();
    let mut router_servers_ipv6: HashSet<u32> = HashSet::new();
    peeringdb::load_routeservers_from_dump(
        pdb_file_path,
        &mut router_servers_ipv4,
        &mut router_servers_ipv6,
    );

    // load available asa files
    let asa_files =
        aspa::get_asa_files(aspa_dir).expect("Unable to obtain asa files from aspa_dir.");

    // get attestations from the asa files
    let attests = aspa::read_aspa_records(&asa_files).expect("Unable to read asa file.");

    // re-organize attestations in a format that's optimized for lookups. (needed much later)
    let attest_lookup = aspa::lookup_from_attests(&attests);

    // get broker items at rib ts
    let broker_items = bgpkit_get_ribs_size_ordered(rib_ts);

    // instanciate a worker pool and channels for communication.
    let pool = ThreadPool::new(config.pipeline_num_bgpkit_workers as usize);
    let (ch_out, ch_in) = unbounded();

    //set up validator
    let mut aspa_val: OpportunisticAspaPathValidator = OpportunisticAspaPathValidator::new();
    aspa_val.add_route_servers(&router_servers_ipv4, &router_servers_ipv6);
    aspa_val.add_upstreams_from_attestations(&attests);

    for target in broker_items {
        // ensure needed structures are cloned and ready to move into closure
        let ch_out_cl = ch_out.clone();
        let aspa_val_cl = aspa_val.clone();

        // enqueue the spawn of a new thread
        pool.execute(move || {
            // closure that processes the data of a single route collector.
            let parser = BgpkitParser::new(target.url.as_str()).unwrap();

            // iterate through elements
            for (i, elem) in parser.into_elem_iter().enumerate() {
                // validate the route and send successful messages to consumer
                match aspa_val_cl.validate_opportunistically(&elem) {
                    OpportunisticAspaValidationState::InvalidAspa(val_route)
                    | OpportunisticAspaValidationState::Valid(val_route) => {
                        ch_out_cl.send(val_route).unwrap()
                    }
                    _ => {} // no opportunities, just ignore this route.
                }
            }
        });
    }

    // we delivered clones to all threads, so we still have to drop the initial reference.
    drop(ch_out);

    // wait till all threads finished and their outputs were gathered
    let witness_map = run_consumer(ch_in);
    pool.join();

    let latest_details_rows = consolidate_results(&attest_lookup, &witness_map);
    let aspa_summary = AspaSummary::from(&latest_details_rows);
    let meta_data = MetaData {
        timestamp: rib_ts as u32,
    };
    let json_container = JsonContainer {
        latest_details: latest_details_rows,
        aspa_summary: aspa_summary,
        meta_data: meta_data,
    };

    dump_to_json(json_out_fn, &json_container);
}
