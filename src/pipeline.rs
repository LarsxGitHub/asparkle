use crate::aspa::{
    AspaAttestWitness, AspaValidatedRoute, OpportunisticAspaPathValidator,
    OpportunisticAspaValidationState, RampDirection,
};
use crate::db::{JsonWitnessType, LatestDetails};
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

fn process_collector(ch_out: Sender<AspaValidatedRoute>, target: BrokerItem) {
    let aspa_val: OpportunisticAspaPathValidator = OpportunisticAspaPathValidator::new();
    let parser = BgpkitParser::new(target.url.as_str()).unwrap();

    for (i, elem) in parser.into_elem_iter().enumerate() {
        match aspa_val.validate_opportunistically(&elem) {
            OpportunisticAspaValidationState::InvalidAspa(val_route)
            | OpportunisticAspaValidationState::Valid(val_route) => ch_out.send(val_route).unwrap(),
            _ => {}
        }
        if i == 100 {
            break;
        }
    }
}

fn run_consumer(
    ch_in: Receiver<AspaValidatedRoute>,
    pool: &ThreadPool,
    json_out_fn: &str,
    _config: &Config,
) {
    println!("CONSUMER STARTED");

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
    pool.join();
    println!("{:#?}", witness_map);
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

    // load attestations
    let asa_files =
        aspa::get_asa_files(aspa_dir).expect("Unable to obtain asa files from aspa_dir.");
    let attests = aspa::read_aspa_records(&asa_files).expect("Unable to read asa file.");

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
        let ch_out_cl = ch_out.clone();
        let aspa_val_cl = aspa_val.clone();
        pool.execute(move || {
            let parser = BgpkitParser::new(target.url.as_str()).unwrap();
            for (i, elem) in parser.into_elem_iter().enumerate() {
                match aspa_val_cl.validate_opportunistically(&elem) {
                    OpportunisticAspaValidationState::InvalidAspa(val_route)
                    | OpportunisticAspaValidationState::Valid(val_route) => {
                        ch_out_cl.send(val_route).unwrap()
                    }
                    _ => {}
                }
                if i == 100000 {
                    break;
                }
            }
            //println!("Finished item {:?}", &target);
        });
    }
    drop(ch_out);
    run_consumer(ch_in, &pool, json_out_fn, config);
}
