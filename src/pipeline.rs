use crate::aspa::{
    AspaValidatedRoute, OpportunisticAspaPathValidator, OpportunisticAspaValidationState,
};
use crate::peeringdb;
use crate::{aspa, Config};
use bgpkit_broker::{BgpkitBroker, BrokerItem};
use bgpkit_parser::BgpkitParser;
use crossbeam_channel::{unbounded, Receiver, Sender};
use itertools::Itertools;
use std::collections::HashSet;
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

fn run_consumer(ch_in: Receiver<AspaValidatedRoute>, pool: &ThreadPool, _config: &Config) {
    println!("CONSUMER STARTED");
    let mut count = 0;
    loop {
        if let Ok(val_route) = ch_in.recv() {
            println!("{:?}", val_route);
            count += val_route.witnesses.len();
        } else {
            break;
        }
    }
    pool.join();
    println!("{}", count);
}

pub(crate) fn run_pipeline(rib_ts: i64, aspa_dir: &str, pdb_file_path: &str, config: &Config) {
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
    run_consumer(ch_in, &pool, config);
}
