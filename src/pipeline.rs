use crate::aspa::{
    AspaValidatedRoute, OpportunisticAspaPathValidator, OpportunisticAspaValidationState,
};
use bgpkit_broker::{BgpkitBroker, BrokerItem};
use bgpkit_parser::BgpkitParser;
use crossbeam_channel::{unbounded, Receiver, Sender};
use itertools::Itertools;
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

fn run_consumer(ch_in: Receiver<AspaValidatedRoute>) -> thread::JoinHandle<()> {
    thread::spawn(move || {
        println!("CONSUMER STARTED");
        let mut count = 0;
        loop {
            println!("In loop");
            if let Ok(val_route) = ch_in.recv() {
                count += val_route.witnesses.len();
            } else {
                break;
            }
        }

        println!("{}", count);
    })
}

pub(crate) fn run_pipeline(rib_ts: i64) {
    let broker_items = bgpkit_get_ribs_size_ordered(rib_ts);
    let pool = ThreadPool::new(10);
    let (ch_out, ch_in) = unbounded();

    let consumer = run_consumer(ch_in);
    for target in broker_items {
        let ch_out_cl = ch_out.clone();
        pool.execute(move || {
            //println!("Starting item {:?}", &target);
            let aspa_val: OpportunisticAspaPathValidator = OpportunisticAspaPathValidator::new();
            let parser = BgpkitParser::new(target.url.as_str()).unwrap();
            for (i, elem) in parser.into_elem_iter().enumerate() {
                match aspa_val.validate_opportunistically(&elem) {
                    OpportunisticAspaValidationState::InvalidAspa(val_route)
                    | OpportunisticAspaValidationState::Valid(val_route) => {
                        ch_out_cl.send(val_route).unwrap()
                    }
                    _ => {}
                }
                if i == 100 {
                    break;
                }
            }
            //println!("Finished item {:?}", &target);
        });
    }
    drop(ch_out);
    pool.join();
    consumer.join();
}
