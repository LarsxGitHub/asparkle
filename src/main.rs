use chrono::{DateTime, FixedOffset, NaiveDate};
use std::process::exit;

#[macro_export]
/// macro that logs an error message bevor exiting.
macro_rules! exit_msg {
    ($($msg:tt)*) => {
        println!($($msg)*);
        exit(1);
    }
}


/// parses the input date and provides the timestamp for start-of-day DateTime.
fn parse_input_ts(date_str: &str) -> i64{
    // check if date is malformatted.
    if let Err(e) = NaiveDate::parse_from_str(date_str, "%Y-%m-%d"){
        exit_msg!("date is incorrectly formatted, see: {}", e);
    }

    // extend date to start-of-day DateTime
    let date_str = String::from(date_str) + " 00:00:00.000 +0000";
    let date: DateTime<FixedOffset>;
    match DateTime::parse_from_str(&date_str, "%Y-%m-%d %H:%M:%S%.3f %z"){
        Ok(dt) => date = dt,
        Err(e) => {
            // this should never happen
            exit_msg!("NaiveDate to DateTime conversion failed, see: {}", e);
        }
    }

    date.timestamp()
}


/***
fn show_files(){
    let broker = BgpkitBroker::new_with_params(
        "https://api.broker.bgpkit.com/v1",
        QueryParams {
            start_ts: Some(1640995200),
            end_ts: Some(1640998799),
            project: Some("route-views".to_string()),
            data_type: Some("update".to_string()),
            ..Default::default()
        });

    for item in &broker {
        println!("processing {:?}...", &item);
    }
}
**/
fn main() {

    let date_str = "2023-05-01";
    let date_str = "a-b-c";


    let _start_ts = parse_input_ts(date_str);


}
