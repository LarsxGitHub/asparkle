use mysql;

/////////////////////// TODO ///////////////////////
// fuck this DB shit. we produce a single json file data_latest.json that we sync every 8 hours ...
// has three first level keys:
// META:
//      SNAPSHOT_EPOCH_TS | #ROUTE_COLLECTORS | #IPv4_PEER_ASES | #IPv6_PEER_ASES | PDB_FILE_NAME |
//
// DETAILS_LATEST: rows(
//      ATTESTATION_FILE
//      CAS
//      PAS
//      CONFIRM/OFFENSE/UNSEEN
//      #PATHS_TOTAL
//      #PFX_TOTAL
//      EXAMPLE_ROUTE_PFX
//      EXAMPLE_ROUTE_PATH
//      INFERRED_APEX
//      INFERENCE_REASON)
//
// HISTORY: rows(
//      TS,
//      #ATTESTATION_FILES,
//      #CAS
//      #PAS
//      #ATTESTS
//      #ATTESTS_ONLY_BOTH
//      #ATTESTS_WITH_IPV4_WITHOUT_IPV6,
//      #ATTESTS_WITHOUT_IPV4_WITH_IPV6,
//      #ATTESTS_WITH_IPV4_AND_IPV6_SPECIFIC
//      #ATTESTS_WITH_ALO_CONFIRM_WITNESS
//      #ATTESTS_WITH_ALO_OFFENSE_WITNESS
//      #ATTESTS_WITH_ALO_UNSEEN
//      #ATTESTS_WITH_UNANIMOUS_TESTIMONY (every cas,pas-pair has a CONFIRM WITNESS, there are no OFFENSE_WITNESSes)

use crate::Config;

pub(crate) fn get_db_connection_pool(config: &Config) -> mysql::Pool {
    let url = format!(
        "mysql://{}:{}@{}",
        config.db_out_db_user, config.db_out_db_pwd, config.db_out_mysql_server,
    );

    let opts =
        mysql::Opts::from_url(&url).expect(&format!("Unable to parse options from url {}", &url));
    mysql::Pool::new(opts).expect(&format!("Unable to get connection pool for url {}", &url))
}
