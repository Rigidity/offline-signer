use serde::{Deserialize, Serialize};

use crate::keys::ConfigKey;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Config {
    #[serde(flatten)]
    pub key: ConfigKey,
    pub node_uri: Option<String>,
    pub network_id: String,
    pub agg_sig_data: String,
}
