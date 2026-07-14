pub mod bitwarden;
pub mod csv_import;
pub mod normalize;

use pspm_core::error::Result;
use pspm_core::types::{Item, Vault};

pub trait ImportEngine {
    fn name(&self) -> &'static str;
    fn supported_extensions(&self) -> Vec<&'static str>;
    fn parse(&self, data: &str) -> Result<(Vault, Vec<Item>)>;
}

pub struct ImportResult {
    pub vault: Vault,
    pub items: Vec<Item>,
    pub warnings: Vec<String>,
    pub errors: Vec<String>,
}
