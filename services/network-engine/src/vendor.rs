use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::OnceLock;

#[derive(Debug, Deserialize)]
struct IeeeRecord {
    #[serde(rename = "Registry")]
    registry: String,

    #[serde(rename = "Assignment")]
    assignment: String,

    #[serde(rename = "Organization Name")]
    organization_name: String,
}

#[derive(Debug, Clone, Serialize)]
pub struct VendorInfo {
    pub manufacturer: String,
    pub registry: String,
    pub assignment: String,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum MacAddressType {
    GloballyAdministered,
    LocallyAdministered,
    Multicast,
    Invalid,
}

pub struct VendorDatabase {
    vendors: HashMap<(String, String), VendorInfo>,
}

impl VendorDatabase {
    pub fn embedded() -> Result<Self, String> {
        let mut database = Self {
            vendors: HashMap::new(),
        };

        database.load_csv(include_str!("../data/ieee/ma-l.csv"))?;
        database.load_csv(include_str!("../data/ieee/ma-m.csv"))?;
        database.load_csv(include_str!("../data/ieee/ma-s.csv"))?;
        database.load_csv(include_str!("../data/ieee/iab.csv"))?;

        Ok(database)
    }

    fn load_csv(&mut self, contents: &str) -> Result<(), String> {
        let mut reader = csv::ReaderBuilder::new()
            .has_headers(true)
            .from_reader(contents.as_bytes());

        for record in reader.deserialize::<IeeeRecord>() {
            let record = record.map_err(|error| error.to_string())?;

            let assignment = record.assignment.trim().to_uppercase();
            let manufacturer = record.organization_name.trim().to_string();

            if assignment.is_empty() || manufacturer.is_empty() {
                continue;
            }

            self.vendors.insert(
                (record.registry.clone(), assignment.clone()),
                VendorInfo {
                    manufacturer,
                    registry: record.registry,
                    assignment,
                },
            );
        }

        Ok(())
    }

    pub fn lookup(&self, mac: &str) -> Result<Option<VendorInfo>, String> {
        let normalized = normalize_mac(mac)?;

        let first_octet =
            u8::from_str_radix(&normalized[0..2], 16).map_err(|error| error.to_string())?;

        // Multicast addresses are not treated as individual device vendors.
        if first_octet & 0x01 != 0 {
            return Ok(None);
        }

        // Locally administered MAC addresses may be randomized.
        if first_octet & 0x02 != 0 {
            return Ok(None);
        }

        // Longest-prefix matching: 36 bits, 28 bits, then 24 bits.
        let prefixes = [
            (&normalized[0..9], &["MA-S", "IAB"][..]),
            (&normalized[0..7], &["MA-M"][..]),
            (&normalized[0..6], &["MA-L"][..]),
        ];

        for (prefix, registries) in prefixes {
            for registry in registries {
                if let Some(vendor) = self
                    .vendors
                    .get(&(registry.to_string(), prefix.to_string()))
                {
                    if vendor.manufacturer.eq_ignore_ascii_case("private") {
                        return Ok(None);
                    }

                    return Ok(Some(vendor.clone()));
                }
            }
        }

        Ok(None)
    }
}

fn normalize_mac(mac: &str) -> Result<String, String> {
    let normalized: String = mac
        .chars()
        .filter(|character| character.is_ascii_hexdigit())
        .collect::<String>()
        .to_uppercase();

    if normalized.len() != 12 {
        return Err("Invalid MAC address format".to_string());
    }

    if !normalized
        .chars()
        .all(|character| character.is_ascii_hexdigit())
    {
        return Err("MAC address contains invalid characters".to_string());
    }

    Ok(normalized)
}

pub fn classify_mac(mac: &str) -> MacAddressType {
    let normalized = match normalize_mac(mac) {
        Ok(value) => value,
        Err(_) => return MacAddressType::Invalid,
    };

    let first_octet = match u8::from_str_radix(&normalized[0..2], 16) {
        Ok(value) => value,
        Err(_) => return MacAddressType::Invalid,
    };

    if first_octet & 0x01 != 0 {
        MacAddressType::Multicast
    } else if first_octet & 0x02 != 0 {
        MacAddressType::LocallyAdministered
    } else {
        MacAddressType::GloballyAdministered
    }
}

static DATABASE: OnceLock<Result<VendorDatabase, String>> = OnceLock::new();

pub fn lookup_mac_vendor(mac: &str) -> Result<Option<VendorInfo>, String> {
    let database = DATABASE.get_or_init(VendorDatabase::embedded);

    match database {
        Ok(database) => database.lookup(mac),
        Err(error) => Err(error.clone()),
    }
}
