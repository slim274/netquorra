use async_snmp::{Auth, AuthProtocol, PrivProtocol, UsmConfig};

#[derive(Clone)]
pub enum SnmpCredentials {
    V2c {
        community: String,
    },
    V3 {
        username: String,
        auth_password: String,
        privacy_password: String,
    },
}

impl SnmpCredentials {
    pub fn to_auth(&self) -> Result<Auth, String> {
        match self {
            Self::V2c { community } => {
                if community.trim().is_empty() {
                    return Err("SNMP community string cannot be empty".into());
                }

                Ok(Auth::v2c(community.clone()))
            }

            Self::V3 {
                username,
                auth_password,
                privacy_password,
            } => {
                if username.trim().is_empty() {
                    return Err("SNMPv3 username cannot be empty".into());
                }

                if auth_password.len() < 8 || privacy_password.len() < 8 {
                    return Err("SNMPv3 passwords must contain at least 8 bytes".into());
                }

                let config = UsmConfig::new(username.clone())
                    .auth_priv(
                        AuthProtocol::Sha256,
                        auth_password.clone(),
                        PrivProtocol::Aes128,
                        privacy_password.clone(),
                    )
                    .map_err(|error| format!("Invalid SNMPv3 configuration: {error}"))?;

                Ok(Auth::Usm(config))
            }
        }
    }
    pub fn version_name(&self) -> &'static str {
        match self {
            Self::V2c { .. } => "SNMPv2c",
            Self::V3 { .. } => "SNMPv3",
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn accepts_valid_v2c_community() {
        let credentials = SnmpCredentials::V2c {
            community: "private-community".into(),
        };

        assert!(credentials.to_auth().is_ok());
    }

    #[test]
    fn rejects_empty_v2c_community() {
        let credentials = SnmpCredentials::V2c {
            community: " ".into(),
        };

        assert!(credentials.to_auth().is_err());
    }

    #[test]
    fn accepts_valid_v3_credentials() {
        let credentials = SnmpCredentials::V3 {
            username: "netquorra".into(),
            auth_password: "authpassword123".into(),
            privacy_password: "privacypassword123".into(),
        };

        assert!(credentials.to_auth().is_ok());
    }

    #[test]
    fn rejects_empty_v3_username() {
        let credentials = SnmpCredentials::V3 {
            username: " ".into(),
            auth_password: "authpassword123".into(),
            privacy_password: "privacypassword123".into(),
        };

        assert!(credentials.to_auth().is_err());
    }

    #[test]
    fn rejects_short_v3_passwords() {
        let credentials = SnmpCredentials::V3 {
            username: "netquorra".into(),
            auth_password: "short".into(),
            privacy_password: "short".into(),
        };

        assert!(credentials.to_auth().is_err());
    }
}
