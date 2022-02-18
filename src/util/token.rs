use std::error::Error;
use std::fmt::{Debug, Display, Formatter};
use std::ops::Add;
use base64::DecodeError;
use chrono::{DateTime, Duration, Utc};
use hmac::{Hmac, NewMac};
use hmac::crypto_mac::InvalidKeyLength;
use sha2::Sha256;

trait SasToken{
    fn new(primary_key: &'static str, days_valid: i64, hub_name: &'static str, target: &'static str) -> Self;
    fn token(&self) -> &'static str;
    fn days_valid(&self) -> i64;
    fn primary_token_check(primary_key: &str) -> PrimaryKeyCheckResult{
        let check_token_format = base64::decode(primary_key);
        return match check_token_format {
            Ok(token) => {
                // Ok! --> Check HMAC now
                let check_hmac: Result<Hmac<Sha256>, InvalidKeyLength> = Hmac::new_from_slice(&token);
                if check_hmac.is_err()
                {
                    PrimaryKeyCheckResult::InvalidKeyLength
                }
                else
                {
                    PrimaryKeyCheckResult::OK
                }
            }
            Err(error) => {
                PrimaryKeyCheckResult::DecodeFailure(error)
            }
        };
    }
    fn future_timestamp(&self) -> i64 {
        let time_now = chrono::offset::Utc::now();
        let add_days = Duration::days(self.days_valid());
        time_now.add(add_days).timestamp()
    }
    fn to_sign_hub_url(&self, expire_timestamp: i64) -> String{
        format!("{}\n{}", self.hub_url(), expire_timestamp)
    }
    fn hub_url(&self) -> String;
}

pub struct DeviceToken{
    token: &'static str,
    days_valid: i64,
    target: &'static str,
    hub_name: &'static str,
}


impl SasToken for DeviceToken{
    fn new(primary_key: &'static str, days_valid: i64, hub_name: &'static str, target: &'static str) -> Self {
        todo!()
    }
    // Property getter
    fn token(&self) -> &'static str { return self.token; }
    fn days_valid(&self) -> i64 { return self.days_valid; }

    fn hub_url(&self) -> String {
        format!("{}.azure-devices.net%2Fdevices%2F{}", self.hub_name, self.target)
    }
}

pub struct ServiceToken{
    token: &'static str,
    days_valid: i64,
    hub_name: &'static str,
    target: &'static str
}

impl SasToken for ServiceToken{
    fn new(primary_key: &'static str, days_valid: i64, hub_name: &'static str, target: &'static str) -> Self {
        todo!()
    }
    // Property getter
    fn token(&self) -> &'static str { return self.token; }
    fn days_valid(&self) -> i64 { return self.days_valid; }

    fn hub_url(&self) -> String {
        format!("{}.azure-devices.net", self.hub_name)
    }
}

pub enum PrimaryKeyCheckResult{
    DecodeFailure(base64::DecodeError),
    InvalidKeyLength,
    OK
}
