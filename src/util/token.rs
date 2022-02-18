use std::error::Error;
use std::fmt::{Debug, Display, Formatter};
use std::ops::Add;
use base64::DecodeError;
use chrono::{DateTime, Duration, Utc};
use hmac::{Hmac, NewMac};
use hmac::crypto_mac::InvalidKeyLength;
use sha2::Sha256;

pub trait SasToken {
    fn new(primary_key: &'static str, days_valid: i64, hub_name: &'static str, device: Option<&'static str>, policy: Option<&'static str>) -> Result<Box::<Self>, SasTokenCreationFailure>
    {
        let primary_key_check =  Self::primary_token_check(primary_key);
        if primary_key_check != PrimaryKeyCheckResult::OK{
            // The primary key is invalid
            return Result::Err(SasTokenCreationFailure::PrimaryKeyInvalid(primary_key_check));
        }
        let hub_url = Self::hub_url(hub_name, device);
        unimplemented!()
    }
    fn token(&self) -> &'static str;
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
    fn future_timestamp(days_valid: i64) -> i64 {
        let time_now = chrono::offset::Utc::now();
        let add_days = Duration::days(days_valid);
        time_now.add(add_days).timestamp()
    }
    fn sign_hub_url(hub_url: &'static str, expire_timestamp: i64) -> String{
        format!("{}\n{}", hub_url, expire_timestamp)
    }
    fn hub_url(hub_name: &'static str, target: Option<&'static str>) -> String;
}

pub struct DeviceToken{
    token: &'static str,
    days_valid: i64,
    device: &'static str,
    hub_name: &'static str,
}


impl SasToken for DeviceToken{
    // Property getter
    fn token(&self) -> &'static str { return self.token; }
    fn hub_url(hub_name: &'static str, device: Option<&'static str>) -> String {
        if device.is_none()
        {
            panic!("Target cannot be None for DeviceToken");
        }
        else
        {
            format!("{}.azure-devices.net%2Fdevices%2F{}", hub_name, device.unwrap())
        }

    }
}

pub struct ServiceToken{
    token: &'static str,
    days_valid: i64,
    hub_name: &'static str,
    policy: &'static str
}

impl SasToken for ServiceToken{
    // Property getter
    fn token(&self) -> &'static str { return self.token; }

    fn hub_url(hub_name: &'static str, target: Option<&'static str>) -> String {
        format!("{}.azure-devices.net", hub_name)
    }
}

#[derive(Eq, PartialEq)]
pub enum PrimaryKeyCheckResult{
    DecodeFailure(base64::DecodeError),
    InvalidKeyLength,
    OK
}

impl Display for PrimaryKeyCheckResult{
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        match self {
            PrimaryKeyCheckResult::DecodeFailure(err) => {
                write!(f, "{}: {}", "DecodeFailure", err)
            }
            PrimaryKeyCheckResult::InvalidKeyLength => {
                write!(f, "{}", "InvalidKeyLength")
            }
            PrimaryKeyCheckResult::OK => {
                write!(f, "{}", "OK")
            }
        }
    }
}

pub enum SasTokenCreationFailure{
    PrimaryKeyInvalid(PrimaryKeyCheckResult)
}

impl Display for SasTokenCreationFailure{
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        match self{
            SasTokenCreationFailure::PrimaryKeyInvalid(err) => {
                write!(f, "{}: {}", "PrimaryKeyInvalid", err)
            }
        }
    }
}

