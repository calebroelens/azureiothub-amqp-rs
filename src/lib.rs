pub mod amqp;
pub mod util;


#[cfg(test)]
mod tests{
    use crate::util::token::{DeviceToken, SasToken, SasTokenCreationFailure};

    // Tokens
    // Run with '-- --nocapture'
    #[test]
    fn test_tokens(){
        let test_token = "z4DNiu1ILV0VJ9fccvzv+E5jJlkoSER9LcCw6H38mpA";
        let test_sas = DeviceToken::new(
            test_token,
            200,
            "azuretesthub",
            Some("testingdevice"),
            None);
        match test_sas{
            Ok(ok) => {
                // Ok:
                println!("Ok");
                let token = ok.token();
            }
            Err(err) => {
                println!("Err: {}", err);
            }
        }
    }
}