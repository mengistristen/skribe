//! This client is used to properly authenticate and call a protected
//! route on the server. Authentication involves decrypting an RSA
//! encrypted token that was encrypted using a public key that is
//! stored by the server.
use anyhow::{anyhow, Context};
use base64::prelude::{Engine, BASE64_URL_SAFE};
use config::{Config, File, FileFormat};
use once_cell::sync::Lazy;
use openssl::rsa;
use skribe::request::AuthenticateRequest;
use skribe::response::AuthenticateResponse;
use std::fs;
use std::path::Path;

/// The base URL for making API requests.
static BASE_URL: Lazy<String> =
    Lazy::new(|| std::env::var("BASE_URL").unwrap_or_else(|_| "http://localhost:3000".to_string()));

/// Attempts to restore an auth token that is cached locally. If the token
/// does not exist or is not valid, will attempt to fetch a new one.
fn get_token(
    username: &str,
    auth_token_path: &str,
    private_key_path: &str,
    client: &reqwest::blocking::Client,
) -> anyhow::Result<String> {
    let restore_result = restore_token(auth_token_path, client);

    // If we can't restore the auth token, we may still be able to acquire one
    // from the API, so don't fail here.
    if restore_result.is_ok() {
        return Ok(restore_result.unwrap());
    }

    fetch_token(username, auth_token_path, private_key_path, client)
}

/// Attempts to restore an auth token that is cached locally. If found,
/// ensures the token is valid.
fn restore_token(
    auth_token_path: &str,
    client: &reqwest::blocking::Client,
) -> anyhow::Result<String> {
    let auth_token = fs::read_to_string(auth_token_path).context("failed to read auth token")?;
    let res = client
        .get(format!("{}/tokens/validate", *BASE_URL))
        .send()
        .context("request for token validation failed")?;

    if res.status().is_success() {
        Ok(auth_token)
    } else {
        Err(anyhow!("failed to validate token"))
    }
}

/// Attempts to fetch a new auth token.
fn fetch_token(
    username: &str,
    auth_token_path: &str,
    private_key_path: &str,
    client: &reqwest::blocking::Client,
) -> anyhow::Result<String> {
    let res = client
        .post(format!("{}/tokens", *BASE_URL))
        .json(&AuthenticateRequest {
            username: username.to_owned(),
        })
        .send()
        .context("request for auth token failed")?;

    if res.status().is_success() {
        let res = res
            .json::<AuthenticateResponse>()
            .context("failed to parse auth response")?;
        let token = decrypt_token(&res.token, private_key_path)?;

        fs::write(auth_token_path, &token).context("failed to write auth token")?;

        Ok(token)
    } else {
        Err(anyhow!("request for authentication failed"))
    }
}

/// Decrypts an RSA encrypted auth token using a private key. The private
/// key must be stored in the PEM format.
fn decrypt_token(encrypted_token: &str, private_key_path: &str) -> anyhow::Result<String> {
    // The token is sent as a Base64 encoded string, so we must decode it first
    let mut decoded = Vec::<u8>::new();

    BASE64_URL_SAFE
        .decode_vec(encrypted_token, &mut decoded)
        .context("failed to decode from Base64")?;

    // Perform the decryption using the private key. It must be in the PEM format.
    let private_key = fs::read_to_string(private_key_path).context("failed to read private key")?;
    let key = rsa::Rsa::private_key_from_pem(private_key.as_bytes())
        .context("failed to build private key")?;
    let mut token: Vec<u8> = vec![0; key.size() as usize];

    key.private_decrypt(&decoded, &mut token, rsa::Padding::PKCS1)
        .context("failed to decrypt token")?;

    // Convert the decrypted bytes into a string, trim the ends, and
    // remove additional null characters that were introduced due to
    // the buffer size.
    let token = String::from_utf8(token).context("failed to parse token")?;
    let token = token.trim().trim_end_matches('\0');

    Ok(token.to_string())
}

/// Finds the location for this app's local configuration.
fn get_config_base_path() -> anyhow::Result<String> {
    if let Ok(path) = std::env::var("XDG_CONFIG_HOME") {
        Ok(path)
    } else if let Some(home) = dirs::home_dir() {
        Ok(home
            .join(".local/share")
            .to_str()
            .ok_or_else(|| anyhow!("failed to find local config path"))?
            .to_owned())
    } else {
        Err(anyhow!("failed to find config file path"))
    }
}

/// Calls a protected route using the decrypted auth token.
fn perform_protected_call(token: &str, client: &reqwest::blocking::Client) -> anyhow::Result<()> {
    let res = client
        .get(format!("{}/protected", *BASE_URL))
        .header(reqwest::header::AUTHORIZATION, format!("Bearer {token}"))
        .send()?;

    if res.status().is_success() {
        Ok(())
    } else {
        Err(anyhow!("request for protected resource failed"))
    }
}

fn main() {
    // determine config file paths
    let config_base_path = get_config_base_path().expect("couldn't find the config base path");
    let application_config_path = Path::new(&config_base_path).join(".skribe");
    let config_file_path = application_config_path.join("config.toml");
    let auth_token_path = application_config_path.join("auth_token");

    // load config items
    let config = Config::builder()
        .add_source(
            File::from(config_file_path)
                .required(true)
                .format(FileFormat::Toml),
        )
        .build()
        .expect("failed to load config file");
    let username = config
        .get::<String>("username")
        .expect("property 'username' not found in config file");
    let private_key_path = config
        .get::<String>("private_key_path")
        .expect("property 'private_key_path' not found in config file");
    let auth_token_path = auth_token_path
        .to_str()
        .expect("couldn't parse auth token path")
        .to_owned();

    // use the same http client for all requests
    let client = reqwest::blocking::Client::new();

    // authentication
    let auth_token = get_token(&username, &auth_token_path, &private_key_path, &client)
        .expect("couldn't acquire an auth token");
    let auth_token = auth_token.trim().trim_end_matches('\0');

    perform_protected_call(auth_token, &client).expect("failed to access protected resource");
}