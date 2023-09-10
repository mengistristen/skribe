//! This module store the type for the collective state of the application.
use std::collections::HashMap;

/// The shared state for the application.
#[derive(Debug)]
pub struct AppState {
    /// A temporary map of usernames to their associated public keys.
    pub keys: HashMap<String, String>,
}

impl AppState {
    /// Creates a new [`AppState`].
    pub fn new() -> Self {
        AppState {
            keys: HashMap::new(),
        }
    }
}
