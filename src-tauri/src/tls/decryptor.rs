use std::collections::HashMap;
use std::fs;

pub struct TlsDecryptor {
    keys: HashMap<String, Vec<u8>>,
    loaded: bool,
}

impl TlsDecryptor {
    pub fn new() -> Self {
        Self {
            keys: HashMap::new(),
            loaded: false,
        }
    }

    pub fn load_sslkeylog(&mut self, path: &str) -> Result<(), String> {
        let content = fs::read_to_string(path)
            .map_err(|e| format!("Failed to read SSL key log: {}", e))?;

        for line in content.lines() {
            let line = line.trim();
            if line.is_empty() || line.starts_with('#') {
                continue;
            }

            let parts: Vec<&str> = line.split_whitespace().collect();
            if parts.len() >= 3 {
                let label = parts[0];
                let client_random = parts[1];
                let secret = parts[2];

                if label == "CLIENT_RANDOM" || label == "RSA" {
                    let secret_bytes = hex::decode(secret)
                        .map_err(|e| format!("Invalid hex in key log: {}", e))?;
                    self.keys.insert(client_random.to_string(), secret_bytes);
                }
            }
        }

        self.loaded = true;
        Ok(())
    }

    pub fn is_loaded(&self) -> bool {
        self.loaded
    }

    pub fn get_key(&self, client_random: &str) -> Option<&Vec<u8>> {
        self.keys.get(client_random)
    }

    pub fn key_count(&self) -> usize {
        self.keys.len()
    }
}

pub fn find_sslkeylog_path() -> Option<String> {
    std::env::var("SSLKEYLOGFILE").ok()
}
