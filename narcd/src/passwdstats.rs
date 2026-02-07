use entropy::shannon_entropy;
use serde::Serialize;
use zxcvbn::zxcvbn;

#[derive(Debug, Serialize)]
pub struct PasswordStatistics {
    pub zx_guess: f64,
    pub sh_entr: f32,
}

impl PasswordStatistics {
    pub fn new(username: &str, password: &str) -> Self {
        Self {
            zx_guess: zxcvbn(password, &[username]).guesses_log10(),
            sh_entr: shannon_entropy(password),
        }
    }
}
