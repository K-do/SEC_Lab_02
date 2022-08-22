use lazy_static::lazy_static;
use fancy_regex::Regex;

/// Validate a password based on the policy:
/// - At least **one digit** \[0-9\]
/// - At least **one lowercase** character \[a-z\]
/// - At least **one uppercase** character \[A-Z\]
/// - At least **one special** character \[.!@#$%^&{}\[\]:;<>,?\\/~_+\-=|'\*\(\)\]
/// - At least **8** characters in length, but no more than **64**.
///
/// # Examples
/// ``` ignore
/// assert!(validate_password("Password1234."));
/// ```
pub fn validate_password(password: &str) -> bool {
    lazy_static! {
        static ref PASSWORD_REGEX: Regex = Regex::new(r"^(?=.*\d)(?=.*[a-z])(?=.*[A-Z])(?=.*[.!@#$%^&{}\[\]:;<>,?\\/~_+\-=|'\*\(\)]).{8,64}$").unwrap();
    }
    PASSWORD_REGEX.is_match(password).unwrap()
}

#[cfg(test)]
mod tests {
    use crate::validator::validate_password;

    #[test]
    fn valid_passwords() {
        // Minimum length
        assert!(validate_password("Aaaaaa1."));

        // Maximum length
        assert!(validate_password("Aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa1."));

        // All special chars
        assert!(validate_password("Aaaaaa1."));
        assert!(validate_password("Aaaaaa1!"));
        assert!(validate_password("Aaaaaa1@"));
        assert!(validate_password("Aaaaaa1#"));
        assert!(validate_password("Aaaaaa1$"));
        assert!(validate_password("Aaaaaa1%"));
        assert!(validate_password("Aaaaaa1^"));
        assert!(validate_password("Aaaaaa1&"));
        assert!(validate_password("Aaaaaa1("));
        assert!(validate_password("Aaaaaa1)"));
        assert!(validate_password("Aaaaaa1{"));
        assert!(validate_password("Aaaaaa1}"));
        assert!(validate_password("Aaaaaa1["));
        assert!(validate_password("Aaaaaa1]"));
        assert!(validate_password("Aaaaaa1]"));
        assert!(validate_password("Aaaaaa1:"));
        assert!(validate_password("Aaaaaa1;"));
        assert!(validate_password("Aaaaaa1<"));
        assert!(validate_password("Aaaaaa1>"));
        assert!(validate_password("Aaaaaa1,"));
        assert!(validate_password("Aaaaaa1?"));
        assert!(validate_password("Aaaaaa1\\"));
        assert!(validate_password("Aaaaaa1/"));
        assert!(validate_password("Aaaaaa1~"));
        assert!(validate_password("Aaaaaa1_"));
        assert!(validate_password("Aaaaaa1+"));
        assert!(validate_password("Aaaaaa1-"));
        assert!(validate_password("Aaaaaa1="));
        assert!(validate_password("Aaaaaa1|"));
        assert!(validate_password("Aaaaaa1'"));
        assert!(validate_password("Aaaaaa1*"));
        assert!(validate_password("Aaaaaa1*"));

        // Multiple digit, uppercase, lowercase and special chars
        assert!(validate_password("ABCabc123456./()"));
    }

    #[test]
    fn invalid_passwords() {
        assert!(!validate_password(""));

        // Invalid length
        assert!(!validate_password("Aaaaa1."));
        assert!(!validate_password("Aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa1."));

        // Missing digit
        assert!(!validate_password("Aaaaaaa."));

        // Missing uppercase
        assert!(!validate_password("aaaaaa1."));

        // Missing lowercase
        assert!(!validate_password("AAAAAA1."));

        // Missing special char
        assert!(!validate_password("Aaaaaaa1"));

        // Unsupported special chars
        assert!(!validate_password("Aaaaaaa "));
        assert!(!validate_password("Aaaaaaaé"));
        assert!(!validate_password("Aaaaaaa¬"));
    }
}