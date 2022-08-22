use lazy_static::lazy_static;
use fancy_regex::Regex;

/// Validate an email based on OWASP regex:
/// https://owasp.org/www-community/OWASP_Validation_Regex_Repository
///
/// # Examples
/// ``` ignore
/// assert!(validate_email("valid.Email@sec.com"));
/// ```
pub fn validate_email(email: &str) -> bool {
    lazy_static! {
        static ref EMAIL_REGEX: Regex = Regex::new(r"^[a-zA-Z0-9_+&*-]+(?:\.[a-zA-Z0-9_+&*-]+)*@(?:[a-zA-Z0-9-]+\.)+[a-zA-Z]{2,7}$").unwrap();
    }
    EMAIL_REGEX.is_match(email).unwrap()
}

#[cfg(test)]
mod tests {
    use crate::validator::validate_email;

    #[test]
    fn valid_emails() {
        assert!(validate_email("classic.address@mybox.com"));
        assert!(validate_email("another_ADDREss98@my-super-box.PT"));

        // Weird addresses
        assert!(validate_email("a_b.98@-.CH"));
        assert!(validate_email("&.__@A.CH"));
        assert!(validate_email("+*-@a.B.c-d.Secured"));
    }

    #[test]
    fn invalid_emails() {
        // Missing part
        assert!(!validate_email(""));
        assert!(!validate_email("@mybox.CH"));
        assert!(!validate_email("email@.CH"));
        assert!(!validate_email("email@mybox"));

        // Invalid chars
        assert!(!validate_email("email//address@mybox.ch"));
        assert!(!validate_email(".email@mybox.ch"));
        assert!(!validate_email("email@my_box.ch"));
        assert!(!validate_email("email@my.box.c-h"));
        assert!(!validate_email("email@my.box.98"));

        // Invalid length in top level
        assert!(!validate_email("email@my.box.c"));
        assert!(!validate_email("email@my.box.abcdefgh"));
    }
}