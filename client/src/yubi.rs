use std::io;
use std::io::Read;
use read_input::prelude::*;
use yubikey::*;
use x509::SubjectPublicKeyInfo;
use lazy_static::lazy_static;
use core::str;
use hex::FromHex;
use fancy_regex::Regex;

pub struct Yubi;

impl Yubi {
    fn auto_yk() -> Result<YubiKey> {
        loop {
            for reader in Context::open()?.iter()? {
                if let Ok(yk) = reader.open() {
                    return Ok(yk);
                }
            }

            println!("No Yubikey detected: Please enter one and press [Enter] to continue...");
            let _ = io::stdin().read(&mut [0u8]).unwrap();
        }
    }

    fn validate_management_key(management_key: &str) -> bool {
        lazy_static! {
            static ref KEY_REGEX: Regex = Regex::new(r"^[0-9a-fA-F]{48}$").unwrap();
        }
        return KEY_REGEX.is_match(management_key).unwrap();
    }

    /// Generate new piv in the connected yubikey and return the corresponding public key.
    ///
    /// The user is prompted to enter a yubikey and the corresponding management key.
    ///
    /// # Errors
    /// If the yubikey could not be read or the generation of the PIV failed.
    ///
    /// # Examples
    /// ```
    /// let public_key = match Yubi::generate_new_piv() {
    ///     Ok(pk) => pk,
    ///     Err(e) => eprintln!("An error occurred: {}", e.to_string())
    /// };
    /// ```
    pub fn generate_new_piv() -> Result<Vec<u8>> {
        let mut yk = Self::auto_yk()?;

        // Ask for management key
        loop {
            let user_input = input::<String>().msg("Management key in hexadecimal: ").get();
            if Self::validate_management_key(&user_input) {
                let management_key = <[u8; 24]>::from_hex(user_input).unwrap();

                // Try to authenticate to the yubikey
                if yk.authenticate(MgmKey::from_bytes(management_key).unwrap()).is_ok() {
                    break;
                }
            }
            println!("Invalid management key!");
        };

        // Generate piv and return public key
        let pk_info = piv::generate(&mut yk,
                                    piv::SlotId::Authentication,
                                    piv::AlgorithmId::EccP256,
                                    PinPolicy::Once,
                                    TouchPolicy::Never)?;

        Ok(pk_info.public_key())
    }

    /// Sign the provided challenge with the PIV stored in a yubikey
    ///
    /// The user is prompted to enter the PIN of the yubikey.
    ///
    /// # Warning
    /// The PIN can be blocked after too much failed attempts. The number of left attempts is
    /// displayed to the user after each fail.
    ///
    /// # Errors
    /// If the yubikey could not be read or the PIN is blocked or the signature failed.
    ///
    /// # Examples
    /// ```
    /// let signature = match Yubi::sign_challenge("The challenge".as_bytes()) {
    ///     Ok(s) => s,
    ///     Err(e) => eprintln!(An error occurred: {}, e.to_string())
    /// };
    /// ```
    pub fn sign_challenge(challenge: &[u8]) -> Result<Vec<u8>> {
        let mut yk = Self::auto_yk()?;

        // Verify pin
        loop {
            let tries = yk.get_pin_retries().unwrap();
            if tries > 0 {
                let pin: String = input::<String>().msg("Pin: ").get();
                if yk.verify_pin(pin.as_bytes()).is_ok() {
                    break;
                } else {
                    println!("Invalid Pin!");
                    println!("{} trials left", tries - 1);
                }
            } else {
                eprintln!("Pin blocked!");
                return Err(Error::AuthenticationError);
            }
        }

        let signature = piv::sign_data(&mut yk,
                                       challenge,
                                       piv::AlgorithmId::EccP256,
                                       piv::SlotId::Authentication)?;

        Ok(signature.to_vec())
    }
}