use serde::{Serialize, Deserialize};
use crate::connection::Connection;
use crate::yubi::Yubi;
use std::error::Error;
use lazy_static::lazy_static;
use read_input::prelude::*;
use base64;
use protocol::*;

use strum::IntoEnumIterator;
use strum_macros::{EnumString, EnumIter};

use argon2::{password_hash::PasswordHasher, Argon2, Params};

use hmac::{Hmac, Mac};
use sha2::{Sha256, Digest};

type HmacSha256 = Hmac<Sha256>;


/// `Authenticate` enum is used to perform:
/// -   User
/// -   Registration
/// -   Password Reset
#[derive(Serialize, Deserialize, Debug, EnumString, EnumIter)]
pub enum Authenticate {
    #[strum(serialize = "Authenticate", serialize = "1")]
    Authenticate,
    #[strum(serialize = "Register", serialize = "2")]
    Register,
    #[strum(serialize = "Reset password", serialize = "3")]
    Reset,
    #[strum(serialize = "Exit", serialize = "4")]
    Exit,
}

/// Compute HMAC response to a challenge with a key derived from Argon2id(password, salt)
///
/// The result is a tag in bytes.
///
/// # Errors
/// If the the password could not be hashed or if the tag could not me computed (HMAC).
///
/// # Examples
/// ```
/// let password = "My strong password";
/// let salt = "My random salt";
/// let challenge = "The challenge";
/// match handle_strong_auth(&password, &salt, &challenge) {
///     Ok(response) => println("The response to the challenge is {}", response.to_string()),
///     Err(e) => eprintln!("An error occurred: {}", e.to_string())
/// };
/// ```
pub fn handle_strong_auth(password: &str, salt: &str, challenge: &str) -> Result<Vec<u8>, Box<dyn Error>> {
    lazy_static! {
        static ref ARGON2: Argon2<'static> = Argon2::new(
            argon2_config::ALGORITHM,
            argon2_config::VERSION,
            Params::new(
                argon2_config::MEMORY,
                argon2_config::ITERATIONS,
                argon2_config::LANES,
                Some(argon2_config::OUTPUT_LENGTH)
            ).unwrap()
        );
    }

    // Hash password
    let hash = match ARGON2.hash_password(password.as_bytes(), &salt) {
        Ok(h) => h.to_string(),
        Err(_) => return Err("Failed hashing password")?
    };

    // Compute response to challenge
    let mut mac = HmacSha256::new_from_slice(hash.as_bytes())?;
    mac.update(challenge.as_bytes());

    // Return response
    Ok(mac.finalize().into_bytes()[..].to_vec())
}


impl Authenticate {
    pub fn display() {
        let mut actions = Authenticate::iter();
        for i in 1..=actions.len() { println!("{}.\t{:?}", i, actions.next().unwrap()); }
    }

    pub fn perform(&self, connection: &mut Connection) -> Result<(), Box<dyn Error>> {
        connection.send(self)?;

        match self {
            Authenticate::Authenticate => Authenticate::authenticate(connection),
            Authenticate::Register => Authenticate::register(connection),
            Authenticate::Reset => Authenticate::reset_password(connection),
            Authenticate::Exit => {
                println!("Exiting...");
                std::process::exit(0);
            }
        }
    }

    fn ask_valid_email() -> String {
        loop {
            let user_input = input::<String>().msg("Email: ").get();
            if validator::validate_email(&user_input) {
                return user_input;
            } else {
                println!("Invalid email!");
            }
        }
    }

    fn ask_valid_password() -> String {
        loop {
            let user_input = input::<String>().msg("Password: ").get();
            if validator::validate_password(&user_input) {
                return user_input;
            } else {
                println!("Invalid password!");
            }
        }
    }

    fn register(connection: &mut Connection) -> Result<(), Box<dyn Error>> {
        println!("\n<< Please register yourself >>");

        // Ask for valid email & password
        let email = Authenticate::ask_valid_email();
        let password = Authenticate::ask_valid_password();

        // Ask for Yubikey;
        let public_key = match Yubi::generate_new_piv() {
            Ok(pk) => pk,
            Err(e) => {
                return Err(format!("Register - Failed generating piv: {}", e.msg()))?;
            }
        };

        // Send credentials to server
        connection.send(&email)?;
        connection.send(&password)?;
        connection.send(&base64::encode(public_key))?;

        // Wait for validation
        let status: String = connection.receive()?;
        return if status == SUCCESS { Ok(()) } else { Err(status)? };
    }

    fn authenticate(connection: &mut Connection) -> Result<(), Box<dyn Error>> {
        println!("\n<< Please authenticate yourself >>");

        let email = input::<String>().msg("Email: ").get();
        connection.send(&email)?;

        // Retrieve challenge and salt
        let salt: String = connection.receive()?;
        let challenge: String = connection.receive()?;

        // Retrieve request for 2fa
        let activated_2fa: bool = connection.receive::<String>()? == "true";

        // Compute 1st factor
        let password = input::<String>().msg("Password: ").get();
        let response = handle_strong_auth(&password, &salt, &challenge)?;
        connection.send(&response)?;

        // Compute 2nd factor if necessary
        if activated_2fa {
            let response = match Yubi::sign_challenge(&Sha256::digest(challenge.as_bytes()).as_slice()) {
                Ok(s) => s,
                Err(e) => {
                    return Err(format!("Authentication - Failed signing challenge: {}", e.msg()))?;
                }
            };
            connection.send(&response)?;
        }

        // Wait for validation
        let status: String = connection.receive()?;
        return if status == SUCCESS { Ok(()) } else { Err(status)? };
    }

    fn reset_password(connection: &mut Connection) -> Result<(), Box<dyn Error>> {
        println!("\n<< Please provide an email and enter the token received >>");

        // Ask for valid email and wait for validation
        let email = Authenticate::ask_valid_email();
        connection.send(&email)?;
        let status: String = connection.receive()?;
        if status != SUCCESS {
            return Err(status)?;
        } else {
            println!("{}", connection.receive::<String>()?);
        }

        // Ask for reset token and wait for validation
        let otp = input::<String>().msg("Token: ").get();
        connection.send(&otp)?;
        let status: String = connection.receive()?;
        if status != SUCCESS {
            return Err(status)?;
        }

        // Ask for new password
        println!("\n<< Please provide a new password >>");
        loop {
            let new_pwd = Authenticate::ask_valid_password();
            let confirm_pwd = input::<String>().repeat_msg("Confirm password: ").get();

            if new_pwd == confirm_pwd {
                connection.send(&new_pwd)?;
                connection.send(&confirm_pwd)?;
                break;
            } else {
                println!("Passwords doesn't match!")
            }
        }

        // Wait for validation
        let status: String = connection.receive()?;
        return if status == SUCCESS { Ok(()) } else { Err(status)? };
    }
}