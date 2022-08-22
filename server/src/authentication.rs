use serde::{Serialize, Deserialize};
use crate::connection::Connection;
use crate::database::Database;
use crate::mailer::send_otp_mail;
use std::error::Error;

use protocol::*;

use argon2::{password_hash::{
    rand_core::OsRng,
    PasswordHash, PasswordHasher, SaltString,
}, Argon2, Params};

use ecdsa::{Signature, VerifyingKey};
use ecdsa::signature::Verifier;
use p256::NistP256;

use hmac::{Hmac, Mac};
use sha2::Sha256;

type HmacSha256 = Hmac<Sha256>;


/// `Authenticate` enum is used to perform:
/// -   Authentication
/// -   Registration
/// -   Password Reset
#[derive(Serialize, Deserialize, PartialEq, Debug)]
pub enum Authenticate {
    Authenticate,
    Register,
    Reset,
    Exit,
}

pub const SERVER_ERROR: &str = "Internal server error";

impl Authenticate {
    pub fn perform(connection: &mut Connection) -> Result<Option<User>, Box<dyn Error>> {
        match connection.receive()? {
            Authenticate::Authenticate => Authenticate::authenticate(connection),
            Authenticate::Register => Authenticate::register(connection),
            Authenticate::Reset => Authenticate::reset_password(connection),
            Authenticate::Exit => Err("Client disconnected")?
        }
    }

    fn hash_password(password: &str, salt: &SaltString) -> Result<String, Box<dyn Error>> {
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
        return match ARGON2.hash_password(password.as_bytes(), salt) {
            Ok(h) => Ok(h.to_string()),
            Err(e) => {
                eprintln!("Register - hashing password failed: {}", e.to_string());
                Err("")?
            }
        };
    }

    fn register(connection: &mut Connection) -> Result<Option<User>, Box<dyn Error>> {
        let email: String = connection.receive::<String>()?.to_lowercase(); // case insensitive
        let password: String = connection.receive()?;
        let public_key: String = connection.receive()?; // base64

        // Check email
        if !validator::validate_email(&email) {
            connection.send(&String::from("Invalid email"))?;
            return Ok(None);
        }
        if Database::get(&email).unwrap().is_some() {
            // I decide to disclose this information for user comfort
            connection.send(&String::from("This email is already used"))?;
            return Ok(None);
        }

        // Check password
        if !validator::validate_password(&password) {
            connection.send(&String::from("Invalid password"))?;
            return Ok(None);
        }

        // Generate salt
        let salt = SaltString::generate(&mut OsRng);

        // Hash password
        let hash = match Authenticate::hash_password(&password, &salt) {
            Ok(h) => h,
            Err(_) => {
                connection.send(&String::from(SERVER_ERROR))?;
                return Err("")?;
            }
        };

        // Register user
        let user = User { email, hash, public_key, activated_2fa: true };
        if Database::insert(&user).is_err() {
            connection.send(&String::from(SERVER_ERROR))?;
            eprintln!("Register - storing user failed");
            return Err("")?;
        }

        // Send validation
        connection.send(&String::from(SUCCESS))?;
        println!("Register - User {} successfully registered", user.email);
        Ok(Some(user))
    }

    fn authenticate(connection: &mut Connection) -> Result<Option<User>, Box<dyn Error>> {
        let email = connection.receive::<String>()?.to_lowercase();

        // Retrieve user (case insensitive)
        // If not in DB we retrieve a default user with a random salt
        let user = match Database::get(&email).unwrap() {
            Some(user) => user,
            None => User {
                email: String::new(),
                hash: format!("$argon2id$v=19$m=65536,t=3,p=4${}$00000000000000000000000000000000000000000000000000000000000000000000000000000000000000",
                              SaltString::generate(&mut OsRng).to_string()),
                public_key: String::new(),
                activated_2fa: false,
            }
        };

        // Send salt
        let salt = PasswordHash::new(&user.hash).unwrap().salt.unwrap().to_string();
        connection.send(&salt)?;

        // Send challenge
        let challenge = SaltString::generate(&mut OsRng).to_string();
        connection.send(&challenge)?;

        // Send 2FA request
        connection.send(&user.activated_2fa.to_string())?;

        // Validate 1st factor
        let mut mac = HmacSha256::new_from_slice(user.hash.as_bytes()).unwrap();
        mac.update(challenge.as_bytes());
        let valid_1fa = mac.verify_slice(&connection.receive::<Vec<u8>>()?).is_ok();

        // Validate 2nd factor if necessary
        let mut valid_2fa = true;
        if user.activated_2fa {
            // Get public key
            let public_key: VerifyingKey<NistP256> = match VerifyingKey::from_sec1_bytes(&base64::decode(&user.public_key).unwrap()) {
                Ok(k) => k,
                Err(e) => {
                    connection.send(&String::from(SERVER_ERROR))?;
                    eprintln!("Authentication - Public key parsing failed: {}", e.to_string());
                    return Err("")?;
                }
            };

            // Get signature
            let signature: Signature<NistP256> = match Signature::from_der(connection.receive::<Vec<u8>>()?.as_slice()) {
                Ok(s) => s,
                Err(e) => {
                    connection.send(&String::from(SERVER_ERROR))?;
                    eprintln!("Authentication - Signature parsing failed: {}", e.to_string());
                    return Err("")?;
                }
            };

            // Validate signature
            valid_2fa = public_key.verify(&challenge.as_bytes(), &signature).is_ok();
        }

        // Send authentication result
        return if valid_1fa && valid_2fa {
            println!("Register - User {} successfully authenticated", user.email);
            connection.send(&String::from(SUCCESS))?;
            Ok(Some(user))
        } else {
            connection.send(&String::from("Invalid authentication"))?;
            Ok(None)
        };
    }

    fn reset_password(connection: &mut Connection) -> Result<Option<User>, Box<dyn Error>> {
        // Validate email
        let email = connection.receive::<String>()?.to_lowercase();
        if !validator::validate_email(&email) {
            connection.send(&String::from("Invalid email"))?;
            return Ok(None);
        } else {
            connection.send(&String::from(SUCCESS))?;
        }

        // Generate OTP
        let otp = SaltString::generate(&mut OsRng).to_string();

        // Send email if user exists
        let user = Database::get(&email).unwrap();
        if user.is_some() {
            send_otp_mail(&email, &otp);
        } else {
            send_otp_mail("nobody@localhost", &otp);
        }
        connection.send(&String::from("If that email address is in our database, we will send you an email to reset your password."))?;

        // Validate otp
        let user_otp: String = connection.receive()?;
        if user_otp == otp {
            connection.send(&String::from(SUCCESS))?;
        } else {
            connection.send(&String::from("Invalid token!"))?;
            return Ok(None);
        }

        let new_pwd: String = connection.receive()?;
        let confirm_pwd: String = connection.receive()?;

        if new_pwd != confirm_pwd {
            connection.send(&String::from("Passwords doesn't match"))?;
            return Ok(None);
        }

        if !validator::validate_password(&new_pwd) {
            connection.send(&String::from("Invalid password!"))?;
            return Ok(None);
        }

        // Hash new password
        let hash = match Authenticate::hash_password(&new_pwd, &SaltString::generate(&mut OsRng)) {
            Ok(h) => h,
            Err(_) => {
                connection.send(&String::from(SERVER_ERROR))?;
                return Err("")?;
            }
        };

        return match user {
            Some(mut u) => {
                u.hash = hash;
                if Database::insert(&u).is_err() {
                    connection.send(&String::from(SERVER_ERROR))?;
                    eprintln!("Reset - update user {} in DB failed", u.email);
                    Err("")?
                } else {
                    println!("Reset - Password of user {} successfully reset", u.email);
                    connection.send(&String::from(SUCCESS))?;
                    Ok(Some(u))
                }
            }
            None => Ok(None)
        };
    }
}

#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct User {
    pub email: String,
    pub hash: String,
    pub public_key: String,
    pub activated_2fa: bool,
}
