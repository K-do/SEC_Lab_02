use serde::{Serialize, Deserialize};
use crate::connection::Connection;
use crate::authentication::{SERVER_ERROR, User};
use crate::database::Database;
use std::error::Error;
use argon2::password_hash::SaltString;
use argon2::PasswordHash;
use rand_core::OsRng;

use hmac::{Hmac, Mac};
use sha2::Sha256;

type HmacSha256 = Hmac<Sha256>;


/// `Action` enum is used to perform logged operations:
/// -   Enable/Disable 2fa authentication
#[derive(Serialize, Deserialize, Debug)]
pub enum Action {
    Switch2FA,
    Logout,
}

impl Action {
    pub fn perform(user: &mut User, connection: &mut Connection) -> Result<bool, Box<dyn Error>> {
        match connection.receive()? {
            Action::Switch2FA => Action::switch_2fa(user, connection),
            Action::Logout => Ok(false)
        }
    }

    fn switch_2fa(user: &mut User, connection: &mut Connection) -> Result<bool, Box<dyn Error>> {
        // Send salt
        let salt = PasswordHash::new(&user.hash).unwrap().salt.unwrap().to_string();
        connection.send(&salt)?;

        // Send challenge
        let challenge_1 = SaltString::generate(&mut OsRng).to_string();
        connection.send(&challenge_1)?;

        // Validate password
        let mut mac = HmacSha256::new_from_slice(user.hash.as_bytes()).unwrap();
        mac.update(challenge_1.as_bytes());
        if mac.verify_slice(&connection.receive::<Vec<u8>>()?).is_ok() {
            // Switch 2FA
            user.activated_2fa = !user.activated_2fa;
            return match Database::insert(user) {
                Ok(_) => {
                    println!("Switch 2FA - 2FA of user {} successfully switched", user.email);
                    connection.send(&format!("2FA switched to: {}", user.activated_2fa))?;
                    Ok(true)
                }
                Err(e) => {
                    eprintln!("Switch 2FA - Update user {} in DB failed: {}", user.email, e.to_string());
                    connection.send(&String::from(SERVER_ERROR))?;
                    Err("")?
                }
            };
        } else {
            connection.send(&String::from("Authentication failed!"))?;
            Ok(true)
        }
    }
}