use serde::{Serialize, Deserialize};
use crate::connection::Connection;
use crate::authentication::handle_strong_auth;
use std::error::Error;

use strum::IntoEnumIterator;
use strum_macros::{EnumString, EnumIter};

use read_input::prelude::*;


/// `Action` enum is used to perform logged operations:
/// -   Enable/Disable 2fa authentication
#[derive(Serialize, Deserialize, Debug, EnumString, EnumIter)]
pub enum Action {
    #[strum(serialize = "Enable/Disable 2FA", serialize = "1")]
    Switch2FA,
    #[strum(serialize = "Exit", serialize = "2")]
    Logout,
}

impl Action {
    pub fn display() {
        let mut actions = Action::iter();
        for i in 1..=actions.len() { println!("{}.\t{:?}", i, actions.next().unwrap()); }
    }

    pub fn perform(&self, connection: &mut Connection) -> Result<bool, Box<dyn Error>> {
        connection.send(self)?;

        match self {
            Action::Switch2FA => Action::switch_2fa(connection),
            Action::Logout => Ok(false)
        }
    }

    fn switch_2fa(connection: &mut Connection) -> Result<bool, Box<dyn Error>> {
        let salt: String = connection.receive()?;
        let challenge: String = connection.receive()?;

        // Compute response
        println!("\n<< Please enter your password to switch the 2FA >>");
        let password: String = input::<String>().msg("Password: ").get();
        let response = handle_strong_auth(&password, &salt, &challenge)?;

        connection.send(&response)?;

        // Get the status
        let status: String = connection.receive()?;
        println!("{}\n", status);

        Ok(true)
    }
}