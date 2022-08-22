use lazy_static::lazy_static;
use lettre::transport::smtp::authentication::Credentials;
use lettre::{Message, SmtpTransport, Transport};

const SMTP_USER: &str = "SMTP_USER";
const SMTP_PASS: &str = "SMTP_PASSWORD";
const SMTP_SERV: &str = "SMTP_SERV_ADDRESS";
const MAIL_FROM: &str = "no-reply <no-reply@sec.com>";

/// Send an email containing an otp to the provided address and print information if the email
/// could be sent or not.
///
/// The subject is: **Reset password**
///
/// The body is: **Here is the token to reset your password: {}\n\nIf you don't request to reset
/// your password, please ignore this message.**
///
/// # Copyright
/// Based on the solution of the series 4, exercise 2 (SEC, 2022)
///
/// # Examples
/// ```
/// send_otp_mail("someone@sec.com", "my random OTP");
/// ```
pub fn send_otp_mail(dst: &str, otp: &str) {
    lazy_static! {
        static ref MAILER : SmtpTransport = SmtpTransport::relay(SMTP_SERV)
        .unwrap()
        .credentials(Credentials::new(SMTP_USER.to_string(), SMTP_PASS.to_string()))
        .build();
    }

    let email = Message::builder()
        .from(MAIL_FROM.parse().unwrap())
        .reply_to(MAIL_FROM.parse().unwrap())
        .to(dst.parse().unwrap())
        .subject("Reset password")
        .body(format!("Here is the token to reset your password: {}\n\nIf you don't request to reset your password, please ignore this message.", otp))
        .unwrap();

    match MAILER.send(&email) {
        Ok(_) => println!("Mailer - Reset token sent successfully to {}", dst),
        Err(e) => panic!("Could not send email: {:?}", e),
    }
}