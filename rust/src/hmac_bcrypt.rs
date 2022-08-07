use base64::{encode, encode_config, decode_config, BCRYPT};
use bcrypt::{hash_with_salt, DEFAULT_COST};
use getrandom::getrandom;
use hmac::{Hmac, Mac};
use sha2::Sha512;
use std::fmt;

const BCRYPT_ID: &str = "2a";
const BCRYPT_PEPPER: &str = "hmac_bcrypt";

struct Settings {
    id: String,
    cost: u32,
    salt: [u8; 16],
}

impl fmt::Display for Settings {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        let salt_b64 = encode_config(self.salt, BCRYPT);
        write!(f, "${}${:02}${}", self.id, self.cost, salt_b64)
    }
}

fn gen_salt() -> [u8; 16] {
    let mut s = [0_u8; 16];
    getrandom(&mut s)
        .map(|_| s)
        .expect("Salt randomness generation problem")
}

fn get_salt(salt_b64: &str) -> [u8; 16] {
    let mut salt = [0_u8; 16];
    let salt_vec = decode_config(salt_b64, BCRYPT)
        .expect("Could not base64 decode salt setting");
    for (src, dst) in salt.iter_mut().zip(salt_vec.iter()) {
        *src = *dst;
    }
    salt
}

fn parse_settings(settings_arg: Option<&str>) -> Settings {
    // settings is a string of "$<id>$<cost>$<salt>"
    let settings_default: String = format!("${BCRYPT_ID}${DEFAULT_COST}$");
    let settings: Vec<&str> = settings_arg
        .unwrap_or(&settings_default)
        .split('$')
        .collect();
    let id = String::from(settings[1]);
    let cost = settings[2].parse::<u32>().expect("Could not decode cost setting");
    let salt = match settings[3] {
        "" => gen_salt(),
        _ => get_salt(&settings[3][..22]),
    };

    Settings { id, cost, salt }
}

pub fn hmac_bcrypt_hash(
    password: &str,
    settings_arg: Option<&str>,
    pepper_arg: Option<&str>,
) -> String {
    let pepper = pepper_arg.unwrap_or(BCRYPT_PEPPER);
    let settings: Settings = parse_settings(settings_arg);

    // Pre hash hmac_sha512(key=pepper, message=password)
    type HmacSha512 = Hmac<Sha512>;
    let mut hmac = HmacSha512::new_from_slice(pepper.as_bytes())
        .expect("pre-hash HMAC key initialisation problem");
    hmac.update(password.as_bytes());
    //let pre_hash = encode_config(hmac.finalize().into_bytes(), BCRYPT);
    let pre_hash = encode(hmac.finalize().into_bytes());

    // Mid hash bcrypt(password, cost, salt)
    let mid_hash = hash_with_salt(pre_hash, settings.cost, settings.salt)
        .expect("Mid-hash bcrypt error")
        .format_for_version(bcrypt::Version::TwoA);

    // Post hash
    let mut hmac = HmacSha512::new_from_slice(pepper.as_bytes())
        .expect("pre-hash HMAC key initialisation problem");
    hmac.update(mid_hash.as_bytes());
    //let post_hash = encode_config(hmac.finalize().into_bytes(), BCRYPT);
    let post_hash = encode(hmac.finalize().into_bytes()).replace('=', "");

    format!("{}{}", settings, post_hash)
}

pub fn hmac_bcrypt_verify(
    password: &str,
    expected: &str,
    pepper_arg: Option<&str>,
) -> Result<String, String> {
    let settings_arg = &expected[..29];
    let salt_check = settings_arg.split('$').nth(3);
    if !match salt_check {
      // bcrypt base64 encoded salt should be 22 characters long
      Some(salt) => salt.len() == 22,
      None => false,
    } {
      // Most commonly due to non zero-padded cost < 10
      return Err("Settings badly formed".to_string());
    }
    let result = hmac_bcrypt_hash(password, Some(settings_arg), pepper_arg);
    if result == expected {
        Ok(result)
    } else {
        Err(result)
    }
}