mod hmac_bcrypt;

fn main() {
    println!("1 {}", hmac_bcrypt::hmac_bcrypt_hash("test-pass", None, None));
    println!("2 {}", hmac_bcrypt::hmac_bcrypt_hash("test-pass", Some("$2a$9$"), None));
    println!(
        "3 {}",
        hmac_bcrypt::hmac_bcrypt_hash("test-pass", Some("$2a$10$v.vnO5oVlX/5zJM9TTXSz."), None)
    );
    println!(
        "4 {:?}",
        hmac_bcrypt::hmac_bcrypt_verify(
            "test-pass",
            "$2a$13$v.vnO5oVlX/5zJM9TTXSz.JMdh9WwErhl6x9XMOEBs5x1R1FxuPC29TMJSMeAEnUlkEgbZw6r0FFZ9jFN07eykXAMgNZH3WrZSqxQkj4qKEQ",
            Some("test-pepper")
        )
    );
}