use rsa::{RsaPrivateKey, RsaPublicKey, BigUint, PublicKeyParts, pkcs1::EncodeRsaPrivateKey};
use std::time::Instant;

fn push_four(value: u32, vec: &mut Vec<u8>) {
    vec.push(((value >> 24) & 0xFF) as u8);
    vec.push(((value >> 16) & 0xFF) as u8);
    vec.push(((value >> 8) & 0xFF) as u8);
    vec.push((value & 0xFF) as u8);
}

fn push_bigint(value: &BigUint, vec: &mut Vec<u8>, extra: bool) {
    let mut bytes = value.to_bytes_be();
    if extra {
        bytes.insert(0, 0x00);
    }
    push_four(bytes.len() as u32, vec);
    vec.append(&mut bytes);
}

fn format_key(n: &BigUint, e: &BigUint) -> String {
    let mut key_bytes: Vec<u8> = Vec::new();

    let label = "ssh-rsa";
    let length = label.len();
    push_four(length as u32, &mut key_bytes);
    for c in label.chars() {
        key_bytes.push(c as u8);
    }

    push_bigint(e, &mut key_bytes, false);
    push_bigint(n, &mut key_bytes, true);

    return base64::encode(&key_bytes);
}

fn find_key() -> String {
    let mut rng = rand::thread_rng();

    let start = Instant::now();
    let mut attempts = 0;

    loop {
        let priv_key = RsaPrivateKey::new(&mut rng, 512).expect("failed to generate a key");

        let pub_key = RsaPublicKey::from(&priv_key);
        let pub_string = format_key(pub_key.n(), pub_key.e());

        attempts += 1;

        if attempts % 10 == 0 {
            println!("Searching... ({} attempts, {:?} seconds)", attempts, start.elapsed());
        }

        if pub_string.to_lowercase().contains("brooke") {
            println!("Found key after {} attempts ({:?} seconds)", attempts, start.elapsed());

            return base64::encode(priv_key.to_pkcs1_der().unwrap().as_bytes());
        }
    }
}

fn main() {
    println!("{}", find_key());
}
