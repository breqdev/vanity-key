use rsa::{pkcs1::EncodeRsaPrivateKey, BigUint, PublicKeyParts, RsaPrivateKey, RsaPublicKey};
use std::sync::{Arc, Mutex};
use std::thread;
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

fn numberize(start: &str) -> Vec<String> {
    let mut strings: Vec<String> = Vec::new();

    match start.chars().nth(0) {
        Some('o') => {
            strings.append(
                &mut numberize(&start[1..])
                    .iter()
                    .map(|s| format!("o{}", s))
                    .collect(),
            );
            strings.append(
                &mut numberize(&start[1..])
                    .iter()
                    .map(|s| format!("0{}", s))
                    .collect(),
            );
        }
        Some('e') => {
            strings.append(
                &mut numberize(&start[1..])
                    .iter()
                    .map(|s| format!("e{}", s))
                    .collect(),
            );
            strings.append(
                &mut numberize(&start[1..])
                    .iter()
                    .map(|s| format!("3{}", s))
                    .collect(),
            );
        }
        Some('a') => {
            strings.append(
                &mut numberize(&start[1..])
                    .iter()
                    .map(|s| format!("a{}", s))
                    .collect(),
            );
            strings.append(
                &mut numberize(&start[1..])
                    .iter()
                    .map(|s| format!("4{}", s))
                    .collect(),
            );
        }
        Some('s') => {
            strings.append(
                &mut numberize(&start[1..])
                    .iter()
                    .map(|s| format!("s{}", s))
                    .collect(),
            );
            strings.append(
                &mut numberize(&start[1..])
                    .iter()
                    .map(|s| format!("5{}", s))
                    .collect(),
            );
        }
        Some('g') => {
            strings.append(
                &mut numberize(&start[1..])
                    .iter()
                    .map(|s| format!("g{}", s))
                    .collect(),
            );
            strings.append(
                &mut numberize(&start[1..])
                    .iter()
                    .map(|s| format!("6{}", s))
                    .collect(),
            );
        }
        Some(letter) => {
            strings.append(
                &mut numberize(&start[1..])
                    .iter()
                    .map(|s| format!("{}{}", letter, s))
                    .collect(),
            );
        }
        None => {
            strings.push(String::from(""));
        }
    }

    strings
}

fn find_key_thread(solution: Arc<Mutex<Option<String>>>, accepted: Vec<String>) {
    let mut rng = rand::thread_rng();

    let start = Instant::now();
    let mut attempts = 0;

    loop {
        let priv_key = RsaPrivateKey::new(&mut rng, 512).expect("failed to generate a key");

        let pub_key = RsaPublicKey::from(&priv_key);
        let pub_string = format_key(pub_key.n(), pub_key.e());

        attempts += 1;

        for accepted in accepted.iter() {
            if pub_string.contains(accepted) {
                println!(
                    "Found key containing {} after {} attempts ({:?} seconds)",
                    accepted,
                    attempts,
                    start.elapsed()
                );

                *solution.lock().unwrap() =
                    Some(base64::encode(priv_key.to_pkcs1_der().unwrap().as_bytes()));
                return;
            }
        }

        {
            if let Some(_) = &*solution.lock().unwrap() {
                return;
            }
        }
    }
}

fn main() {
    let accepted = vec!["breq".to_string()];

    println!("{:?} accepted", accepted);

    let mut handles = Vec::new();
    let solution = Arc::new(Mutex::new(None));

    for _ in 0..12 {
        let clone = solution.clone();
        let accepted = accepted.clone();
        handles.push(thread::spawn(|| {
            find_key_thread(clone, accepted);
        }))
    }

    for handle in handles {
        handle.join().unwrap();
    }

    println!("{}", solution.lock().unwrap().as_ref().unwrap());
}
