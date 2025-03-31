use anyhow::Result;
use base64::{engine::general_purpose::STANDARD as b64, Engine as _};
use rand::rngs;

use offline_finding::p224::SecretKey;

use ip_over_airtag::network::{Receiver, Sender};

#[tokio::main]
async fn main() -> Result<()> {
    let mut rng = rngs::OsRng;

    let alice_private_key = SecretKey::random(&mut rng);
    let alice_public_key = alice_private_key.public_key();

    let bob_private_key = SecretKey::random(&mut rng);
    let bob_public_key = bob_private_key.public_key();

    let alice_sender = Sender::new(alice_private_key);
    let bob_receiver = Receiver::new(bob_private_key);

    let data = b"hello world";
    let data_length = data.len();

    println!(
        "[from alice to bob] data: {}\n",
        String::from_utf8(data.to_vec())?
    );

    println!("[alice] send bluetooth advertisements:");
    alice_sender
        .transmit(data, bob_public_key, |ad_data, bt_address| {
            println!(
                "- {} (as {})",
                hex::encode(ad_data),
                bt_address.map(|byte| hex::encode_upper([byte])).join(":")
            );

            Ok(())
        })
        .await?;

    println!("\n[bob] fetch reports:");
    for (i, (_, public_key)) in bob_receiver
        .get_keys_for_fetching_and_decrypting(alice_public_key, data_length)
        .iter()
        .enumerate()
    {
        let hashed_public_key = public_key.hash();
        println!("{}. {}", i + 1, b64.encode(hashed_public_key));
    }

    Ok(())
}
