use anyhow::Result;
use base64::{engine::general_purpose::STANDARD as b64, Engine as _};
use rand::rngs;

use offline_finding::{accessory::Accessory, p224::SecretKey};

use ip_over_airtag::accessory::TwoPartyChannel;

fn main() -> Result<()> {
    let mut rng = rngs::OsRng;

    let alice_secret_key = SecretKey::random(&mut rng);
    let bob_secret_key = SecretKey::random(&mut rng);

    let alice_two_party_channel =
        TwoPartyChannel::from_identity_keys(alice_secret_key.clone(), bob_secret_key.public_key());
    let bob_two_party_channel =
        TwoPartyChannel::from_identity_keys(bob_secret_key, alice_secret_key.public_key());

    let data = b"hello world";
    let data_length = data.len();

    println!(
        "[from alice to bob] data: {}\n",
        String::from_utf8(data.to_vec())?
    );

    println!("[alice] send bluetooth advertisements:");
    for (byte, their_public_key) in data.iter().zip(alice_two_party_channel.iter_their_keys()) {
        let bt_address = their_public_key.to_ble_address_bytes_be();
        let ad_data = TwoPartyChannel::generate_ad_to_transmit_data(their_public_key, byte);
        println!(
            "- {} (as {})",
            hex::encode(ad_data),
            bt_address.map(|byte| hex::encode_upper([byte])).join(":")
        );
    }

    println!("\n[bob] fetch reports:");
    for (i, (_, public_key)) in bob_two_party_channel
        .iter_our_keys()
        .enumerate()
        .take(data_length)
    {
        let hashed_public_key = public_key.hash();
        println!("{}. {}", i + 1, b64.encode(hashed_public_key));
    }

    Ok(())
}
