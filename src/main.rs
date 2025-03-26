use anyhow::Result;
use rand::rngs;

use offline_finding::p224::SecretKey;

use ip_over_airtag::accessory::TwoPartyChannel;

fn main() -> Result<()> {
    let mut rng = rngs::OsRng;

    let alice_secret_key = SecretKey::random(&mut rng);
    let bob_secret_key = SecretKey::random(&mut rng);

    let mut two_party_channel = TwoPartyChannel::new(alice_secret_key, bob_secret_key.public_key());

    for byte in b"hello world" {
        let ad_data = two_party_channel.generate_ad_to_transmit_data(byte);
        println!("{}", hex::encode(ad_data));
    }

    Ok(())
}
