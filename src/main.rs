use offline_finding::p224::SecretKey;

use ip_over_airtag::accessory::TwoPartyChannel;
use rand::rngs;

fn main() {
    let mut rng = rngs::OsRng;
    let alice_secret_key = SecretKey::random(&mut rng);
    let bob_secret_key = SecretKey::random(&mut rng);

    let mut channel = TwoPartyChannel::new(alice_secret_key, bob_secret_key.public_key());

    for byte in b"hello world" {
        let ad_data = channel.generate_ad_to_transmit_data(byte);
        println!("{}", hex::encode(ad_data));
    }
}
