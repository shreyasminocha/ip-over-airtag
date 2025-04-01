use std::time;

use base64::{engine::general_purpose::STANDARD as b64, Engine as _};
use color_eyre::{self, eyre::eyre};
use rand::rngs;
use tracing::*;

use ip_over_airtag::network::{Receiver, Sender};
use ip_over_airtag::offline_finding::p224::SecretKey;

#[tokio::main]
async fn main() -> color_eyre::Result<()> {
    color_eyre::install()?;
    let subscriber = tracing_subscriber::FmtSubscriber::new();
    tracing::subscriber::set_global_default(subscriber)?;

    info!("started up!");

    let ports = serialport::available_ports().unwrap();
    let port = ports
        .into_iter()
        .find(|p| matches!(p.port_type, serialport::SerialPortType::UsbPort(_)))
        .ok_or_else(|| eyre!("Found no USB serialports"))?;

    let mut port = serialport::new(port.port_name, 115200).open()?;

    let mut rng = rngs::OsRng;

    let alice_private_key = SecretKey::random(&mut rng);
    let alice_public_key = alice_private_key.public_key();

    let bob_private_key = SecretKey::random(&mut rng);
    let bob_public_key = bob_private_key.public_key();

    let alice_sender = Sender::new(alice_private_key);
    let bob_receiver = Receiver::new(bob_private_key);

    let data = b"hello world";

    let transmit_result = alice_sender
        .transmit(data, bob_public_key, async |ad_data, bt_address| {
            info!(
                "making advertisement {} ({})",
                hex::encode(ad_data),
                hex::encode(bt_address)
            );

            let serial_data: [u8; 37] = [
                bt_address.as_slice(),
                [30u8].as_slice(),
                ad_data.as_slice(),
                [0x00u8].as_slice(),
            ]
            .concat()
            .try_into()
            .expect("29 + 1 + 6 + 1 == 37");
            port.write_all(&serial_data)?;

            tokio::time::sleep(time::Duration::from_secs(10)).await;

            Ok(())
        })
        .await
        .unwrap();

    dbg!(&transmit_result);

    for (i, (bob_private_key, bob_public_key)) in bob_receiver
        .get_keys_for_fetching_and_decrypting(alice_public_key, data.len())
        .iter()
        .enumerate()
    {
        let hashed_public_key = bob_public_key.hash();
        println!(
            "{}. {} (private key = {})",
            i + 1,
            b64.encode(hashed_public_key),
            b64.encode(bob_private_key.to_bytes())
        );
    }

    info!("waiting 10 mins");
    tokio::time::sleep(time::Duration::from_secs(60 * 10)).await;

    let received = bob_receiver.receive(alice_public_key).await.unwrap();
    println!("received: {}", hex::encode(&received));
    println!("aka: {}", String::from_utf8(received).unwrap());

    Ok(())
}
