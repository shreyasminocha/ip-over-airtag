use std::time;

use base64::{engine::general_purpose::STANDARD as b64, Engine as _};
use color_eyre::{self, eyre::eyre};
use offline_finding::protocol::{BleAdvertisementMetadata, OfflineFindingPublicKey};
use p224::{PublicKey, SecretKey};
use rand::rngs::{self, OsRng};
use tracing::*;

fn make_adv_data(key: &PublicKey) -> [u8; 37] {
    let of_pub_key: OfflineFindingPublicKey = key.into();
    let addr = of_pub_key.to_ble_address_bytes_be();
    let adv_data =
        of_pub_key.to_ble_advertisement_data(BleAdvertisementMetadata { status: 0, hint: 0 });

    let serial_data: [u8; 37] = [
        addr.as_slice(),
        [30u8].as_slice(),
        adv_data.as_slice(),
        [0x00u8].as_slice(),
    ]
    .concat()
    .try_into()
    .unwrap(); // Infallible

    serial_data
}

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

    let mut rng = OsRng::default();

    loop {
        let key = SecretKey::random(&mut rng);
        let adv_data = make_adv_data(&key.public_key());
        port.write_all(&adv_data)?;
    }
}
