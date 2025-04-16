use base64::{prelude::BASE64_STANDARD, Engine};
use color_eyre::{self, eyre::eyre};
use offline_finding::protocol::{BleAdvertisementMetadata, OfflineFindingPublicKey};
use p224::{elliptic_curve::sec1::ToEncodedPoint, PublicKey, SecretKey};
use rand::rngs::{self, OsRng};
use std::{fs::File, io::Write, time::SystemTime};
use tokio::time;
use tracing::*;

fn make_adv_data(key: &PublicKey) -> [u8; 37] {
    let of_pub_key: OfflineFindingPublicKey = key.into();
    let addr = of_pub_key.to_ble_address_bytes_be();
    let adv_data =
        of_pub_key.to_ble_advertisement_data(BleAdvertisementMetadata { status: 0, hint: 0 });

    let serial_data: [u8; 37] = [
        addr.as_slice(),
        [30u8, 0xff].as_slice(),
        adv_data.as_slice(),
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

    let mut output_file = File::create_new("output.csv")?;
    writeln!(&mut output_file, "timestamp,key")?;

    loop {
        let key = SecretKey::random(&mut rng);
        let adv_data = make_adv_data(&key.public_key());

        let unix_time = SystemTime::now()
            .duration_since(SystemTime::UNIX_EPOCH)?
            .as_secs();
        writeln!(
            &mut output_file,
            "{},{}",
            unix_time,
            BASE64_STANDARD.encode(key.to_bytes())
        )?;
        port.write_all(&adv_data)?;
        info!(
            "set new adv key: {:X?}",
            key.public_key().to_encoded_point(true).as_bytes()
        );

        time::sleep(time::Duration::from_secs(60)).await;
    }
}
