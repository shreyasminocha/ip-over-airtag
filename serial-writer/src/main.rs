use color_eyre::{self, eyre::eyre};
use std::thread;
use std::time;
use tracing::*;

fn main() -> color_eyre::Result<()> {
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

    let mut data = [0u8; 37];
    hex::decode_to_slice(
        "DFC74521EB001E4C00121968A480DDB266F529AA104E217675BDB54AE38A8F2697ED020000",
        &mut data,
    )?;

    loop {
        info!("writing adv data");
        port.write_all(&data)?;
        thread::sleep(time::Duration::from_secs(2));
    }
}
