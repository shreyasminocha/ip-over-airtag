mod esp32_http;
mod esp32_wifi;

use embedded_svc::http::client::Client as HttpClient;
use esp_idf_svc::{
    eventloop::EspSystemEventLoop,
    hal::prelude::Peripherals,
    http::client::{Configuration as HttpConfiguration, EspHttpConnection},
    nvs::EspDefaultNvsPartition,
    wifi::{BlockingWifi, EspWifi},
};
use http::Request;
use log::info;

const SSID: &str = env!("WIFI_SSID");
const PASSWORD: &str = env!("WIFI_PASS");

fn main() -> anyhow::Result<()> {
    // It is necessary to call this function once. Otherwise some patches to the runtime
    // implemented by esp-idf-sys might not link properly. See https://github.com/esp-rs/esp-idf-template/issues/71
    esp_idf_svc::sys::link_patches();

    // Bind the log crate to the ESP Logging facilities
    esp_idf_svc::log::EspLogger::initialize_default();

    log::info!("Logging initialized!");

    let peripherals = Peripherals::take()?;
    let sys_loop = EspSystemEventLoop::take()?;
    let nvs = EspDefaultNvsPartition::take()?;

    let mut wifi = BlockingWifi::wrap(
        EspWifi::new(peripherals.modem, sys_loop.clone(), Some(nvs))?,
        sys_loop,
    )?;

    esp32_wifi::connect_wifi(SSID, PASSWORD, &mut wifi)?;

    let mut client = HttpClient::wrap(EspHttpConnection::new(&HttpConfiguration {
        crt_bundle_attach: Some(esp_idf_svc::sys::esp_crt_bundle_attach),
        ..Default::default()
    })?);

    let req = Request::builder()
        .method(http::Method::GET)
        .uri("https://archlinux.org")
        .body([].as_ref())?;
    let resp = esp32_http::request(req, &mut client)?;

    info!("response status: {}", resp.status());

    let output = std::str::from_utf8(resp.body())?;
    info!("output: {}", output);

    Ok(())
}
