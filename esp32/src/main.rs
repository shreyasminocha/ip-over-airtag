use embedded_svc::{
    http::{client::Client as HttpClient, Method},
    io::Write,
    wifi::{AuthMethod, ClientConfiguration, Configuration},
};
use esp_idf_svc::{
    eventloop::EspSystemEventLoop,
    hal::prelude::Peripherals,
    http::client::{Configuration as HttpConfiguration, EspHttpConnection},
    nvs::EspDefaultNvsPartition,
    wifi::{BlockingWifi, EspWifi},
};
use http::{Request, Response};
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

    connect_wifi(SSID, PASSWORD, &mut wifi)?;

    let mut client = HttpClient::wrap(EspHttpConnection::new(&HttpConfiguration {
        crt_bundle_attach: Some(esp_idf_svc::sys::esp_crt_bundle_attach),
        ..Default::default()
    })?);

    let req = Request::builder()
        .method(http::Method::GET)
        .uri("https://archlinux.org")
        .body([].as_ref())?;
    let resp = request(req, &mut client)?;

    info!("response status: {}", resp.status());

    let output = std::str::from_utf8(resp.body())?;
    info!("output: {}", output);

    Ok(())
}

// copied from example code
// https://github.com/esp-rs/esp-idf-svc/blob/master/examples/wifi.rs
fn connect_wifi(
    ssid: &str,
    password: &str,
    wifi: &mut BlockingWifi<EspWifi<'static>>,
) -> anyhow::Result<()> {
    let wifi_configuration: Configuration = Configuration::Client(ClientConfiguration {
        ssid: ssid.try_into().unwrap(),
        bssid: None,
        auth_method: AuthMethod::WPA2Personal,
        password: password.try_into().unwrap(),
        channel: None,
        ..Default::default()
    });

    wifi.set_configuration(&wifi_configuration)?;

    wifi.start()?;
    info!("Wifi started");

    wifi.connect()?;
    info!("Wifi connected");

    wifi.wait_netif_up()?;
    info!("Wifi netif up");

    Ok(())
}

fn request(
    req: Request<&[u8]>,
    client: &mut HttpClient<EspHttpConnection>,
) -> anyhow::Result<Response<Vec<u8>>> {
    let headers: Vec<(&str, &str)> = req
        .headers()
        .iter()
        .map(|(k, v)| {
            (
                k.as_str(),
                v.to_str().expect("could not convert header value to str"),
            )
        })
        .collect();

    info!("headers");

    let esp_method = match *req.method() {
        http::Method::GET => Method::Get,
        http::Method::POST => Method::Post,
        _ => unimplemented!("who uses other http methods??"),
    };
    let uri = req.uri().to_string();
    let mut esp_req = client.request(esp_method, &uri, &headers)?;
    esp_req.write_all(req.body())?;

    info!("request made");

    let mut esp_resp = esp_req.submit()?;
    info!("request submitted");

    let resp_builder = http::Response::builder().status(esp_resp.status());

    let mut body = [0u8; 4096];
    esp_resp.read(&mut body)?;
    let resp = resp_builder.body(Vec::from(body))?;

    info!("response built");

    Ok(resp)
}
