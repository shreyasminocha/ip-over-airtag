use embedded_svc::{
    http::{client::Client as HttpClient, Method},
    io::Write,
};
use esp_idf_svc::http::client::EspHttpConnection;
use http::{Request, Response};
use log::info;

pub fn request(
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
