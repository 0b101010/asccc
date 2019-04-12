use structopt::StructOpt;
use std::io::prelude::*;
use std::io::{stdin, ErrorKind};
use std::path::PathBuf;
use std::fs::File;
use failure::ResultExt;
use exitfailure::ExitFailure;

mod arg_coap {
    use structopt::clap::*;
    arg_enum! {
        #[derive(Debug)]
        pub enum Method {
            Get,
            Put,
            Post,
            Observe
        }
     }

     arg_enum! {
        #[derive(Debug)]
        pub enum MediaType {
            Text,
            Xml,
            OctetStream,
            Exi,
            Json,
            Cbor
        }
            
    }
}

use coap::{CoAPClient, CoAPRequest, IsMessage, Method, CoAPOption};
use num_traits::cast::FromPrimitive;
use coap::message::packet::ContentFormat;
use coap::message::packet::Packet;

/// A simple coap client.
#[derive(StructOpt, Debug)]
#[structopt(rename_all = "kebab-case")]
struct Cli {
    /// get put delete post
    #[structopt(long, short, default_value = "Get", raw(possible_values = "&arg_coap::Method::variants()", case_insensitive = "true"))]
    method: arg_coap::Method,
    /// i.e 192.168.1.3
    #[structopt(long, short, required = true)]
    host: String,
    /// The port if not standard CoAP port.
    #[structopt(long, short, default_value = "5683")]
    port: u16,
    /// The URI path of the request.
    #[structopt(long, short)]
    uri_path: String,
    /// Payload for a PUT or POST command in a file. If omitted will read stdin.
    #[structopt(long, short = "f", parse(from_os_str))]
    payload_file: Option<PathBuf>,
    /// Content format to send with request, does not do any conversion of payload.
    #[structopt(long, short, default_value = "Text", raw(possible_values = "&arg_coap::MediaType::variants()", case_insensitive = "true"))]
    content_format: arg_coap::MediaType,
    /// Encode the payload using cbor
    #[structopt(long, short)]
    encode_cbor: bool,
}

fn get_content_format(msg: &Packet) -> Option<ContentFormat> {
    if let Some(list) = msg.get_option(CoAPOption::ContentFormat) {
        if let Some(vector) = list.front() {
            match vector.len() {
                2 => {
                    let msb = vector[0] as u16;
                    let lsb = vector[1] as u16;
                    let number = (msb << 8) + lsb;
                    return ContentFormat::from_u16(number);
                }
                1 => {
                    let lsb = vector[0] as u16;
                    return ContentFormat::from_u16(lsb);
                }
                _ => return None
            } 
        }
    }
    None
}

fn set_accept_content_format(req: &mut CoAPRequest, cf: ContentFormat) {
    let content_format = cf as u16;
    let msb = (content_format >> 8) as u8;
    let lsb = (content_format & 0xFF) as u8;

    let content_format: Vec<u8> = vec![msb, lsb];
    req.message.add_option(CoAPOption::Accept, content_format);
}

fn coap_message_to_string(message: Packet) -> Result<(String), failure::Error> {
    match get_content_format(&message) {
        Some(cf) => {
            match cf {
                ContentFormat::ApplicationCBOR => {
                    let mut deserializer = serde_cbor::Deserializer::from_slice(message.payload.as_slice());
                    let mut serializer = serde_json::Serializer::pretty(Vec::new());
                    serde_transcode::transcode(&mut deserializer, &mut serializer)?;
                    let payload = serializer.into_inner();
                    Ok(String::from_utf8(payload)?)
                }
                _ => Ok(String::from_utf8(message.payload)?)
            }
        }
        None => Ok(String::from_utf8(message.payload)?)
    }
}

fn coap_request(opts: &Cli) -> Result<(), failure::Error>  {

    let addr = opts.host.as_str();
    let path = &opts.uri_path;

    println!("Client request: coap://{}:{}/{}", addr, opts.port, path);
    let mut request = CoAPRequest::new();
    match opts.method {
        arg_coap::Method::Get => request.set_method(Method::Get),
        arg_coap::Method::Put => request.set_method(Method::Put),
        _                     => return Err(failure::err_msg(format!("Method '{}' is not implemented!", opts.method)))
    }

    request.set_path(path);

    if opts.encode_cbor {
        set_accept_content_format(&mut request, ContentFormat::ApplicationCBOR);
    }

    match opts.content_format {
        arg_coap::MediaType::Text => request.message.set_content_format(ContentFormat::TextPlain),
        arg_coap::MediaType::Xml => request.message.set_content_format(ContentFormat::ApplicationXML),
        arg_coap::MediaType::OctetStream => request.message.set_content_format(ContentFormat::ApplicationOctetStream),
        arg_coap::MediaType::Exi => request.message.set_content_format(ContentFormat::ApplicationEXI),
        arg_coap::MediaType::Json => request.message.set_content_format(ContentFormat::ApplicationJSON),
        arg_coap::MediaType::Cbor => request.message.set_content_format(ContentFormat::ApplicationCBOR),
    }

    match opts.method {
        arg_coap::Method::Put => {
                let mut data = Vec::new();
                match opts.payload_file {
                    Some(ref path) => {
                        let mut file = File::open(path)
                            .with_context(|_| format!("opening file `{}`", path.display()))?;
                        file.read_to_end(&mut data).expect("Error reading file!");
                    }
                    None => {
                        let mut in_stream = stdin();
                        in_stream.read_to_end(&mut data).expect("Error reading file!");
                    }
                }
                let payload;
                if opts.encode_cbor {
                    let mut deserializer = serde_json::Deserializer::from_slice(data.as_slice());
                    let mut serializer = serde_cbor::Serializer::new(Vec::new());
                    serde_transcode::transcode(&mut deserializer, &mut serializer)?;
                    payload = serializer.into_inner();
                } else {
                    payload = data;
                }
                request.set_payload(payload);   
            },
        _ => {}
    }
    
    let client = CoAPClient::new((addr, opts.port))?;
    client.send(&request)?;

    match client.receive() {
        Ok(response) => {
            println!("Server reply: {}",
                     coap_message_to_string(response.message)?);
            Ok(())
        }
        Err(e) => {
            match e.kind() {
                ErrorKind::WouldBlock => Err(failure::err_msg("Request timeout")),   // Unix
                ErrorKind::TimedOut => Err(failure::err_msg("Request timeout")),     // Windows
                _ => Err(failure::err_msg(format!("Request error: {:?}", e))),
            }
        }
    }
}

fn coap_observe(opts: &Cli) -> Result<(), failure::Error> {
    let addr = opts.host.as_str();
    let path = &opts.uri_path;

    println!("Client observe: coap://{}:{}/{}", addr, opts.port, path);
    let mut client = CoAPClient::new((addr, opts.port))?;
    let rc = client.observe(path, |msg| {
        println!("Resource changed {}", coap_message_to_string(msg).unwrap());
    });
    match rc {
        Err(e) => {
            match e.kind() {
                ErrorKind::WouldBlock => Err(failure::err_msg("Request timeout")),   // Unix
                ErrorKind::TimedOut => Err(failure::err_msg("Request timeout")),     // Windows
                _ => Err(failure::err_msg(format!("Request error: {:?}", e))),
            }
        }
        Ok(_response) => {
            println!("Press any key to stop...");
            stdin().read_line(&mut String::new())?;
            Ok(())
        }
    }
}

fn exec_coap_method(opts: &Cli) -> Result<(), failure::Error> {  
    match opts.method {
        arg_coap::Method::Observe => coap_observe(&opts),
        _                         => coap_request(&opts)
    }
}

fn main() -> Result<(), ExitFailure> {
    let opts = Cli::from_args();
    Ok(exec_coap_method(&opts)?)
}
