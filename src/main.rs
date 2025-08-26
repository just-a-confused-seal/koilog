use gethostname::gethostname;
use evtx::EvtxParser;
use std::collections::HashMap;
use reqwest::blocking::{Client};
use serde::Serialize;
use serde_json::Value; //for debugging
use xmltree::Element;
use chrono::{Local};
use configparser::ini::{Ini};
use thiserror::Error;
use std::process;

#[derive(Error, Debug)]
pub enum Error{
    #[error("Could not find windows event log - security.evtx")]
    EvtxPathNotFound,

    #[error("Coule not find koi.ini - configuration file")]
    KoiPathNotFound,
}

#[derive(Serialize)]
struct EventPayload{
    event_id: u64, //whitelist windows event log
    event_source: String, //PC hostname
    event_desc: String, //short description from hashmap
    event_verbose:Value , //detail from r.data
}

#[derive(Serialize)]
struct Payload{
    event:EventPayload,
    sourcetype: String, //used for index
    time:i64, //timestamp
}

struct SplunkIni{
    splunk_url: String,
    splunk_mitre_enrichment: String, //gonna used this latter
    splunk_auth_key:String,
}

fn banner(){
    println!("--------------------------");
    println!("KOILOG - WINDOWS EVENT LOG - {:?}", gethostname());
    println!("--------------------------");
}

fn build_evtx_dict() -> HashMap<u64, String>{
    let mut evtx_whitelist_map: HashMap<u64,String> = HashMap::new();
    evtx_whitelist_map.insert(4624u64,"Successful account logon".to_string());
    evtx_whitelist_map.insert(4625u64,"Account failed to log on".to_string());
    evtx_whitelist_map.insert(4634u64,"Account was logged off".to_string());
    evtx_whitelist_map.insert(4647u64,"User initiated logoff".to_string());
    evtx_whitelist_map.insert(4648u64,"A logon was attempted using explicit credentials".to_string());
    evtx_whitelist_map.insert(4723u64,"An attempt was made to change an account's password".to_string());
    evtx_whitelist_map.insert(4724u64,"An attempt was made to reset an accounts password".to_string());
    evtx_whitelist_map.insert(4725u64,"A user account was disabled".to_string());
    evtx_whitelist_map.insert(4670u64,"Permissions on an object were changed".to_string());
    evtx_whitelist_map.insert(4672u64,"Special privileges assigned to new logon".to_string());
    evtx_whitelist_map.insert(4673u64,"A privileged service was called".to_string());
    evtx_whitelist_map.insert(4674u64,"An operation was attempted on a privileged object".to_string());
    evtx_whitelist_map.insert(4732u64,"A member was added to a security-enabled local group".to_string());
    evtx_whitelist_map.insert(4733u64,"A member was removed from a security-enabled local group".to_string());
    evtx_whitelist_map.insert(4735u64,"A security-enabled local group was changed".to_string());
    evtx_whitelist_map.insert(4737u64,"A security-enabled global group was changed".to_string());
    evtx_whitelist_map.insert(4738u64,"A user account was changed".to_string());
    evtx_whitelist_map.insert(4756u64,"A member was added to a security-enabled universal group".to_string());
    evtx_whitelist_map.insert(4757u64,"A member was removed from a security-enabled universal group".to_string());
    evtx_whitelist_map.insert(4717u64,"System security access was granted to an account".to_string());
    evtx_whitelist_map.insert(4663u64,"An attempt was made to access an object".to_string());
    evtx_whitelist_map.insert(4658u64,"The handle to an object was closed".to_string());
    evtx_whitelist_map.insert(4690u64,"An attempt was made to duplicate a handle to an object".to_string());

    return evtx_whitelist_map;
}

fn get_event_id_data(r:&String) -> u64{
    let xml_data = Element::parse(r.as_bytes()).expect("Failed to parse xml;");

    if let Some(system_xml) = xml_data.get_child("System"){
        if let Some(event_id) = system_xml.get_child("EventID"){
            for child in &event_id.children{
                if let xmltree::XMLNode::Text(text) = child{
                    let event_id:u64 = text.parse().expect("Failed parsed to u64");
                    return event_id 
                } 
            }
        }
    }

    return 0u64;
}

fn get_event_data(r:&String)-> Value{
    let mut map_json: HashMap<String,String> = HashMap::new();
    let xml_data = Element::parse(r.as_bytes()).expect("Failed to parse XML;");
    let unknown_name = String::from("unknown");

    if let Some(eventdata_xml) = xml_data.get_child("EventData"){
        for element in &eventdata_xml.children{
            if let xmltree::XMLNode::Element(data) = element{
                let name_attr = data.attributes.get("Name").map(String::as_str).unwrap_or(&unknown_name);
                let value = data.get_text().map(|cow| cow.into_owned()).unwrap_or_else(||"unknown".to_string());
                map_json.insert(name_attr.to_string(),value.to_string());
            }
        }
    }

    return serde_json::json!(map_json);
}

fn parse_evtx() -> Vec<Payload>{

    let local_evtx_security = "C:\\Windows\\System32\\winevt\\Logs\\Security.evtx";
    let mut evtx_json_list: Vec<Payload> = Vec::new();
    let mut parser = match EvtxParser::from_path(local_evtx_security).map_err(|_| Error::EvtxPathNotFound){
        Ok(p) => p,
        Err(e) =>{
            eprintln!("Failed to open EVTX file: {}",e);
            process::exit(1);
        }
    };

    let evtx_whitelist_map = build_evtx_dict();
    let current_timestamp = Local::now().timestamp() - 300i64;
    
    for record in parser.records(){
        match record{
            Ok(r) => {
                let epoch_timestamp:i64 = r.timestamp.timestamp() as i64;
                if epoch_timestamp > current_timestamp{
                    let event_id = get_event_id_data(&r.data);
                    if evtx_whitelist_map.contains_key(&event_id){
                        if let Some(payload_desc) = evtx_whitelist_map.get(&event_id){
                            //println!("{}",r.data);
                            
                                let evtx_payload_json = Payload{
                                    event: EventPayload{
                                        event_id: event_id,
                                        event_source: gethostname().to_string_lossy().into_owned(),
                                        event_desc: payload_desc.to_string(),
                                        event_verbose: get_event_data(&r.data),
                                    },
                                    sourcetype:"t2log_automation_wineventlog".to_string(),
                                    time:epoch_timestamp,
                                };

                                //uncomment this and comment above line to do debugging in json payload
                                //let json_string = serde_json::to_string_pretty(&evtx_payload_json).unwrap();
                                //println!("{}",json_string);

                                //i'm the above line don't forget to uncomment me later
                                evtx_json_list.push(evtx_payload_json);
                        }
                    }
                }
            },
            Err(e) => eprintln!("Error: {}",e),
        }
    }

    return evtx_json_list;
    
}

fn parsed_koi_ini() -> SplunkIni{
    let mut config = Ini::new();
    let _map_koi_ini = match config.load("koi.ini").map_err(|_| Error::KoiPathNotFound){
        Ok(p) => p,
        Err(e) => {
            eprintln!("Failed to open koi.ini file: {}",e);
            process::exit(1);
        }
    };
    //println!("{:?}",map_koi_ini);
    
    //let check_prop = config.get("PROP","prop_status").unwrap();
    let check_splunk = config.get("SPLUNK","splunk_status").unwrap();

    if check_splunk == "on"{
        println!("KOILOG - Splunk configuration - ON");
        let splunk_struct = SplunkIni{
            splunk_url: config.get("SPLUNK","splunk_url").unwrap(),
            splunk_mitre_enrichment: config.get("SPLUNK","splunk_mitre_enrichment").unwrap(),
            splunk_auth_key:config.get("SPLUNK","splunk_auth_key").unwrap(),
        };
        return splunk_struct;
    }
        let splunk_empty = SplunkIni{
            splunk_url: "".to_string(),
            splunk_mitre_enrichment: "".to_string(),
            splunk_auth_key:"".to_string(),
        };

        return splunk_empty;
    
}

fn check_splunk_hec(url: &String) -> i64{
    let http_client: Client = Client::new();
    let http_result = http_client.get(url).send();
    if http_result.is_ok(){
        println!("URL {} is alive!!!!",url);
        return 1i64;
    }else{
        println!("URL {} is not alive!!!!",url);
        return -1i64;
    }
}

fn send_splunk_hec(splunk_config: SplunkIni,evtx_payload_list:Vec<Payload>){
    let http_client: Client = Client::new();
    let ndjson = evtx_payload_list.iter().map(|p| serde_json::to_string(p).unwrap()).collect::<Vec<_>>().join("\n");
    let auth_key = format!("Splunk {}",splunk_config.splunk_auth_key);

    let http_post_send = http_client.post(splunk_config.splunk_url).body(ndjson).header("User-Agent","Koilog_Agent_V.0.0.1").header("Authorization",auth_key).send();
    if http_post_send.is_ok(){
        println!("{:#?}",http_post_send.ok().unwrap().text().unwrap());
    }else{
        println!("Not OK");
    }
}

fn main() {
    banner();
    let evtx_list:Vec<Payload> = parse_evtx();
    let koi_config:SplunkIni = parsed_koi_ini();
    let status_url:i64 = check_splunk_hec(&koi_config.splunk_url);
    if status_url == 1i64{
        println!("Proceed to send Log!");
        send_splunk_hec(koi_config,evtx_list);
    }
}
