use gethostname::gethostname;
use evtx::EvtxParser;
use std::collections::HashMap;
//use reqwest::Client;
use serde::Serialize;
use serde_json::Value; //for debugging
use xmltree::Element;
use chrono::{DateTime,Local};

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

/*#[derive(Serialize)]
struct EvtxMitre{
    event_id: u64,
    event_desc: String,
    mitre_id_tactic: String,
    mitre_id_technique: String,
    mitre_description: String,
}*/

fn banner(){
    println!("--------------------------");
    println!("KOILOG - WINDOWS EVENT LOG - {:?}", gethostname());
    println!("--------------------------");
}

/*fn build_evtx_dict_mitre() -> EvtxMitre{
    let mut evtxmitre_list: Vec<EvtxMitre> = Vec::new();
    evtx_whitelist_map.push(EvtxMitre{
        event_id: 0u64,
        event_desc: "".to_string(),
        mitre_id_tactic: "".to_string(),
        mitre_id_technique: "".to_string(),
        mitre_description: "".to_string(),
    });
}*/

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
    evtx_whitelist_map.insert(435244u64,"TESTING".to_string());

    return evtx_whitelist_map;
}

fn get_date_evtx(r:&String)->i64{
    let xml_data = Element::parse(r.as_bytes()).expect("Failed to parse XML;");
    //println!("Root element: {}", xml_data.name);

    if let Some(system_xml) = xml_data.get_child("System"){
        if let Some(time_created_xml) = system_xml.get_child("TimeCreated"){
            if let Some(text) = time_created_xml.attributes.get("SystemTime"){
                match DateTime::parse_from_rfc3339(text){
                    Ok(parsed_time) => {
                        let epoch = parsed_time.timestamp();
                        return epoch;
                    }Err(_e) =>{
                        return 0i64;
                    }
                }
            }
        }
    }

    return 0i64;
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

fn parse_evtx(){

    let local_evtx_security = "C:\\Windows\\System32\\winevt\\Logs\\Security.evtx";
    let mut parser = match EvtxParser::from_path(local_evtx_security){
        Ok(p) => p,
        Err(e) =>{
            eprintln!("Failed to open EVTX file: {}, are you running this as admin?",e);
            return;
        }
    };

    let evtx_whitelist_map = build_evtx_dict();
    let current_timestamp = Local::now().timestamp() - 300i64;
    let mut evtx_json_list: Vec<Payload> = Vec::new();
    for record in parser.records(){
        match record{
            Ok(r) => {
                if evtx_whitelist_map.contains_key(&r.event_record_id){
                    if let Some(payload_desc) = evtx_whitelist_map.get(&r.event_record_id){
                        let epoch_timestamp:i64 = get_date_evtx(&r.data);
                        
                        if epoch_timestamp > current_timestamp{
                            let evtx_payload_json = Payload{
                                event: EventPayload{
                                    event_id: r.event_record_id,
                                    event_source: gethostname().to_string_lossy().into_owned(),
                                    event_desc: payload_desc.to_string(),
                                    event_verbose: get_event_data(&r.data),
                                },
                                sourcetype:"t2log_automation_wineventlog".to_string(),
                                time:epoch_timestamp,
                            };
                            evtx_json_list.push(evtx_payload_json);
                            
                            let json_string = serde_json::to_string_pretty(&evtx_payload_json).unwrap();
                            println!("{}",json_string);
                        }
                    }
                }
            },
            Err(e) => eprintln!("Error: {}",e),
        }
    }
    
}


fn main() {
    banner();
    parse_evtx();
}
