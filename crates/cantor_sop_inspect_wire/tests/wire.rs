use cantor_sop_inspect::{InspectionRequest, inspect, request as inspection_request};
use cantor_sop_inspect_wire::{
    MAX_WIRE_REQUEST_BYTES, Operation, REQUEST_PROFILE, RESPONSE_PROFILE, Status, WireRequest,
    parse_response, request, respond, validate_response, validate_response_bytes,
};
use cantor_sop_project::{PROJECT_PROFILE, SuppliedFile, SuppliedPackage, SuppliedProject};
use cantor_sop_query::FindRequest;
use serde_json::{Value, json};

const SOURCE: &str = "kind [kind:fact] \"Fact\" { meaning \"An observation\" }\ncontext [context:any] { scopes () purposes () perspectives () }\nterm [site:alpha] \"Café alpha\" { kind [kind:fact] context [context:any] meaning \"Alpha\" }\nterm [site:beta] \"Café beta\" { kind [kind:fact] context [context:any] meaning \"Beta\" }\n";

fn project() -> SuppliedProject {
    SuppliedProject {
        profile: PROJECT_PROFILE.to_owned(),
        packages: vec![SuppliedPackage {
            id: "pkg:site".to_owned(),
            version: "1.0.0".to_owned(),
            namespaces: ["site".to_owned()].into_iter().collect(),
            dependencies: Default::default(),
            files: vec![SuppliedFile {
                id: "source:site".to_owned(),
                path: "site/main.sop".to_owned(),
                namespace: "site".to_owned(),
                text: SOURCE.to_owned(),
            }],
        }],
    }
}

fn nested(text: &str) -> InspectionRequest {
    inspection_request(project(), FindRequest::prefix(text)).unwrap()
}

fn encoded(request: WireRequest) -> Vec<u8> {
    serde_json::to_vec(&request).unwrap()
}

#[test]
fn success_is_exact_deterministic_and_replayable() {
    let nested = nested("Caf");
    let direct = inspect(&nested).unwrap();
    let bytes = encoded(request(nested));
    let first = respond(&bytes).unwrap();
    let second = respond(&bytes).unwrap();
    assert_eq!(first, second);
    let response = parse_response(&first).unwrap();
    assert_eq!(response.profile, RESPONSE_PROFILE);
    assert_eq!(response.status, Status::Succeeded);
    assert_eq!(response.result, Some(direct));
    assert!(response.fault.is_none());
    validate_response(&bytes, &response).unwrap();
    validate_response_bytes(&bytes, &first).unwrap();
}

#[test]
fn empty_page_and_pagination_preserve_nested_truth() {
    let empty_bytes = encoded(request(nested("Absent")));
    let empty = parse_response(&respond(&empty_bytes).unwrap()).unwrap();
    assert!(empty.result.unwrap().find.items.is_empty());

    let mut find = FindRequest::prefix("Caf");
    find.limit = 1;
    let first_nested = inspection_request(project(), find.clone()).unwrap();
    let first_bytes = encoded(request(first_nested));
    let first = parse_response(&respond(&first_bytes).unwrap()).unwrap();
    let first_result = first.result.unwrap();
    assert_eq!(first_result.find.items.len(), 1);
    assert!(!first_result.find.complete);
    find.cursor = first_result.find.next;
    let second_nested = inspection_request(project(), find).unwrap();
    let second_bytes = encoded(request(second_nested));
    let second = parse_response(&respond(&second_bytes).unwrap()).unwrap();
    let second_result = second.result.unwrap();
    assert_eq!(second_result.find.items.len(), 1);
    assert!(second_result.find.complete);
}

#[test]
fn nested_refusal_is_bounded_and_atomic() {
    let mut nested = nested("Caf");
    nested.request_digest = "0".repeat(64);
    let bytes = encoded(request(nested));
    let response = parse_response(&respond(&bytes).unwrap()).unwrap();
    assert_eq!(response.status, Status::Refused);
    assert!(response.result.is_none());
    assert_eq!(
        response.fault.as_ref().unwrap().code,
        "inspection_request_mismatch"
    );
    assert_eq!(response.request_digest, Some("0".repeat(64)));
    validate_response(&bytes, &response).unwrap();
}

#[test]
fn strict_outer_machine_forms_refuse() {
    let nested = nested("Caf");
    let valid = serde_json::to_value(request(nested.clone())).unwrap();
    let mut unknown = valid.clone();
    unknown["extra"] = json!(false);
    let mut unsupported_profile = valid.clone();
    unsupported_profile["profile"] = json!("other");
    for bytes in [
        br#"{"#.to_vec(),
        br#"{}{}"#.to_vec(),
        serde_json::to_vec(&unknown).unwrap(),
        serde_json::to_vec(&unsupported_profile).unwrap(),
        format!(
            "{{\"profile\":\"{REQUEST_PROFILE}\",\"profile\":\"{REQUEST_PROFILE}\",\"operation\":\"semantic_inspect\",\"request\":{}}}",
            serde_json::to_string(&nested).unwrap()
        )
        .into_bytes(),
        format!(
            "{{\"profile\":\"{REQUEST_PROFILE}\",\"operation\":\"other\",\"request\":{}}}",
            serde_json::to_string(&nested).unwrap()
        )
        .into_bytes(),
    ] {
        let response = parse_response(&respond(&bytes).unwrap()).unwrap();
        assert_eq!(response.status, Status::Refused);
        assert!(response.result.is_none());
        assert!(response.fault.is_some());
        validate_response(&bytes, &response).unwrap();
    }
}

#[test]
fn raw_request_bound_refuses_without_outer_parse() {
    let bytes = vec![b' '; MAX_WIRE_REQUEST_BYTES + 1];
    let response = parse_response(&respond(&bytes).unwrap()).unwrap();
    assert_eq!(response.status, Status::Refused);
    assert_eq!(response.fault.unwrap().code, "wire_request_limit");
}

#[test]
fn response_shape_digest_and_substitution_attacks_refuse() {
    let bytes = encoded(request(nested("Caf")));
    let response_bytes = respond(&bytes).unwrap();
    let response = parse_response(&response_bytes).unwrap();

    let mut both = response.clone();
    both.fault = Some(cantor_sop_inspect_wire::WireFault {
        code: "forged".to_owned(),
        message: "forged".to_owned(),
    });
    assert_eq!(
        validate_response(&bytes, &both).unwrap_err().code,
        "wire_response_mismatch"
    );

    let mut digest = response.clone();
    digest.response_digest = "0".repeat(64);
    assert_eq!(
        validate_response(&bytes, &digest).unwrap_err().code,
        "wire_response_mismatch"
    );

    let other_bytes = encoded(request(nested("Absent")));
    assert_eq!(
        validate_response(&other_bytes, &response).unwrap_err().code,
        "wire_response_mismatch"
    );
}

#[test]
fn response_parser_rejects_unknown_trailing_duplicate_and_invalid_exclusivity() {
    let bytes = encoded(request(nested("Caf")));
    let response_bytes = respond(&bytes).unwrap();
    let mut value: Value = serde_json::from_slice(&response_bytes).unwrap();
    value["extra"] = json!(false);
    assert!(parse_response(&serde_json::to_vec(&value).unwrap()).is_err());

    let mut trailing = response_bytes.clone();
    trailing.extend_from_slice(b"{}");
    assert!(parse_response(&trailing).is_err());

    let text = String::from_utf8(response_bytes).unwrap();
    let duplicate = text.replacen(
        &format!("\"profile\":\"{RESPONSE_PROFILE}\""),
        &format!("\"profile\":\"{RESPONSE_PROFILE}\",\"profile\":\"{RESPONSE_PROFILE}\""),
        1,
    );
    assert!(parse_response(duplicate.as_bytes()).is_err());

    let mut exclusive: Value = serde_json::from_str(&text).unwrap();
    exclusive["result"] = Value::Null;
    assert!(parse_response(&serde_json::to_vec(&exclusive).unwrap()).is_err());
}

#[test]
fn fixed_operation_is_semantic_inspect() {
    let wire = request(nested("Caf"));
    assert_eq!(wire.operation, Operation::SemanticInspect);
}
