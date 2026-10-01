mod support;
use cantor_sop_inspect_mcp::*;
use cantor_sop_semantics::digest;
use serde_json::json;

#[test]
fn eight_goldens_preserve_exact_five_outputs_and_three_adapter_refusals() {
    let server = InspectionMcpServer::default();
    for fixture in support::fixtures() {
        let reply = server.inspect_arguments(Some(support::arguments(&fixture.request)));
        support::check_fixture(&fixture, &reply);
        assert_eq!(reply.request_bytes, Some(fixture.request.len()));
        assert_eq!(
            reply.request_sha256,
            Some(digest::bytes(fixture.request.as_bytes()))
        );
        if let Some(output) = &reply.wire_response_json {
            assert_eq!(reply.response_bytes, Some(output.len()));
            assert_eq!(
                reply.response_sha256,
                Some(digest::bytes(output.as_bytes()))
            );
        }
    }
}
#[test]
fn malformed_argument_shapes_refuse_without_echoing_secrets() {
    let server = InspectionMcpServer::default();
    for value in [
        json!({}),
        json!({"other":"secret"}),
        json!({"wire_request_json":0}),
        json!({"wire_request_json":null}),
        json!({"wire_request_json":"{}","future":"secret"}),
    ] {
        let reply = server.inspect_arguments(Some(value.as_object().unwrap().clone()));
        assert_eq!(reply.fault_code, Some(AdapterFault::Arguments));
        assert!(reply.request_bytes.is_none());
        assert!(!serde_json::to_string(&reply).unwrap().contains("secret"));
    }
    assert_eq!(
        server.inspect_arguments(None).fault_code,
        Some(AdapterFault::Arguments)
    );
}
#[test]
fn raw_request_exact_limit_and_plus_one_have_distinct_fixed_refusals() {
    let server = InspectionMcpServer::default();
    let fixture = support::fixtures().remove(0);
    for count in [MAX_REQUEST_BYTES, MAX_REQUEST_BYTES + 1] {
        let mut input = fixture.request.clone();
        input.push_str(&" ".repeat(count - input.len()));
        let reply = server.inspect_arguments(Some(support::arguments(&input)));
        assert_eq!(
            reply.fault_code,
            if count == MAX_REQUEST_BYTES {
                None
            } else {
                Some(AdapterFault::RequestLimit)
            }
        );
        assert_eq!(reply.request_sha256.is_some(), count == MAX_REQUEST_BYTES);
        assert_eq!(reply.request_bytes, Some(count));
        if count == MAX_REQUEST_BYTES {
            assert_eq!(reply.wire_response_json, Some(fixture.stdout.clone()));
        }
    }
}
#[test]
fn original_nested_wire_duplicate_unknown_trailing_and_profile_refuse() {
    let request = support::fixtures().remove(0).request;
    let mut unknown: serde_json::Value = serde_json::from_str(&request).unwrap();
    unknown["future"] = json!(true);
    let mut profile = unknown.clone();
    profile.as_object_mut().unwrap().remove("future");
    profile["profile"] = json!("foreign");
    for input in [
        format!("{{\"profile\":\"duplicate\",{}", &request[1..]),
        format!("{request} {{}}"),
        unknown.to_string(),
        profile.to_string(),
        String::new(),
    ] {
        let reply =
            InspectionMcpServer::default().inspect_arguments(Some(support::arguments(&input)));
        assert_eq!(reply.fault_code, Some(AdapterFault::WireInput));
        assert!(reply.wire_response_json.is_none());
    }
}
#[test]
fn structured_content_is_authoritative_with_fixed_summary_and_error_flag() {
    for fixture in support::fixtures() {
        let result = InspectionMcpServer::default()
            .execute_tool_arguments(Some(support::arguments(&fixture.request)));
        let reply = support::reply(result.structured_content.unwrap());
        assert_eq!(
            result.is_error,
            Some(reply.outcome != Outcome::InspectionSucceeded)
        );
        assert_eq!(result.content.len(), 1);
        support::check_fixture(&fixture, &reply);
    }
}
#[test]
fn reply_unknown_duplicate_and_trailing_fields_are_not_accepted() {
    let reply = InspectionMcpServer::default().inspect_arguments(None);
    let bytes = serde_json::to_string(&reply).unwrap();
    assert!(
        serde_json::from_str::<AdapterReply>(&format!("{{\"profile\":\"foreign\",{}", &bytes[1..]))
            .is_err()
    );
    let mut value = serde_json::to_value(reply).unwrap();
    value["future_authority"] = json!(true);
    assert!(serde_json::from_value::<AdapterReply>(value).is_err());
    assert!(serde_json::from_str::<AdapterReply>(&format!("{bytes} {{}}")).is_err());
}
