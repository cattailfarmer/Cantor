use cantor_sop_inspect_mcp::{AdapterReply, InspectionMcpServer, Outcome};
use rmcp::model::JsonObject;
use serde::Deserialize;
use serde_json::{Value, json};

#[derive(Deserialize)]
pub struct Fixture {
    pub id: String,
    pub request: String,
    pub stdout: String,
    pub exit_code: i32,
}
#[derive(Deserialize)]
struct Bundle {
    cases: Vec<Fixture>,
}
pub fn fixtures() -> Vec<Fixture> {
    serde_json::from_str::<Bundle>(include_str!(
        "../../../../fixtures/semantic_inspection_consumer_handoff_p0/fixtures.json"
    ))
    .unwrap()
    .cases
}
pub fn arguments(request: &str) -> JsonObject {
    json!({"wire_request_json": request})
        .as_object()
        .unwrap()
        .clone()
}
pub fn reply(value: Value) -> AdapterReply {
    serde_json::from_value(value).unwrap()
}
pub fn check_fixture(fixture: &Fixture, response: &AdapterReply) {
    if fixture.exit_code == 0 {
        assert_eq!(
            response.wire_response_json.as_deref(),
            Some(fixture.stdout.as_str()),
            "{} exact original bytes",
            fixture.id
        );
        assert_eq!(
            response.outcome,
            if fixture.id == "nested_refusal" {
                Outcome::SemanticRefused
            } else {
                Outcome::InspectionSucceeded
            }
        );
    } else {
        assert_eq!(response.outcome, Outcome::AdapterRefused, "{}", fixture.id);
        assert!(response.wire_response_json.is_none());
    }
    assert_eq!(
        response,
        &InspectionMcpServer::default().inspect_arguments(Some(arguments(&fixture.request)))
    );
}
