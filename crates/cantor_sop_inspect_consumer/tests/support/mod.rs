use cantor_sop_inspect::{InspectionRequest, request as inspect_request};
use cantor_sop_inspect_consumer::{ConsumerContract, Receipt, Transcript, contract, verify};
use cantor_sop_inspect_wire::{parse_response, request as wire_request, respond};
use cantor_sop_project::{PROJECT_PROFILE, SuppliedFile, SuppliedPackage, SuppliedProject};
use cantor_sop_query::FindRequest;
use serde::{Deserialize, Serialize};

pub const BUNDLE_PROFILE: &str = "cantor-semantic-inspection-consumer-fixtures/0.1";
pub const SOURCE: &str = "kind [kind:fact] \"Fact\" { meaning \"An observation\" }\ncontext [context:any] { scopes () purposes () perspectives () }\nterm [site:alpha] \"Café alpha\" { kind [kind:fact] context [context:any] meaning \"Observed α\" }\nterm [site:beta] \"Café beta\" { kind [kind:fact] context [context:any] meaning \"Observed β\" }\n";

#[derive(Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct FixtureBundle {
    pub profile: String,
    pub contract: ConsumerContract,
    pub cases: Vec<Fixture>,
}

#[derive(Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Fixture {
    pub id: String,
    pub request: String,
    pub stdout: String,
    pub stderr: String,
    pub exit_code: i32,
    pub receipt: Receipt,
}

pub fn nested(find: FindRequest) -> InspectionRequest {
    inspect_request(
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
        },
        find,
    )
    .unwrap()
}

pub fn encode(request: InspectionRequest) -> Vec<u8> {
    serde_json::to_vec(&wire_request(request)).unwrap()
}

pub fn success_input() -> Vec<u8> {
    encode(nested(FindRequest::prefix("Café")))
}

fn fixture(id: &str, request: &[u8], stdout: &[u8], stderr: &[u8], exit_code: i32) -> Fixture {
    Fixture {
        id: id.to_owned(),
        request: String::from_utf8(request.to_vec()).unwrap(),
        stdout: String::from_utf8(stdout.to_vec()).unwrap(),
        stderr: String::from_utf8(stderr.to_vec()).unwrap(),
        exit_code,
        receipt: verify(
            request,
            Transcript {
                exit_code,
                stdout,
                stderr,
            },
        )
        .unwrap(),
    }
}

fn wire_fixture(id: &str, request: Vec<u8>) -> Fixture {
    let output = respond(&request).unwrap();
    fixture(id, &request, &output, b"", 0)
}

pub fn bundle() -> FixtureBundle {
    let mut page_query = FindRequest::prefix("Café");
    page_query.limit = 1;
    let page_one = encode(nested(page_query.clone()));
    page_query.cursor = parse_response(&respond(&page_one).unwrap())
        .unwrap()
        .result
        .unwrap()
        .find
        .next;
    let page_two = encode(nested(page_query));
    let mut refused = nested(FindRequest::prefix("Café"));
    refused.request_digest = "0".repeat(64);
    let mut unknown: serde_json::Value = serde_json::from_slice(&success_input()).unwrap();
    unknown["future_effect"] = serde_json::json!("must not execute");
    let fault = cantor_sop_inspect_consumer::PUBLIC_HOST_FAULT;
    FixtureBundle {
        profile: BUNDLE_PROFILE.to_owned(),
        contract: contract().unwrap(),
        cases: vec![
            wire_fixture("unicode_success", success_input()),
            wire_fixture("empty_page", encode(nested(FindRequest::prefix("Absent")))),
            wire_fixture("page_one", page_one),
            wire_fixture("page_two", page_two),
            wire_fixture("nested_refusal", encode(refused)),
            fixture("malformed_outer", b"{", b"", fault, 2),
            fixture(
                "unknown_outer",
                &serde_json::to_vec(&unknown).unwrap(),
                b"",
                fault,
                2,
            ),
            fixture("empty_outer", b"", b"", fault, 2),
        ],
    }
}

pub fn bundle_bytes() -> Vec<u8> {
    let mut bytes = serde_json::to_vec_pretty(&bundle()).unwrap();
    bytes.push(b'\n');
    bytes
}
