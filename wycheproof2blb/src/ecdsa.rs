use crate::wycheproof::{self, description_v1};
use crate::wycheproof::{case_result, description, hex_string};
use crate::TestInfo;
use serde::Deserialize;

#[derive(Debug, Deserialize)]
struct TestSuite {
    #[serde(flatten)]
    pub suite: wycheproof::Suite,
    #[serde(rename = "testGroups")]
    pub test_groups: Vec<TestGroup>,
}

#[derive(Debug, Deserialize)]
struct TestGroup {
    #[allow(dead_code)]
    #[serde(flatten)]
    pub group: wycheproof::Group,
    #[allow(dead_code)]
    #[serde(rename = "keyDer")]
    pub key_der: String,
    #[allow(dead_code)]
    #[serde(rename = "keyPem")]
    pub key_pem: String,
    pub sha: String,
    pub key: TestKey,
    pub tests: Vec<TestCase>,
}

#[derive(Debug, Deserialize)]
struct TestKey {
    curve: String,
    #[allow(dead_code)]
    #[serde(rename = "type")]
    key_type: String,
    #[serde(with = "hex_string")]
    wx: Vec<u8>,
    #[serde(with = "hex_string")]
    wy: Vec<u8>,
}

#[derive(Debug, Deserialize)]
struct TestCase {
    #[serde(flatten)]
    pub case: wycheproof::Case,
    #[serde(with = "hex_string")]
    pub msg: Vec<u8>,
    #[serde(with = "hex_string")]
    pub sig: Vec<u8>,
}

// V1 version

#[derive(Debug, Deserialize)]
struct TestSuiteV1 {
    #[serde(flatten)]
    pub suite: wycheproof::SuiteV1,
    #[serde(rename = "testGroups")]
    pub test_groups: Vec<TestGroupV1>,
}

#[derive(Debug, Deserialize)]
struct TestGroupV1 {
    #[allow(dead_code)]
    #[serde(flatten)]
    pub group: wycheproof::Group,
    #[allow(dead_code)]
    #[serde(rename = "publicKeyDer")]
    pub key_der: String,
    #[allow(dead_code)]
    #[serde(rename = "publicKeyPem")]
    pub key_pem: String,
    pub sha: String,
    #[serde(rename = "publicKey")]
    pub key: TestKeyV1,
    pub tests: Vec<TestCaseV1>,
}

#[derive(Debug, Deserialize)]
struct TestKeyV1 {
    curve: String,
    #[allow(dead_code)]
    #[serde(rename = "type")]
    key_type: String,
    #[serde(with = "hex_string")]
    wx: Vec<u8>,
    #[serde(with = "hex_string")]
    wy: Vec<u8>,
}

#[derive(Debug, Deserialize)]
struct TestCaseV1 {
    #[serde(flatten)]
    pub case: wycheproof::Case,
    #[serde(with = "hex_string")]
    pub msg: Vec<u8>,
    #[serde(with = "hex_string")]
    pub sig: Vec<u8>,
}

pub fn generator(data: &[u8], algorithm: &str, _key_size: u32) -> Vec<TestInfo> {
    let suite: TestSuite = serde_json::from_slice(data).unwrap();

    let mut infos = vec![];
    for g in &suite.test_groups {
        assert!(algorithm.starts_with(&g.key.curve));
        assert!(matches!(
            g.sha.as_str(),
            "SHA-224" | "SHA-256" | "SHA-384" | "SHA-512"
        ));
        for tc in &g.tests {
            if tc.case.result == crate::wycheproof::CaseResult::Acceptable {
                // TODO: figure out what to do with test cases that pass but which have weak params
                continue;
            }
            infos.push(TestInfo {
                data: vec![
                    g.key.wx.clone(),
                    g.key.wy.clone(),
                    tc.msg.clone(),
                    tc.sig.clone(),
                    vec![case_result(&tc.case)],
                ],
                desc: description(&suite.suite, &tc.case),
            });
        }
    }
    infos
}

pub fn generator_v1(data: &[u8], algorithm: &str, _key_size: u32) -> Vec<TestInfo> {
    let suite: TestSuiteV1 = serde_json::from_slice(data).unwrap();

    let mut infos = vec![];
    for g in &suite.test_groups {
        assert!(algorithm.starts_with(&g.key.curve));
        assert!(matches!(
            g.sha.as_str(),
            "SHA-224" | "SHA-256" | "SHA-384" | "SHA-512"
        ));
        for tc in &g.tests {
            if tc.case.result == crate::wycheproof::CaseResult::Acceptable {
                // TODO: figure out what to do with test cases that pass but which have weak params
                continue;
            }
            infos.push(TestInfo {
                data: vec![
                    g.key.wx.clone(),
                    g.key.wy.clone(),
                    tc.msg.clone(),
                    tc.sig.clone(),
                    vec![case_result(&tc.case)],
                ],
                desc: description_v1(&suite.suite, &tc.case),
            });
        }
    }
    infos
}
