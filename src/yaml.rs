use crate::job::{self, MAX_TIMEOUT};
use serde::Deserialize;
use std::collections::HashMap;

pub type Workflow = HashMap<String, Job>;

// https://www.linux-kvm.org/downloads/lersek/ovmf-whitepaper-c770f8c.txt
// https://github.com/tianocore/tianocore.github.io/wiki/How-to-run-OVMF
// The UEFI firmware can be split into two sections
#[derive(Debug, Clone, Deserialize)]
pub struct UefiSplit {
    pub code: String,
    pub vars: String,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(untagged)]
pub enum UefiFirmware {
    Boolean(bool),
    Path(String),
    Split(UefiSplit),
}

#[derive(Debug, Clone, Deserialize)]
pub struct Job {
    pub image: Option<String>,
    pub arch: Option<String>,
    pub cpus: Option<u32>,
    pub memory: Option<String>,
    pub user: Option<String>,
    pub pass: Option<String>,
    pub key: Option<String>,
    pub port: Option<u16>,
    pub uefi: Option<UefiFirmware>,
    pub cpu_model: Option<String>,
    pub additional_drives: Option<Vec<String>>,
    pub additional_devices: Option<Vec<String>>,
    pub qemu_args: Option<Vec<String>>,
    pub tpm: Option<bool>,
    pub steps: Vec<Step>,
}

#[derive(Debug, Clone, Deserialize)]
pub struct Step {
    pub name: Option<String>,
    pub run: Option<String>,
    pub copy: Option<CopySpec>,
    pub offline: Option<bool>,
    pub workdir: Option<String>,
    pub timeout: Option<String>,
    #[serde(default)]
    pub env: HashMap<String, String>,
    #[serde(default)]
    pub continue_on_error: bool,
}

#[derive(Debug, Clone, Deserialize)]
pub struct CopySpec {
    pub from: String,
    pub to: String,
    #[serde(default)]
    pub exclude: Vec<String>,
}

impl Step {
    pub fn validate(&self) -> Result<StepKind, &'static str> {
        match (&self.run, &self.copy, &self.offline) {
            (Some(cmd), None, None) => Ok(StepKind::Run(cmd.clone())),
            (None, Some(copy), None) => Ok(StepKind::Copy(copy.clone())),
            (None, None, Some(offline)) => Ok(StepKind::Offline(*offline)),
            (None, None, None) => Err("step must have one of: run, copy, offline"),
            _ => Err("step must have only one of: run, copy, offline"),
        }
    }
}

#[derive(Debug, Clone)]
pub enum StepKind {
    Run(String),
    Copy(CopySpec),
    Offline(bool),
}

pub fn parse_workflow(contents: &str) -> Result<Workflow, serde_yml::Error> {
    return serde_yml::from_str(contents);
}

pub fn parse_timeout_seconds(s: &str) -> u64 {
    let s = s.trim();
    if s.is_empty() {
        return job::MAX_TIMEOUT;
    }

    let (num, unit) = if s.ends_with('S') || s.ends_with('s') {
        (&s[..s.len() - 1], 1u64)
    } else if s.ends_with('M') || s.ends_with('m') {
        (&s[..s.len() - 1], 60u64)
    } else if s.ends_with('H') || s.ends_with('h') {
        (&s[..s.len() - 1], 3600u64)
    } else {
        // assume seconds
        (s, 1u64)
    };

    return num
        .parse::<u64>()
        .ok()
        .map(|n| n * unit)
        .unwrap_or(MAX_TIMEOUT);
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_simple_workflow() {
        let yaml = r#"
test-job:
  image: ~/test.qcow2
  user: root
  pass: secret
  steps:
    - name: Hello
      run: echo hello
"#;
        let workflow = parse_workflow(yaml).unwrap();
        assert!(workflow.contains_key("test-job"));
        let job = &workflow["test-job"];
        assert_eq!(job.image, Some("~/test.qcow2".to_string()));
        assert_eq!(job.steps.len(), 1);
    }

    #[test]
    fn test_parse_copy_step() {
        let yaml = r#"
job:
  steps:
    - name: Upload
      copy:
        from: ./local
        to: vm:/remote
"#;
        let workflow = parse_workflow(yaml).unwrap();
        let step = &workflow["job"].steps[0];
        assert!(step.copy.is_some());
        let copy = step.copy.as_ref().unwrap();
        assert_eq!(copy.from, "./local");
        assert_eq!(copy.to, "vm:/remote");
    }

    #[test]
    fn test_parse_offline_step() {
        let yaml = r#"
job:
  steps:
    - offline: true
    - run: make build
    - offline: false
"#;
        let workflow = parse_workflow(yaml).unwrap();
        assert_eq!(workflow["job"].steps.len(), 3);
        assert_eq!(workflow["job"].steps[0].offline, Some(true));
        assert_eq!(workflow["job"].steps[2].offline, Some(false));
    }
}
