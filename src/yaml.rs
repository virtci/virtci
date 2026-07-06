// Copyright (C) 2026 gabkhanfig
// SPDX-License-Identifier: GPL-2.0-only

use crate::run::MAX_TIMEOUT;
use serde::Deserialize;
use serde::de::{self, Deserializer};
use std::collections::HashMap;

/// Coerce a YAML scalar (string, number, or bool) into a `String`.
fn scalar_to_string<E: de::Error>(value: serde_yaml_ng::Value, what: &str) -> Result<String, E> {
    match value {
        serde_yaml_ng::Value::String(s) => Ok(s),
        serde_yaml_ng::Value::Bool(b) => Ok(b.to_string()),
        serde_yaml_ng::Value::Number(n) => Ok(n.to_string()),
        serde_yaml_ng::Value::Null
        | serde_yaml_ng::Value::Sequence(_)
        | serde_yaml_ng::Value::Mapping(_)
        | serde_yaml_ng::Value::Tagged(_) => {
            Err(de::Error::custom(format!("{what} must be a scalar value")))
        }
    }
}

/// Deserialize an optional `String` field, coercing scalar numbers/bools.
fn de_opt_scalar_string<'de, D>(deserializer: D) -> Result<Option<String>, D::Error>
where
    D: Deserializer<'de>,
{
    let value = Option::<serde_yaml_ng::Value>::deserialize(deserializer)?;
    match value {
        None | Some(serde_yaml_ng::Value::Null) => Ok(None),
        Some(v) => Ok(Some(scalar_to_string(v, "value")?)),
    }
}

/// Deserialize a `HashMap<String, String>`, coercing scalar number/bool values.
fn de_scalar_string_map<'de, D>(deserializer: D) -> Result<HashMap<String, String>, D::Error>
where
    D: Deserializer<'de>,
{
    let raw = HashMap::<String, serde_yaml_ng::Value>::deserialize(deserializer)?;
    raw.into_iter()
        .map(|(k, v)| {
            let s = scalar_to_string(v, &format!("env value for `{k}`"))?;
            Ok((k, s))
        })
        .collect()
}

pub type Workflow = HashMap<String, Job>;

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Job {
    pub image: String,
    pub cpus: Option<u32>,
    #[serde(default, deserialize_with = "de_opt_scalar_string")]
    pub memory: Option<String>,
    #[serde(default)]
    pub host_env: Vec<String>,
    #[serde(default)]
    pub cache: Option<Cache>,
    pub steps: Vec<Step>,
}

/// User defined things to check if changed to cause a workflow cache to be considered invalid for
/// this workflow run.
/// There are some implicit things that are not user specifiy-able:
/// - Backing image chain modified
/// - Workflow YAML changed
/// - TTL (Cache has lived long enough)
/// - Cache namespace
/// - Storage limits
#[derive(Debug, Clone, Default, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Cache {
    /// Invalidate if a specific list of files has their contents changed.
    #[serde(default)]
    pub files_modified: Vec<String>,
    /// Invalidate if the list of files in the list of directories changed, for instance adding a
    /// new C++ source.
    #[serde(default)]
    pub files_list: Vec<String>,
    /// Invalidate if the hash of any of the environment variables provided has changed.
    #[serde(default)]
    pub env: Vec<String>,
    /// If this workflow writes a cache, sets its TTL to this value. No post-fix defaults to
    /// integer as days, but can be post-fixed.
    ///
    /// - `S`/`s` = seconds
    /// - `M`/`m` = minutes
    /// - `H`/`h` = hours
    /// - `D`/`d` = days
    #[serde(default)]
    pub max_age: Option<String>,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Step {
    pub name: Option<String>,
    pub run: Option<String>,
    pub copy: Option<CopySpec>,
    pub restart: Option<RestartSpec>,
    pub workdir: Option<String>,
    pub timeout: Option<String>,
    #[serde(default, deserialize_with = "de_scalar_string_map")]
    pub env: HashMap<String, String>,
    #[serde(default)]
    pub continue_on_error: bool,
    /// Don't bother running this step if running from a cached workflow.
    #[serde(default)]
    pub skip_if_cached: bool,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CopySpec {
    pub from: String,
    pub to: String,
    #[serde(default)]
    pub exclude: Vec<String>,
    #[serde(default)]
    pub crlf: bool,
    #[serde(default)]
    pub no_mkdir: bool,
    #[serde(default)]
    pub allow_empty: bool,
}

#[derive(Debug, Clone, Default, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RestartSpec {
    /// `None` preserves the VM's current offline state.
    pub offline: Option<bool>,
    pub cpus: Option<u32>,
    #[serde(default, deserialize_with = "de_opt_scalar_string")]
    pub memory: Option<String>,
}

#[derive(Debug, Clone, Default)]
pub struct ResolvedRestart {
    pub offline: Option<bool>,
    pub cpus: Option<u32>,
    pub memory_mb: Option<u64>,
}

impl Step {
    pub fn validate(&self) -> Result<StepKind, &'static str> {
        match (&self.run, &self.copy, &self.restart) {
            (Some(cmd), None, None) => Ok(StepKind::Run(cmd.clone())),
            (None, Some(copy), None) => Ok(StepKind::Copy(copy.clone())),
            (None, None, Some(restart)) => Ok(StepKind::Restart(restart.clone())),
            (None, None, None) => Err("step must have one of: run, copy, restart"),
            _ => Err("step must have only one of: run, copy, restart"),
        }
    }
}

#[derive(Debug, Clone)]
pub enum StepKind {
    Run(String),
    Copy(CopySpec),
    Restart(RestartSpec),
}

pub fn validate_copy_direction(from: &str, to: &str) -> Result<(), &'static str> {
    match (from.starts_with("vm:"), to.starts_with("vm:")) {
        (true, true) => Err("copy cannot have both `from` and `to` prefixed with `vm:`"),
        (false, false) => Err("copy requires exactly one of `from`/`to` to be prefixed with `vm:`"),
        _ => Ok(()),
    }
}

pub fn parse_workflow(contents: &str) -> Result<Workflow, serde_yaml_ng::Error> {
    serde_yaml_ng::from_str(contents)
}

pub fn parse_timeout_seconds(s: &str) -> u64 {
    try_parse_timeout_seconds(s).unwrap_or(MAX_TIMEOUT)
}

pub fn try_parse_timeout_seconds(s: &str) -> Option<u64> {
    let s = s.trim();
    if s.is_empty() {
        return Some(MAX_TIMEOUT);
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

    num.parse::<u64>().ok().map(|n| n * unit)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn coerces_numeric_and_bool_scalars_to_strings() {
        let yaml = r#"
job:
  image: ubuntu
  memory: 6144
  steps:
    - run: echo hi
      env:
        PORT: 8080
        DEBUG: true
        NAME: release
      timeout: 5M
"#;
        let wf = parse_workflow(yaml).expect("should parse");
        let job = &wf["job"];
        assert_eq!(job.memory.as_deref(), Some("6144"));
        let env = &job.steps[0].env;
        assert_eq!(env["PORT"], "8080");
        assert_eq!(env["DEBUG"], "true");
        assert_eq!(env["NAME"], "release");
    }

    #[test]
    fn coerces_restart_memory_scalar() {
        let yaml = r#"
job:
  image: ubuntu
  steps:
    - restart:
        memory: 12288
"#;
        let wf = parse_workflow(yaml).expect("should parse");
        let restart = wf["job"].steps[0].restart.as_ref().unwrap();
        assert_eq!(restart.memory.as_deref(), Some("12288"));
    }

    #[test]
    fn rejects_non_scalar_env_value() {
        let yaml = r#"
job:
  image: ubuntu
  steps:
    - run: echo hi
      env:
        BAD: [1, 2, 3]
"#;
        assert!(parse_workflow(yaml).is_err());
    }
}
