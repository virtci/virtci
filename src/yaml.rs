// Copyright (C) 2026 gabkhanfig
// SPDX-License-Identifier: GPL-2.0-only

use crate::run::MAX_TIMEOUT;
use serde::Deserialize;
use std::collections::HashMap;

pub type Workflow = HashMap<String, Job>;

#[derive(Debug, Clone, Deserialize)]
pub struct Job {
    pub image: String,
    pub cpus: Option<u32>,
    pub memory: Option<String>,
    #[serde(default)]
    pub host_env: Vec<String>,
    pub steps: Vec<Step>,
}

#[derive(Debug, Clone, Deserialize)]
pub struct Step {
    pub name: Option<String>,
    pub run: Option<String>,
    pub copy: Option<CopySpec>,
    pub restart: Option<RestartSpec>,
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
    #[serde(default)]
    pub crlf: bool,
    #[serde(default)]
    pub no_mkdir: bool,
    #[serde(default)]
    pub allow_empty: bool,
}

#[derive(Debug, Clone, Default, Deserialize)]
pub struct RestartSpec {
    /// `None` preserves the VM's current offline state.
    pub offline: Option<bool>,
    pub cpus: Option<u32>,
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

pub fn parse_workflow(contents: &str) -> Result<Workflow, serde_yaml_ng::Error> {
    serde_yaml_ng::from_str(contents)
}

pub fn parse_timeout_seconds(s: &str) -> u64 {
    let s = s.trim();
    if s.is_empty() {
        return MAX_TIMEOUT;
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

    num.parse::<u64>().ok().map_or(MAX_TIMEOUT, |n| n * unit)
}
