// Copyright (C) 2026 gabkhanfig
// SPDX-License-Identifier: GPL-2.0-only

use crate::global_paths::VciGlobalPaths;
use crate::yaml::{self, Job, Step, StepKind};
use serde_yaml_ng::{Mapping, Value};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Severity {
    Error,
    Warning,
}

#[derive(Debug, Clone)]
pub struct Diagnostic {
    pub severity: Severity,
    /// A path into the document, e.g. `ubuntu-x64.steps[2]`.
    pub location: String,
    pub message: String,
}

impl Diagnostic {
    fn error(location: impl Into<String>, message: impl Into<String>) -> Self {
        Self {
            severity: Severity::Error,
            location: location.into(),
            message: message.into(),
        }
    }

    fn warning(location: impl Into<String>, message: impl Into<String>) -> Self {
        Self {
            severity: Severity::Warning,
            location: location.into(),
            message: message.into(),
        }
    }
}

/// `true` if any diagnostic is an error, in which the workflow definitely cannot run.
pub fn has_errors(diags: &[Diagnostic]) -> bool {
    diags.iter().any(|d| d.severity == Severity::Error)
}

/// Print diagnostics to stderr, colored by severity, followed by a summary line.
pub fn print_diagnostics(diags: &[Diagnostic]) {
    use colored::Colorize;

    for d in diags {
        let label = match d.severity {
            Severity::Error => "error:".red().bold(),
            Severity::Warning => "warning:".yellow().bold(),
        };
        eprintln!(
            "{label} {} {}",
            format!("[{}]", d.location).dimmed(),
            d.message
        );
    }

    let errors = diags
        .iter()
        .filter(|d| d.severity == Severity::Error)
        .count();
    let warnings = diags.len() - errors;
    if errors == 0 && warnings == 0 {
        eprintln!("{}", "Workflow is valid.".green().bold());
    } else {
        eprintln!(
            "{}",
            format!("{errors} error(s), {warnings} warning(s)").bold()
        );
    }
}

/// Validate a workflow's YAML source, returning every problem found to the best of our ability.
/// `paths` is used only to check whether referenced images exist on this host.
/// A missing image is a warning, never an error, since the run may target a remote server.
pub fn validate_workflow_str(contents: &str, paths: &VciGlobalPaths) -> Vec<Diagnostic> {
    let mut diags = Vec::new();

    // On Windows hosts, CRLF line endings are common and usually fine. This is
    // a heads-up, not an error: copy steps can set `crlf: true` to convert line
    // endings to/from the VM automatically.
    #[cfg(target_os = "windows")]
    if contents.contains("\r\n") {
        diags.push(Diagnostic::warning(
            "<file>",
            "workflow uses CRLF line endings; copy steps can set `crlf: true` to convert \
             line endings to/from the VM automatically",
        ));
    }

    // If the document is not even well-formed YAML, that's the only thing we
    // can report; deeper validation is impossible.
    let root: Value = match serde_yaml_ng::from_str(contents) {
        Ok(v) => v,
        Err(e) => {
            let location = e.location().map_or_else(
                || "<file>".to_string(),
                |l| format!("line {}:{}", l.line(), l.column()),
            );
            diags.push(Diagnostic::error(
                location,
                format!("YAML syntax error: {e}"),
            ));
            return diags;
        }
    };

    let Value::Mapping(jobs) = root else {
        diags.push(Diagnostic::error(
            "<root>",
            "workflow must be a mapping of job names to job definitions",
        ));
        return diags;
    };

    if jobs.is_empty() {
        diags.push(Diagnostic::error("<root>", "workflow defines no jobs"));
        return diags;
    }

    for (name_v, job_v) in &jobs {
        let Some(name) = name_v.as_str() else {
            diags.push(Diagnostic::error("<root>", "job name must be a string"));
            continue;
        };
        validate_job(name, job_v, paths, &mut diags);
    }

    diags
}

fn validate_job(name: &str, job_v: &Value, paths: &VciGlobalPaths, diags: &mut Vec<Diagnostic>) {
    if let Err(e) = super::validate_run_name(name) {
        diags.push(Diagnostic::error(name, e.to_string()));
    }

    let Value::Mapping(map) = job_v else {
        diags.push(Diagnostic::error(name, "job must be a mapping"));
        return;
    };

    let mut shell = map.clone();
    shell.insert("steps".into(), Value::Sequence(Vec::new()));
    if let Err(e) = serde_yaml_ng::from_value::<Job>(Value::Mapping(shell)) {
        diags.push(Diagnostic::error(name, e.to_string()));
    }

    validate_job_semantics(name, map, paths, diags);

    match map.get("steps") {
        None => diags.push(Diagnostic::error(name, "missing required field `steps`")),
        Some(Value::Sequence(seq)) if seq.is_empty() => diags.push(Diagnostic::error(
            format!("{name}.steps"),
            "must contain at least one step",
        )),
        Some(Value::Sequence(seq)) => {
            for (i, step_v) in seq.iter().enumerate() {
                validate_step(&format!("{name}.steps[{i}]"), step_v, diags);
            }
        }
        Some(_) => diags.push(Diagnostic::error(
            format!("{name}.steps"),
            "must be a sequence",
        )),
    }
}

fn validate_job_semantics(
    name: &str,
    map: &Mapping,
    paths: &VciGlobalPaths,
    diags: &mut Vec<Diagnostic>,
) {
    if matches!(map.get("cpus"), Some(Value::Number(n)) if n.as_u64() == Some(0)) {
        diags.push(Diagnostic::error(
            format!("{name}.cpus"),
            "must be a positive, non-zero integer",
        ));
    }

    if let Some(mem) = scalar_string(map.get("memory")) {
        check_memory(&format!("{name}.memory"), &mem, diags);
    }

    match map.get("image") {
        Some(Value::String(img)) if img.trim().is_empty() => diags.push(Diagnostic::error(
            format!("{name}.image"),
            "must not be empty",
        )),
        Some(Value::String(img)) if paths.resolve_image_home(img).is_none() => {
            diags.push(Diagnostic::warning(
                format!("{name}.image"),
                format!(
                    "image `{img}` not found on this host (run `virtci list`, may exist on a remote runner)."
                ),
            ));
        }
        _ => {}
    }
}

/// A scalar (string, number, or bool) rendered as a string, mirroring the coercion in
/// [`crate::yaml`]. Returns `None` for absent, null, or non-scalar values.
fn scalar_string(v: Option<&Value>) -> Option<String> {
    match v {
        Some(Value::String(s)) => Some(s.clone()),
        Some(Value::Number(n)) => Some(n.to_string()),
        Some(Value::Bool(b)) => Some(b.to_string()),
        _ => None,
    }
}

fn validate_step(loc: &str, step_v: &Value, diags: &mut Vec<Diagnostic>) {
    // serde handles structure (types, unknown fields). Anything beyond that is
    // a semantic rule it cannot express, layered on below.
    let step = match serde_yaml_ng::from_value::<Step>(step_v.clone()) {
        Ok(step) => step,
        Err(e) => {
            diags.push(Diagnostic::error(loc, e.to_string()));
            return;
        }
    };

    // Exactly one of run/copy/restart (each is independently optional, so serde
    // can't enforce it), plus the copy `vm:` direction rule.
    match step.validate() {
        Ok(StepKind::Copy(spec)) => {
            if let Err(e) = yaml::validate_copy_direction(&spec.from, &spec.to) {
                diags.push(Diagnostic::error(format!("{loc}.copy"), e));
            }

            // Ignore files only work from host->VM. VM->host ignore in a copy step is malformed.
            let is_vm_to_host = spec.from.starts_with("vm:");
            let requests_ignore = matches!(
                spec.ignore_file,
                Some(yaml::IgnoreFileField::Str(_) | yaml::IgnoreFileField::Bool(true))
            );
            if is_vm_to_host && requests_ignore {
                diags.push(Diagnostic::error(
                    format!("{loc}.copy.ignore_file"),
                    "ignore_file only applies when copying from the host into the VM; \
                     remove it from this vm:-> host copy"
                        .to_string(),
                ));
            }

            if let Some(yaml::IgnoreFileField::Str(s)) = &spec.ignore_file
                && s.trim().is_empty()
            {
                diags.push(Diagnostic::error(
                    format!("{loc}.copy.ignore_file"),
                    "ignore_file must not be empty".to_string(),
                ));
            }
        }
        Ok(StepKind::Restart(r)) => {
            if r.cpus == Some(0) {
                diags.push(Diagnostic::error(
                    format!("{loc}.restart.cpus"),
                    "must be a positive, non-zero integer",
                ));
            }
            if let Some(mem) = &r.memory {
                check_memory(&format!("{loc}.restart.memory"), mem, diags);
            }
        }
        Ok(StepKind::Run(_)) => {}
        Err(msg) => diags.push(Diagnostic::error(loc, msg)),
    }

    // A timeout that won't parse would silently fall back to the default at
    // runtime, which is surprising; treat it as an error.
    if let Some(t) = &step.timeout
        && yaml::try_parse_timeout_seconds(t).is_err()
    {
        diags.push(Diagnostic::error(
            format!("{loc}.timeout"),
            format!("`{t}` is not a valid timeout (e.g. `30s`, `5M`, `2H`)"),
        ));
    }
}

/// A memory string (`6G`, `512M`, `6144`) must parse to a non-zero size.
fn check_memory(loc: &str, mem: &str, diags: &mut Vec<Diagnostic>) {
    match crate::cli::parse_mem_mb(mem) {
        Some(mb) if mb > 0 => {}
        Some(_) => diags.push(Diagnostic::error(loc, "must be greater than zero")),
        None => diags.push(Diagnostic::error(
            loc,
            format!("`{mem}` is not a valid memory size. Should be like `6G`, `512M`, `6144`."),
        )),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn validate(yaml: &str) -> Vec<Diagnostic> {
        validate_workflow_str(yaml, &VciGlobalPaths::default())
    }

    fn error_blob(diags: &[Diagnostic]) -> String {
        diags
            .iter()
            .filter(|d| d.severity == Severity::Error)
            .map(|d| format!("{} | {}\n", d.location, d.message))
            .collect()
    }

    #[test]
    fn valid_workflow_has_no_errors() {
        let yaml = r"
ubuntu-x64:
  image: ubuntu-server-x64
  cpus: 2
  memory: 6G
  steps:
    - run: echo hi
    - restart: {}
";
        assert!(!has_errors(&validate(yaml)), "{:#?}", validate(yaml));
    }

    #[test]
    fn syntax_error_reports_location_and_stops() {
        let diags = validate("job:\n  image: ubuntu\n   bad: indent\n");
        assert_eq!(
            diags
                .iter()
                .filter(|d| d.severity == Severity::Error)
                .count(),
            1
        );
        assert!(diags[0].message.contains("YAML syntax error"));
    }

    #[test]
    fn collects_errors_across_jobs_and_steps_in_one_pass() {
        let yaml = r"
job-a:
  cpus: 0
  memory: 6Gigs
  steps:
    - {}
job-b:
  image: ubuntu-server-x64
  banana: peel
  steps:
    - run: echo hi
      copy:
        from: ./
        to: vm:~/
";

        let blob = error_blob(&validate(yaml));
        // job-a: missing image, cpus=0, bad memory, empty step (no one-of).
        // job-b: unknown field `banana`, step with both run+copy.

        assert!(blob.contains("missing field `image`"), "{blob}");
        assert!(blob.contains("job-a.cpus"), "{blob}");
        assert!(blob.contains("6Gigs"), "{blob}");
        assert!(blob.contains("only one of"), "{blob}");
        assert!(blob.contains("banana"), "{blob}");
    }

    #[test]
    fn empty_step_reports_missing_one_of() {
        let yaml = r"
job:
  image: ubuntu-server-x64
  steps:
    - {}
";
        assert!(error_blob(&validate(yaml)).contains("one of: run, copy, restart"));
    }

    #[test]
    fn copy_without_vm_prefix_is_error() {
        let yaml = r"
job:
  image: ubuntu-server-x64
  steps:
    - copy:
        from: ./
        to: ./out
";
        assert!(error_blob(&validate(yaml)).contains("exactly one of `from`/`to`"));
    }

    #[test]
    fn copy_with_both_vm_prefix_is_error() {
        let yaml = r"
job:
  image: ubuntu-server-x64
  steps:
    - copy:
        from: vm:~/a
        to: vm:~/b
";
        assert!(error_blob(&validate(yaml)).contains("both"));
    }

    #[test]
    fn valid_copy_direction_has_no_errors() {
        let yaml = r"
job:
  image: ubuntu-server-x64
  steps:
    - copy:
        from: ./
        to: vm:~/
";
        assert!(!has_errors(&validate(yaml)));
    }

    #[test]
    fn invalid_timeout_is_an_error() {
        let yaml = r"
job:
  image: ubuntu-server-x64
  steps:
    - run: echo hi
      timeout: soon
";
        assert!(error_blob(&validate(yaml)).contains("not a valid timeout"));
    }

    #[test]
    fn valid_timeout_has_no_errors() {
        let yaml = r"
job:
  image: ubuntu-server-x64
  steps:
    - run: echo hi
      timeout: 5M
";
        assert!(!has_errors(&validate(yaml)));
    }

    #[test]
    fn invalid_restart_memory_is_an_error() {
        let yaml = r"
job:
  image: ubuntu-server-x64
  steps:
    - restart:
        memory: bad
";
        let blob = error_blob(&validate(yaml));
        assert!(blob.contains("restart.memory"), "{blob}");
        assert!(blob.contains("not a valid memory size"), "{blob}");
    }

    #[test]
    fn restart_cpus_zero_is_an_error() {
        let yaml = r"
job:
  image: ubuntu-server-x64
  steps:
    - restart:
        cpus: 0
";
        assert!(error_blob(&validate(yaml)).contains("restart.cpus"));
    }

    #[test]
    fn bool_memory_is_caught_like_the_run_would() {
        let yaml = r"
job:
  image: ubuntu-server-x64
  memory: true
  steps:
    - run: echo hi
";
        let blob = error_blob(&validate(yaml));
        assert!(blob.contains("job.memory"), "{blob}");
        assert!(blob.contains("not a valid memory size"), "{blob}");
    }

    #[test]
    fn valid_restart_has_no_errors() {
        let yaml = r"
job:
  image: ubuntu-server-x64
  steps:
    - restart:
        cpus: 4
        memory: 8G
";
        assert!(!has_errors(&validate(yaml)));
    }
}
