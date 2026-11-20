//! Redaction of secrets from command lines before they reach disk.

use regex::Regex;

pub struct Redactor {
    rules: Vec<Regex>,
}

/// Each rule's capture group 1 is kept; the rest of the match becomes `***`.
const BUILTIN: &[&str] = &[
    // key=value / key:value for secret-ish keys (also connection strings)
    r#"(?i)(\b(?:password|passwd|pwd|secret|token|apikey|api[_-]?key|access[_-]?key|client[_-]?secret|sas|sig)\s*[=:]\s*)("[^"]*"|'[^']*'|[^\s;&"']+)"#,
    // --password VALUE, -p VALUE, /p:VALUE, /password:VALUE
    r#"(?i)((?:--?(?:password|passwd|pwd|token|secret)|/p(?:assword)?:)\s*)("[^"]*"|\S+)"#,
    // Authorization: Bearer xxx
    r#"(?i)(bearer\s+)([A-Za-z0-9._~+/=-]{8,})"#,
    // user:password@host in URLs
    r#"(?i)([a-z][a-z0-9+.-]*://[^/\s:@]+:)([^@\s/]+)(@)"#,
];

impl Redactor {
    pub fn new(extra: &[String]) -> Self {
        let mut rules: Vec<Regex> = BUILTIN.iter().map(|p| Regex::new(p).expect("builtin regex")).collect();
        for p in extra {
            match Regex::new(p) {
                Ok(r) => rules.push(r),
                Err(e) => log::warn!("ignoring invalid redact pattern {p:?}: {e}"),
            }
        }
        Self { rules }
    }

    pub fn apply(&self, s: &str) -> String {
        let mut out = s.to_string();
        for r in &self.rules {
            out = r
                .replace_all(&out, |c: &regex::Captures| {
                    let keep = c.get(1).map(|m| m.as_str()).unwrap_or("");
                    let suffix = c.get(3).map(|m| m.as_str()).unwrap_or("");
                    format!("{keep}***{suffix}")
                })
                .into_owned();
        }
        out
    }
}

impl Default for Redactor {
    fn default() -> Self {
        Self::new(&[])
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn redacts_common_forms() {
        let r = Redactor::default();
        assert_eq!(r.apply("app.exe --password hunter2 -v"), "app.exe --password *** -v");
        assert_eq!(r.apply("app.exe design=blue"), "app.exe design=blue");
        assert_eq!(r.apply("net use x: \\\\s\\c /user:bob P@ss"), "net use x: \\\\s\\c /user:bob P@ss");
        assert_eq!(r.apply("sqlcmd Server=a;Password=abc;"), "sqlcmd Server=a;Password=***;");
        assert_eq!(r.apply("curl -H \"Authorization: Bearer abcdefghijk\""), "curl -H \"Authorization: Bearer ***\"");
        assert_eq!(r.apply("git clone https://me:tok123@host/r"), "git clone https://me:***@host/r");
        assert_eq!(r.apply("tool.exe /p:secret"), "tool.exe /p:***");
    }
}
