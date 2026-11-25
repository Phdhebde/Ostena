//! Structured logging: one JSON object per line, sensitive fields redacted.
//!
//! Protection against secrets in logs, in layers (ADR-0003):
//!
//! 1. Compile time: [`Secret`](crate::secret::Secret) implements neither `Debug`
//!    nor `Display`, so it cannot be recorded as a `tracing` field at all, and a
//!    struct holding one cannot derive `Debug`.
//! 2. Run time: [`JsonLayer`] replaces with `[REDACTED]` the value of every
//!    event or span field whose name looks sensitive ([`is_sensitive_field`]),
//!    whatever its type.
//!
//! Not covered: a value taken out with `expose_secret()` and logged under a
//! harmless field name, or formatted into the message text. That is why
//! `expose_secret` is a disallowed method whose every use is reviewed.

use std::fs::OpenOptions;
use std::io::{self, Write};
use std::path::PathBuf;
use std::sync::Mutex;
use std::time::{SystemTime, UNIX_EPOCH};

use serde_json::{Map, Value};
use tracing::field::{Field, Visit};
use tracing::span::{Attributes, Id, Record};
use tracing::{Event, Subscriber};
use tracing_subscriber::Layer;
use tracing_subscriber::filter::LevelFilter;
use tracing_subscriber::layer::{Context, SubscriberExt};
use tracing_subscriber::registry::{LookupSpan, Registry};

use crate::config::{LogLevel, LoggingConfig, Output};
use crate::secret::Redacted;

/// Fragments that make a field name sensitive (matched case-insensitively,
/// anywhere in the name). Over-redaction is accepted: keystroke fields
/// (`key…`) are sensitive anyway.
const SENSITIVE_FRAGMENTS: &[&str] = &[
    "password",
    "passwd",
    "passphrase",
    "pwd",
    "secret",
    "token",
    "key",
    "credential",
    "authorization",
    "cookie",
    "private",
    "session_id",
    "otp",
    "pin",
];

/// Whether a field with this name must never be written in clear.
pub fn is_sensitive_field(name: &str) -> bool {
    let lower = name.to_ascii_lowercase();
    SENSITIVE_FRAGMENTS.iter().any(|f| lower.contains(f))
}

/// Errors raised while setting up logging.
#[derive(Debug, thiserror::Error)]
pub enum LoggingError {
    /// A log file cannot be opened.
    #[error("[LOG-E001] impossible d'ouvrir le fichier de journal {} : {source}", path.display())]
    OpenFile {
        /// File path.
        path: PathBuf,
        /// Underlying error.
        source: io::Error,
    },
    /// The destination is valid in the configuration but not implemented yet.
    #[error("[LOG-E002] destination de journaux pas encore prise en charge : {0}")]
    Unsupported(&'static str),
    /// A global subscriber is already installed.
    #[error("[LOG-E003] la journalisation est déjà initialisée")]
    AlreadyInitialised,
}

/// Installs the global JSON subscriber described by the configuration.
///
/// # Errors
///
/// [`LoggingError`] if a destination cannot be opened or is not supported yet
/// (syslog arrives with `ostena-audit`), or if logging is already initialised.
pub fn init(config: &LoggingConfig) -> Result<(), LoggingError> {
    let mut writers: Vec<Box<dyn Write + Send>> = Vec::with_capacity(config.outputs.len());
    for output in &config.outputs {
        writers.push(match output {
            Output::Stdout {} => Box::new(io::stdout()),
            Output::File { path } => Box::new(
                OpenOptions::new()
                    .create(true)
                    .append(true)
                    .open(path)
                    .map_err(|source| LoggingError::OpenFile {
                        path: path.clone(),
                        source,
                    })?,
            ),
            Output::Syslog { .. } => return Err(LoggingError::Unsupported("syslog")),
            Output::SyslogUnix { .. } => return Err(LoggingError::Unsupported("syslog-unix")),
        });
    }
    let subscriber = Registry::default()
        .with(level_filter(config.level))
        .with(JsonLayer::new(writers));
    tracing::subscriber::set_global_default(subscriber)
        .map_err(|_| LoggingError::AlreadyInitialised)
}

/// `tracing` filter matching a configured level.
pub fn level_filter(level: LogLevel) -> LevelFilter {
    match level {
        LogLevel::Trace => LevelFilter::TRACE,
        LogLevel::Debug => LevelFilter::DEBUG,
        LogLevel::Info => LevelFilter::INFO,
        LogLevel::Warn => LevelFilter::WARN,
        LogLevel::Error => LevelFilter::ERROR,
    }
}

/// Layer writing each event as one JSON line to every writer.
///
/// Line shape: `{"timestamp", "level", "target", "message", "fields",
/// "spans": [{"name", "fields"}]}`, with sensitive fields redacted.
pub struct JsonLayer {
    writers: Mutex<Vec<Box<dyn Write + Send>>>,
}

impl JsonLayer {
    /// A layer writing to the given destinations.
    pub fn new(writers: Vec<Box<dyn Write + Send>>) -> Self {
        Self {
            writers: Mutex::new(writers),
        }
    }

    fn write_line(&self, line: &[u8]) {
        // A poisoned lock only means another thread panicked while writing:
        // keep logging rather than lose events.
        let mut writers = self
            .writers
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        for w in writers.iter_mut() {
            // Logging must never bring the service down: write errors are dropped.
            let _ = w.write_all(line);
        }
    }
}

/// Span fields kept in the span extensions.
struct SpanFields(Map<String, Value>);

impl<S> Layer<S> for JsonLayer
where
    S: Subscriber + for<'a> LookupSpan<'a>,
{
    fn on_new_span(&self, attrs: &Attributes<'_>, id: &Id, ctx: Context<'_, S>) {
        let mut fields = Map::new();
        attrs.record(&mut JsonVisitor(&mut fields));
        if let Some(span) = ctx.span(id) {
            span.extensions_mut().insert(SpanFields(fields));
        }
    }

    fn on_record(&self, id: &Id, values: &Record<'_>, ctx: Context<'_, S>) {
        if let Some(span) = ctx.span(id)
            && let Some(fields) = span.extensions_mut().get_mut::<SpanFields>()
        {
            values.record(&mut JsonVisitor(&mut fields.0));
        }
    }

    fn on_event(&self, event: &Event<'_>, ctx: Context<'_, S>) {
        let meta = event.metadata();
        let mut fields = Map::new();
        event.record(&mut JsonVisitor(&mut fields));

        let mut line = Map::new();
        line.insert(
            "timestamp".into(),
            Value::String(rfc3339(SystemTime::now())),
        );
        line.insert("level".into(), Value::String(meta.level().as_str().into()));
        line.insert("target".into(), Value::String(meta.target().into()));
        if let Some(message) = fields.remove("message") {
            line.insert("message".into(), message);
        }
        if !fields.is_empty() {
            line.insert("fields".into(), Value::Object(fields));
        }
        if let Some(scope) = ctx.event_scope(event) {
            let spans: Vec<Value> = scope
                .from_root()
                .map(|span| {
                    let mut entry = Map::new();
                    entry.insert("name".into(), Value::String(span.name().into()));
                    if let Some(f) = span.extensions().get::<SpanFields>()
                        && !f.0.is_empty()
                    {
                        entry.insert("fields".into(), Value::Object(f.0.clone()));
                    }
                    Value::Object(entry)
                })
                .collect();
            if !spans.is_empty() {
                line.insert("spans".into(), Value::Array(spans));
            }
        }

        // Serialising a map of JSON values cannot fail.
        let mut bytes = serde_json::to_vec(&Value::Object(line)).unwrap_or_default();
        bytes.push(b'\n');
        self.write_line(&bytes);
    }
}

/// Records fields into a JSON map, redacting sensitive names.
struct JsonVisitor<'a>(&'a mut Map<String, Value>);

impl JsonVisitor<'_> {
    fn put(&mut self, field: &Field, value: Value) {
        let value = if is_sensitive_field(field.name()) {
            Value::String(Redacted::TEXT.into())
        } else {
            value
        };
        self.0.insert(field.name().into(), value);
    }
}

impl Visit for JsonVisitor<'_> {
    fn record_f64(&mut self, field: &Field, value: f64) {
        self.put(
            field,
            serde_json::Number::from_f64(value).map_or(Value::Null, Value::Number),
        );
    }

    fn record_i64(&mut self, field: &Field, value: i64) {
        self.put(field, Value::from(value));
    }

    fn record_u64(&mut self, field: &Field, value: u64) {
        self.put(field, Value::from(value));
    }

    fn record_i128(&mut self, field: &Field, value: i128) {
        self.put(field, Value::String(value.to_string()));
    }

    fn record_u128(&mut self, field: &Field, value: u128) {
        self.put(field, Value::String(value.to_string()));
    }

    fn record_bool(&mut self, field: &Field, value: bool) {
        self.put(field, Value::Bool(value));
    }

    fn record_str(&mut self, field: &Field, value: &str) {
        self.put(field, Value::String(value.into()));
    }

    fn record_error(&mut self, field: &Field, value: &(dyn std::error::Error + 'static)) {
        self.put(field, Value::String(value.to_string()));
    }

    fn record_debug(&mut self, field: &Field, value: &dyn std::fmt::Debug) {
        self.put(field, Value::String(format!("{value:?}")));
    }
}

/// UTC timestamp `YYYY-MM-DDTHH:MM:SS.mmmZ`, without a date crate.
fn rfc3339(time: SystemTime) -> String {
    let since = time.duration_since(UNIX_EPOCH).unwrap_or_default();
    let secs = since.as_secs();
    let (year, month, day) = civil_from_days(secs / 86_400);
    let rem = secs % 86_400;
    format!(
        "{year:04}-{month:02}-{day:02}T{:02}:{:02}:{:02}.{:03}Z",
        rem / 3600,
        rem % 3600 / 60,
        rem % 60,
        since.subsec_millis()
    )
}

/// UTC date and time `YYYY-MM-DD HH:MM:SS UTC` of `unix_secs`, for messages.
pub fn utc_text(unix_secs: u64) -> String {
    let (year, month, day) = civil_from_days(unix_secs / 86_400);
    let rem = unix_secs % 86_400;
    format!(
        "{year:04}-{month:02}-{day:02} {:02}:{:02}:{:02} UTC",
        rem / 3600,
        rem % 3600 / 60,
        rem % 60
    )
}

/// Days since 1970-01-01 to (year, month, day), proleptic Gregorian calendar.
/// Algorithm from H. Hinnant, "chrono-Compatible Low-Level Date Algorithms".
fn civil_from_days(days: u64) -> (u64, u64, u64) {
    let z = days + 719_468;
    let era = z / 146_097;
    let doe = z % 146_097;
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let day = doy - (153 * mp + 2) / 5 + 1;
    let month = if mp < 10 { mp + 3 } else { mp - 9 };
    let year = yoe + era * 400 + u64::from(month <= 2);
    (year, month, day)
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;
    use std::time::Duration;

    use super::*;

    #[test]
    fn utc_text_formats_dates() {
        assert_eq!(utc_text(0), "1970-01-01 00:00:00 UTC");
        assert_eq!(utc_text(1_800_028_800), "2027-01-15 16:00:00 UTC");
        assert_eq!(utc_text(951_782_400), "2000-02-29 00:00:00 UTC");
    }

    #[derive(Clone, Default)]
    struct Buffer(Arc<Mutex<Vec<u8>>>);

    impl Write for Buffer {
        fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
            self.0.lock().unwrap().extend_from_slice(buf);
            Ok(buf.len())
        }
        fn flush(&mut self) -> io::Result<()> {
            Ok(())
        }
    }

    fn capture(f: impl FnOnce()) -> Vec<Value> {
        let buffer = Buffer::default();
        let subscriber = Registry::default()
            .with(LevelFilter::TRACE)
            .with(JsonLayer::new(vec![Box::new(buffer.clone())]));
        tracing::subscriber::with_default(subscriber, f);
        let bytes = buffer.0.lock().unwrap().clone();
        String::from_utf8(bytes)
            .unwrap()
            .lines()
            .map(|l| serde_json::from_str(l).unwrap())
            .collect()
    }

    #[test]
    fn sensitive_names() {
        for name in [
            "password",
            "db_password",
            "API_KEY",
            "apikey",
            "token",
            "auth.token",
            "client_secret",
            "Authorization",
            "session_id",
            "private_key",
            "otp_code",
        ] {
            assert!(is_sensitive_field(name), "{name}");
        }
        for name in [
            "user",
            "target",
            "address",
            "code",
            "message",
            "event",
            "duration_ms",
        ] {
            assert!(!is_sensitive_field(name), "{name}");
        }
    }

    #[test]
    fn event_shape() {
        let lines = capture(|| {
            let span = tracing::info_span!("session", target_host = "srv01");
            let _guard = span.enter();
            tracing::warn!(
                event = "config.weakening",
                count = 2_u64,
                ok = true,
                "hello {}",
                42
            );
        });
        assert_eq!(lines.len(), 1);
        let line = &lines[0];
        assert_eq!(line["level"], "WARN");
        assert_eq!(line["message"], "hello 42");
        assert_eq!(line["fields"]["event"], "config.weakening");
        assert_eq!(line["fields"]["count"], 2);
        assert_eq!(line["fields"]["ok"], true);
        assert_eq!(line["spans"][0]["name"], "session");
        assert_eq!(line["spans"][0]["fields"]["target_host"], "srv01");
        assert!(line["timestamp"].as_str().unwrap().ends_with('Z'));
    }

    #[test]
    fn sensitive_fields_are_redacted_whatever_their_type() {
        let lines = capture(|| {
            let span = tracing::info_span!("s", token = "tok", user = tracing::field::Empty);
            span.record("user", "alice");
            let _guard = span.enter();
            tracing::info!(
                password = "p",
                api_key = 12_u64,
                secret_flag = true,
                other = "ok"
            );
        });
        let line = &lines[0];
        assert_eq!(line["fields"]["password"], "[REDACTED]");
        assert_eq!(line["fields"]["api_key"], "[REDACTED]");
        assert_eq!(line["fields"]["secret_flag"], "[REDACTED]");
        assert_eq!(line["fields"]["other"], "ok");
        assert_eq!(line["spans"][0]["fields"]["token"], "[REDACTED]");
        assert_eq!(line["spans"][0]["fields"]["user"], "alice");
    }

    #[test]
    #[expect(
        clippy::duration_suboptimal_units,
        reason = "Unix timestamps read best in seconds"
    )]
    fn timestamp_format() {
        assert_eq!(rfc3339(UNIX_EPOCH), "1970-01-01T00:00:00.000Z");
        let t = UNIX_EPOCH + Duration::from_secs(1_762_860_000) + Duration::from_millis(123);
        assert_eq!(rfc3339(t), "2025-11-11T11:20:00.123Z");
        let leap = UNIX_EPOCH + Duration::from_secs(951_782_400); // 2000-02-29
        assert_eq!(rfc3339(leap), "2000-02-29T00:00:00.000Z");
    }

    #[test]
    fn syslog_is_not_supported_yet() {
        let config = LoggingConfig {
            level: LogLevel::Info,
            outputs: vec![Output::SyslogUnix {
                path: "/dev/log".into(),
            }],
        };
        assert!(matches!(
            init(&config),
            Err(LoggingError::Unsupported("syslog-unix"))
        ));
    }
}
