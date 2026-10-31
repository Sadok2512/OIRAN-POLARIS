//! Bounded, streaming reader for persisted call-flow JSON artifacts.
//!
//! A call flow can contain thousands of decoded events. Deserializing the
//! complete document and then cloning it for an HTTP response multiplies its
//! resident-memory cost. This reader walks the JSON object once, retains only
//! the requested event window and emits a cursor for the next window.

use serde::de::{self, DeserializeSeed, Deserializer, MapAccess, SeqAccess, Visitor};
use serde_json::{json, Map, Value};
use std::{collections::BTreeSet, fmt, fs::File, io::BufReader, path::Path};

pub const DEFAULT_CALLFLOW_PAGE_EVENTS: usize = 100;
pub const MAX_CALLFLOW_PAGE_EVENTS: usize = 256;

#[derive(Debug)]
struct EventPage {
    events: Vec<Value>,
    total_events: usize,
    next_cursor: Option<String>,
}

struct EventPageSeed<'a> {
    cursor: Option<&'a str>,
    limit: usize,
}

impl<'de> DeserializeSeed<'de> for EventPageSeed<'_> {
    type Value = EventPage;

    fn deserialize<D>(self, deserializer: D) -> Result<Self::Value, D::Error>
    where
        D: Deserializer<'de>,
    {
        deserializer.deserialize_seq(EventPageVisitor {
            cursor: self.cursor,
            limit: self.limit,
        })
    }
}

struct EventPageVisitor<'a> {
    cursor: Option<&'a str>,
    limit: usize,
}

impl<'de> Visitor<'de> for EventPageVisitor<'_> {
    type Value = EventPage;

    fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("a call-flow events array")
    }

    fn visit_seq<A>(self, mut sequence: A) -> Result<Self::Value, A::Error>
    where
        A: SeqAccess<'de>,
    {
        let mut events = Vec::with_capacity(self.limit);
        let mut total_events = 0usize;
        let mut cursor_found = self.cursor.is_none();
        let mut page_started = self.cursor.is_none();
        let mut has_more = false;
        let mut last_selected_id = None;

        while let Some(event) = sequence.next_element::<Value>()? {
            total_events = total_events.saturating_add(1);
            let event_id = event
                .get("event_id")
                .and_then(Value::as_str)
                .ok_or_else(|| de::Error::custom("CALLFLOW_EVENT_ID_MISSING"))?;

            if !page_started {
                if Some(event_id) == self.cursor {
                    cursor_found = true;
                    page_started = true;
                }
                continue;
            }

            if events.len() < self.limit {
                last_selected_id = Some(event_id.to_owned());
                events.push(event);
            } else {
                has_more = true;
            }
        }

        if !cursor_found {
            return Err(de::Error::custom("CALLFLOW_CURSOR_INVALID"));
        }

        Ok(EventPage {
            events,
            total_events,
            next_cursor: has_more.then_some(last_selected_id).flatten(),
        })
    }
}

struct CallflowPageSeed<'a> {
    cursor: Option<&'a str>,
    limit: usize,
}

impl<'de> DeserializeSeed<'de> for CallflowPageSeed<'_> {
    type Value = Value;

    fn deserialize<D>(self, deserializer: D) -> Result<Self::Value, D::Error>
    where
        D: Deserializer<'de>,
    {
        deserializer.deserialize_map(CallflowPageVisitor {
            cursor: self.cursor,
            limit: self.limit,
        })
    }
}

struct CallflowPageVisitor<'a> {
    cursor: Option<&'a str>,
    limit: usize,
}

impl<'de> Visitor<'de> for CallflowPageVisitor<'_> {
    type Value = Value;

    fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("a call-flow JSON object")
    }

    fn visit_map<A>(self, mut object: A) -> Result<Self::Value, A::Error>
    where
        A: MapAccess<'de>,
    {
        let mut output = Map::new();
        let mut event_page = None;

        while let Some(key) = object.next_key::<String>()? {
            if key == "events" {
                if event_page.is_some() {
                    return Err(de::Error::duplicate_field("events"));
                }
                event_page = Some(object.next_value_seed(EventPageSeed {
                    cursor: self.cursor,
                    limit: self.limit,
                })?);
            } else {
                output.insert(key, object.next_value::<Value>()?);
            }
        }

        let page = event_page.ok_or_else(|| de::Error::missing_field("events"))?;
        let selected_ids = page
            .events
            .iter()
            .filter_map(|event| event.get("event_id").and_then(Value::as_str))
            .collect::<BTreeSet<_>>();

        if let Some(procedures) = output.get_mut("procedures").and_then(Value::as_array_mut) {
            for procedure in procedures.iter_mut() {
                if let Some(ids) = procedure.get_mut("event_ids").and_then(Value::as_array_mut) {
                    ids.retain(|id| id.as_str().is_some_and(|id| selected_ids.contains(id)));
                }
            }
            procedures.retain(|procedure| {
                procedure
                    .get("event_ids")
                    .and_then(Value::as_array)
                    .is_some_and(|ids| !ids.is_empty())
            });
        }

        if let Some(edges) = output
            .get_mut("correlation_edges")
            .and_then(Value::as_array_mut)
        {
            edges.retain(|edge| {
                ["source_event_id", "target_event_id"].iter().any(|field| {
                    edge.get(field)
                        .and_then(Value::as_str)
                        .is_some_and(|id| selected_ids.contains(id))
                })
            });
        }

        let returned_events = page.events.len();
        output.insert("events".into(), Value::Array(page.events));
        output.insert(
            "pagination".into(),
            json!({
                "limit": self.limit,
                "cursor": self.cursor,
                "next_cursor": page.next_cursor,
                "returned_events": returned_events,
                "total_events": page.total_events,
            }),
        );
        Ok(Value::Object(output))
    }
}

pub fn read_callflow_page(
    path: &Path,
    cursor: Option<&str>,
    limit: usize,
) -> Result<Value, String> {
    if !(1..=MAX_CALLFLOW_PAGE_EVENTS).contains(&limit) {
        return Err("CALLFLOW_LIMIT_INVALID".into());
    }
    let file = File::open(path).map_err(|error| format!("CALLFLOW_OPEN_FAILED: {error}"))?;
    let reader = BufReader::with_capacity(1024 * 1024, file);
    let mut deserializer = serde_json::Deserializer::from_reader(reader);
    CallflowPageSeed { cursor, limit }
        .deserialize(&mut deserializer)
        .map_err(|error| {
            let message = error.to_string();
            if message.contains("CALLFLOW_CURSOR_INVALID") {
                "CALLFLOW_CURSOR_INVALID".into()
            } else {
                format!("CALLFLOW_READ_FAILED: {message}")
            }
        })
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::{
        fs,
        io::{BufWriter, Write},
        sync::{
            atomic::{AtomicBool, AtomicU64, Ordering},
            Arc,
        },
        thread,
        time::{Duration, SystemTime, UNIX_EPOCH},
    };

    fn rss_bytes() -> u64 {
        fs::read_to_string("/proc/self/status")
            .ok()
            .and_then(|status| {
                status.lines().find_map(|line| {
                    line.strip_prefix("VmRSS:")
                        .and_then(|value| value.split_whitespace().next())
                        .and_then(|value| value.parse::<u64>().ok())
                })
            })
            .unwrap_or_default()
            .saturating_mul(1024)
    }

    fn temporary_path() -> std::path::PathBuf {
        std::env::temp_dir().join(format!(
            "oiran-callflow-page-{}.json",
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ))
    }

    fn write_synthetic_callflow(path: &Path, event_count: usize) {
        let mut writer = BufWriter::new(File::create(path).unwrap());
        writer
            .write_all(br#"{"callflow_id":"cf","session_id":"large","technology":"5G SA","start_timestamp":"0","end_timestamp":"1","participants":[],"interfaces":["N3"],"procedures":[],"events":["#)
            .unwrap();
        let padding = "x".repeat(16 * 1024);
        for index in 0..event_count {
            if index > 0 {
                writer.write_all(b",").unwrap();
            }
            serde_json::to_writer(
                &mut writer,
                &json!({
                    "event_id": format!("event-{index:08}"),
                    "decoded_ie_tree": [{"name":"padding","value":padding}],
                }),
            )
            .unwrap();
        }
        writer
            .write_all(br#"],"correlation_edges":[],"correlation_status":{},"decoder_versions":{},"schema_version":"1","capture_references":[],"accounting":{},"unresolved_fields":0}"#)
            .unwrap();
        writer.flush().unwrap();
    }

    #[test]
    fn streams_large_callflow_with_bounded_rss_and_cursor_pages() {
        let configured =
            std::env::var_os("OIRAN_TEST_LARGE_CALLFLOW_PATH").map(std::path::PathBuf::from);
        let generated = configured.is_none();
        let path = configured.unwrap_or_else(|| {
            let path = temporary_path();
            write_synthetic_callflow(&path, 8_192);
            path
        });

        let running = Arc::new(AtomicBool::new(true));
        let peak = Arc::new(AtomicU64::new(rss_bytes()));
        let sampler = {
            let running = Arc::clone(&running);
            let peak = Arc::clone(&peak);
            thread::spawn(move || {
                while running.load(Ordering::Relaxed) {
                    peak.fetch_max(rss_bytes(), Ordering::Relaxed);
                    thread::sleep(Duration::from_millis(2));
                }
            })
        };

        let first = read_callflow_page(&path, None, 100).unwrap();
        let cursor = first["pagination"]["next_cursor"]
            .as_str()
            .expect("large flow has another page")
            .to_owned();
        let second = read_callflow_page(&path, Some(&cursor), 100).unwrap();
        running.store(false, Ordering::Relaxed);
        sampler.join().unwrap();

        assert_eq!(first["events"].as_array().unwrap().len(), 100);
        assert_eq!(second["events"].as_array().unwrap().len(), 100);
        assert_ne!(
            first["events"][0]["event_id"],
            second["events"][0]["event_id"]
        );
        let peak_rss = peak.load(Ordering::Relaxed);
        println!("CALLFLOW_PAGE_PATH={}", path.display());
        println!(
            "CALLFLOW_PAGE_TOTAL={}",
            first["pagination"]["total_events"]
        );
        println!("CALLFLOW_PAGE_PEAK_RSS_BYTES={peak_rss}");
        assert!(peak_rss < 256 * 1024 * 1024, "peak RSS exceeded 256 MiB");

        if generated {
            fs::remove_file(path).unwrap();
        }
    }

    #[test]
    fn rejects_unknown_cursor_without_returning_the_first_page() {
        let path = temporary_path();
        write_synthetic_callflow(&path, 3);
        assert_eq!(
            read_callflow_page(&path, Some("not-an-event"), 2).unwrap_err(),
            "CALLFLOW_CURSOR_INVALID"
        );
        fs::remove_file(path).unwrap();
    }
}
