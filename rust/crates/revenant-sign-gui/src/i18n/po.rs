//! Minimal reader for the subset of the gettext PO format the bundled
//! translation catalogs use.
//!
//! The catalogs key every entry by a stable message *key* (e.g. `gui.cancel`)
//! and use no plurals, message contexts, or flags, so a full PO library would
//! be overkill and pull avoidable dependencies into a store-shipped binary.
//! This reader handles exactly what the catalogs contain: `msgid`/`msgstr`
//! pairs, multi-line continuation strings, comment lines, and C-style escapes.

use std::collections::HashMap;

/// Which field a run of bare quoted continuation lines extends.
enum Field {
    None,
    Id,
    Str,
}

/// Parse PO catalog text into a `key -> translated string` map.
///
/// The header entry (empty `msgid`) and any entry whose `msgstr` is empty are
/// skipped: an empty translation carries no information, so lookups fall back
/// rather than returning a blank string.
pub(crate) fn parse(source: &str) -> HashMap<String, String> {
    let mut entries = HashMap::new();
    let mut msgid: Option<String> = None;
    let mut msgstr: Option<String> = None;
    let mut field = Field::None;

    for line in source.lines() {
        let trimmed = line.trim_start();
        if trimmed.is_empty() || trimmed.starts_with('#') {
            flush(&mut entries, &mut msgid, &mut msgstr);
            field = Field::None;
        } else if let Some(rest) = trimmed.strip_prefix("msgid ") {
            // A fresh msgid opens a new entry; commit the previous one first.
            flush(&mut entries, &mut msgid, &mut msgstr);
            msgid = Some(unquote(rest));
            field = Field::Id;
        } else if let Some(rest) = trimmed.strip_prefix("msgstr ") {
            msgstr = Some(unquote(rest));
            field = Field::Str;
        } else if trimmed.starts_with('"') {
            let piece = unquote(trimmed);
            match field {
                Field::Id => msgid.get_or_insert_with(String::new).push_str(&piece),
                Field::Str => msgstr.get_or_insert_with(String::new).push_str(&piece),
                Field::None => {}
            }
        }
    }
    flush(&mut entries, &mut msgid, &mut msgstr);
    entries
}

/// Commit a completed `msgid`/`msgstr` pair, dropping the header and any entry
/// with an empty key or empty translation.
fn flush(
    entries: &mut HashMap<String, String>,
    msgid: &mut Option<String>,
    msgstr: &mut Option<String>,
) {
    if let (Some(id), Some(text)) = (msgid.take(), msgstr.take()) {
        if !id.is_empty() && !text.is_empty() {
            entries.insert(id, text);
        }
    }
}

/// Strip the surrounding quotes from a PO string token and unescape its body.
fn unquote(token: &str) -> String {
    let Some(open) = token.find('"') else {
        return String::new();
    };
    let body = &token[open + 1..];
    let end = body.rfind('"').unwrap_or(body.len());
    unescape(&body[..end])
}

/// Resolve C-style backslash escapes used in PO strings.
fn unescape(s: &str) -> String {
    if !s.contains('\\') {
        return s.to_owned();
    }
    let mut out = String::with_capacity(s.len());
    let mut chars = s.chars();
    while let Some(c) = chars.next() {
        if c != '\\' {
            out.push(c);
            continue;
        }
        match chars.next() {
            Some('n') => out.push('\n'),
            Some('t') => out.push('\t'),
            Some('r') => out.push('\r'),
            Some('"') => out.push('"'),
            // An escaped backslash and a dangling backslash at end-of-input both
            // resolve to a single literal backslash.
            Some('\\') | None => out.push('\\'),
            // Unknown escape: keep it verbatim so nothing is silently dropped.
            Some(other) => {
                out.push('\\');
                out.push(other);
            }
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::parse;

    #[test]
    fn parses_simple_pair() {
        let map = parse("msgid \"gui.cancel\"\nmsgstr \"Cancel\"\n");
        assert_eq!(map.get("gui.cancel").map(String::as_str), Some("Cancel"));
    }

    #[test]
    fn skips_header_and_empty_translations() {
        let src = "msgid \"\"\nmsgstr \"Content-Type: text/plain\"\n\n\
                   msgid \"gui.untranslated\"\nmsgstr \"\"\n";
        let map = parse(src);
        assert!(map.is_empty());
    }

    #[test]
    fn ignores_comments_and_references() {
        let src = "#. EN: Cancel\n#: source.rs:1\nmsgid \"gui.cancel\"\nmsgstr \"Cancel\"\n";
        let map = parse(src);
        assert_eq!(map.get("gui.cancel").map(String::as_str), Some("Cancel"));
    }

    #[test]
    fn joins_multiline_continuations() {
        let src = "msgid \"gui.help\"\nmsgstr \"\"\n\"first line\\n\"\n\"second line\"\n";
        let map = parse(src);
        assert_eq!(
            map.get("gui.help").map(String::as_str),
            Some("first line\nsecond line")
        );
    }

    #[test]
    fn unescapes_quotes_tabs_and_backslashes() {
        let src = "msgid \"gui.q\"\nmsgstr \"a \\\"b\\\"\\tc\\\\d\"\n";
        let map = parse(src);
        assert_eq!(map.get("gui.q").map(String::as_str), Some("a \"b\"\tc\\d"));
    }

    #[test]
    fn blank_line_separates_entries() {
        let src = "msgid \"a\"\nmsgstr \"A\"\n\nmsgid \"b\"\nmsgstr \"B\"\n";
        let map = parse(src);
        assert_eq!(map.get("a").map(String::as_str), Some("A"));
        assert_eq!(map.get("b").map(String::as_str), Some("B"));
    }
}
