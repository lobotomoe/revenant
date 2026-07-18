//! A minimal read-only XML DOM over `quick-xml`.
//!
//! A small tree built from `quick-xml` events: namespace prefixes are stripped
//! from element and attribute names, and callers walk the tree by local tag
//! name. `quick-xml` never expands external or custom entities, so this is not
//! vulnerable to the billion-laughs / external-entity attacks that a naive XML
//! parser would be.
//!
//! Two consumers share this DOM: the SOAP response parsers (`net`) and the ETSI
//! Trust Service List parser (`pki::tsl`). It lives here, in a neutral module,
//! so neither depends on the other's internals.

use quick_xml::events::{BytesStart, Event};
use quick_xml::Reader;

/// A node in the minimal parsed DOM. Namespace prefixes are stripped from both
/// element and attribute names.
#[derive(Debug)]
pub(crate) struct Node {
    pub(crate) name: String,
    pub(crate) attrs: Vec<(String, String)>,
    pub(crate) children: Vec<Node>,
    pub(crate) text: String,
}

impl Node {
    fn root() -> Self {
        Self {
            name: String::new(),
            attrs: Vec::new(),
            children: Vec::new(),
            text: String::new(),
        }
    }

    fn from_start(e: &BytesStart<'_>) -> Self {
        let name = local_name(e.local_name().as_ref());
        let mut attrs = Vec::new();
        for attr in e.attributes().flatten() {
            let key = local_name(attr.key.local_name().as_ref());
            if let Ok(value) = attr.unescape_value() {
                attrs.push((key, value.into_owned()));
            }
        }
        Self {
            name,
            attrs,
            children: Vec::new(),
            text: String::new(),
        }
    }

    pub(crate) fn attr(&self, name: &str) -> Option<&str> {
        self.attrs
            .iter()
            .find(|(k, _)| k == name)
            .map(|(_, v)| v.as_str())
    }

    /// The element's direct text, trimmed; `None` when empty or whitespace-only.
    pub(crate) fn trimmed_text(&self) -> Option<&str> {
        let trimmed = self.text.trim();
        if trimmed.is_empty() {
            None
        } else {
            Some(trimmed)
        }
    }
}

fn local_name(raw: &[u8]) -> String {
    String::from_utf8_lossy(raw).into_owned()
}

/// Parse XML into the minimal DOM. Returns the synthetic root whose children
/// are the top-level elements. Fails on malformed XML -- mismatched or unclosed
/// tags -- so a truncated document is caught instead of silently parsed as a
/// partial tree.
pub(crate) fn parse_dom(xml: &str) -> Result<Node, String> {
    let mut reader = Reader::from_str(xml);
    // Index 0 is the synthetic root; deeper entries are open elements.
    let mut stack: Vec<Node> = vec![Node::root()];

    loop {
        match reader.read_event().map_err(|e| e.to_string())? {
            Event::Start(e) => stack.push(Node::from_start(&e)),
            Event::Empty(e) => {
                let node = Node::from_start(&e);
                if let Some(top) = stack.last_mut() {
                    top.children.push(node);
                }
            }
            Event::End(_) => {
                // Never pop the synthetic root; balanced XML keeps len() >= 2 here.
                if stack.len() > 1 {
                    if let Some(node) = stack.pop() {
                        if let Some(parent) = stack.last_mut() {
                            parent.children.push(node);
                        }
                    }
                }
            }
            Event::Text(e) => {
                let text = e.unescape().map_err(|e| e.to_string())?;
                if let Some(top) = stack.last_mut() {
                    top.text.push_str(&text);
                }
            }
            Event::CData(e) => {
                if let Some(top) = stack.last_mut() {
                    top.text.push_str(&String::from_utf8_lossy(&e.into_inner()));
                }
            }
            Event::Eof => break,
            _ => {}
        }
    }

    // Any element left open at EOF means the document was truncated or malformed.
    if stack.len() != 1 {
        return Err(format!(
            "unexpected end of document with {} unclosed element(s)",
            stack.len() - 1
        ));
    }
    let root = stack
        .into_iter()
        .next()
        .expect("synthetic root is always present");
    // A well-formed XML document has a root element; plain text ("not xml") that
    // `quick-xml` happily reads as a single text node is not valid XML, so it is
    // rejected here.
    if root.children.is_empty() {
        return Err("document has no root element".to_owned());
    }
    Ok(root)
}

/// First element with local name `tag`, in document order, returning its text.
pub(crate) fn find_value(node: &Node, tag: &str) -> Option<String> {
    for child in &node.children {
        if child.name == tag {
            if let Some(text) = child.trimmed_text() {
                return Some(text.to_owned());
            }
        }
        if let Some(found) = find_value(child, tag) {
            return Some(found);
        }
    }
    None
}

/// Text of every element with local name `tag`, in document order.
pub(crate) fn find_all_values(node: &Node, tag: &str, out: &mut Vec<String>) {
    for child in &node.children {
        if child.name == tag {
            if let Some(text) = child.trimmed_text() {
                out.push(text.to_owned());
            }
        }
        find_all_values(child, tag, out);
    }
}

/// First element with local name `tag`, in document order, as a node (so the
/// caller can walk its subtree). The node equivalent of [`find_value`].
pub(crate) fn find_node<'a>(node: &'a Node, tag: &str) -> Option<&'a Node> {
    for child in &node.children {
        if child.name == tag {
            return Some(child);
        }
        if let Some(found) = find_node(child, tag) {
            return Some(found);
        }
    }
    None
}

/// Every element with local name `tag`, in document order (the node equivalent
/// of [`find_all_values`], for callers that need to walk each match's subtree).
pub(crate) fn find_all_nodes<'a>(node: &'a Node, tag: &str, out: &mut Vec<&'a Node>) {
    for child in &node.children {
        if child.name == tag {
            out.push(child);
        }
        find_all_nodes(child, tag, out);
    }
}

/// The `attr_name` attribute of the first element named `element_tag`.
pub(crate) fn find_attribute(node: &Node, element_tag: &str, attr_name: &str) -> Option<String> {
    for child in &node.children {
        if child.name == element_tag {
            if let Some(value) = child.attr(attr_name) {
                return Some(value.to_owned());
            }
        }
        if let Some(found) = find_attribute(child, element_tag, attr_name) {
            return Some(found);
        }
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_nested_elements_and_strips_prefixes() {
        let dom = parse_dom("<a:Root xmlns:a='urn:x'><Child>hi</Child></a:Root>").unwrap();
        assert_eq!(find_value(&dom, "Child").as_deref(), Some("hi"));
        assert_eq!(find_value(&dom, "Root").as_deref(), None); // no direct text
    }

    #[test]
    fn find_all_values_collects_in_document_order() {
        let dom = parse_dom("<r><x>1</x><g><x>2</x></g><x>3</x></r>").unwrap();
        let mut out = Vec::new();
        find_all_values(&dom, "x", &mut out);
        assert_eq!(out, ["1", "2", "3"]);
    }

    #[test]
    fn find_all_nodes_walks_each_match() {
        let dom = parse_dom("<r><s><n>a</n></s><s><n>b</n></s></r>").unwrap();
        let mut nodes = Vec::new();
        find_all_nodes(&dom, "s", &mut nodes);
        assert_eq!(nodes.len(), 2);
        assert_eq!(find_value(nodes[1], "n").as_deref(), Some("b"));
    }

    #[test]
    fn unclosed_tag_is_rejected() {
        assert!(parse_dom("<r><child></r>").is_err());
    }

    #[test]
    fn attribute_lookup_by_local_name() {
        let dom = parse_dom("<r><e xml:lang='en' k='v'/></r>").unwrap();
        assert_eq!(find_attribute(&dom, "e", "k").as_deref(), Some("v"));
        assert_eq!(find_attribute(&dom, "e", "lang").as_deref(), Some("en"));
    }
}
