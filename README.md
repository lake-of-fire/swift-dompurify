# SwiftDOMPurify

Swift 6.2 SwiftPM port of [DOMPurify](https://github.com/cure53/DOMPurify), backed by [SwiftSoup](https://github.com/scinfu/SwiftSoup) for parsing and DOM manipulation.

## Features
- DOMPurify-style allowlist/forbidlist sanitization for HTML, SVG, and MathML.
- Hooks for element, attribute, and shadowroot sanitization.
- String, Element, and Node inputs.
- `RETURN_DOM` and `RETURN_DOM_FRAGMENT` behavior as string/fragment wrappers.
- `DOMPurify.removed` tracking.

## Install
Add the package to your `Package.swift`:

```swift
.package(url: "https://github.com/your-org/SwiftDOMPurify.git", from: "0.1.0"),
```

## Basic Usage
```swift
import SwiftDOMPurify

let clean = DOMPurify.sanitize("<img src=x onerror=alert(1)>")
// => "<img src=\"x\">"
```

## Configuration
```swift
var config = DOMPurify.Configuration.default
config.allowedTags.insert("custom-tag")
config.allowedAttributes.insert("data-foo")

let clean = DOMPurify.sanitize("<custom-tag data-foo=\"ok\"></custom-tag>", config: config)
```

## Hooks
Hook callbacks receive a `Node` and optional `HookEvent` (for attribute and element hooks):

```swift
DOMPurify.addHook(.beforeSanitizeElements) { node, _ in
  if let element = node as? Element {
    _ = try? element.attr("data-seen", "1")
  }
}
```

Hooks fire for all nodes (including text, data, and comment nodes). Cast to `Element` when you need element-only APIs.

## Node Input
```swift
let doc = try SwiftSoup.parseBodyFragment("<div></div>")
let node = try doc.select("div").first()!

let clean = DOMPurify.sanitize(node)
let dom = DOMPurify.sanitizeToDOM(node)   // stringified DOM output (outer HTML)
let fragment = DOMPurify.sanitizeToFragment(node)
let document = DOMPurify.sanitizeToDocument(node) // SanitizedDOM wrapper (html/head/body strings)
let tree = DOMPurify.sanitizeToDocumentTree(node) // SwiftSoup.Document (sanitized DOM tree)
let removed = DOMPurify.sanitizeAndGetRemoved("<img src=x onerror=alert(1)>")
```

## In-Place Sanitization
```swift
let doc = try SwiftSoup.parseBodyFragment("<a href=\"javascript:alert(1)\"></a>")
let anchor = try doc.select("a").first()!

try DOMPurify.sanitizeInPlace(anchor)
```

## Notes
- Ported from DOMPurify 3.3.1.
- `RETURN_DOM` and `RETURN_DOM_FRAGMENT` return string/fragment wrappers rather than native DOM types.
- `sanitizeToDocument` returns a lightweight wrapper with `html`, `headHTML`, and `bodyHTML`.
- `sanitizeToDocumentTree` returns a SwiftSoup `Document` for direct DOM manipulation.
- `sanitizeAndGetRemoved` returns the sanitized output and removed items together (useful for concurrency).

## Choosing an API
- `sanitize`: most convenient, returns sanitized HTML string (body fragment).
- `sanitizeToDOM`: when you want outer HTML for the sanitized root node.
- `sanitizeToFragment`: when you want fragment html + first child text/data value.
- `sanitizeToDocument`: when you want stringified `<html>/<head>/<body>` views.
- `sanitizeToDocumentTree`: when you need a mutable SwiftSoup `Document`.

## Removed Items
Removed items are reported as enum cases:
- `.element(RemovedElement)` with `nodeName`
- `.attribute(RemovedAttribute)` with `name` and `fromNodeName`

Example:
```swift
let result = DOMPurify.sanitizeAndGetRemoved("<a href=\"javascript:alert(1)\">x</a>")
let removedAttributes = result.removed.compactMap { item -> DOMPurify.RemovedAttribute? in
  if case .attribute(let attr) = item { return attr }
  return nil
}
let removedElements = result.removed.compactMap { item -> DOMPurify.RemovedElement? in
  if case .element(let element) = item { return element }
  return nil
}
```
- Hook callbacks are invoked for all nodes (including text and data nodes), similar to DOMPurify’s node iterator behavior.
- `safeForTemplates` applies to text/data nodes as well as attribute values.
