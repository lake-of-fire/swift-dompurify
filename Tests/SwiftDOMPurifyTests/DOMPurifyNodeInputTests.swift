import SwiftSoup
import Testing

@testable import SwiftDOMPurify

@Test("DOMPurify should deliver accurate results when sanitizing nodes 1")
func dompurifySanitizesNodeInputToString() throws {
  try withDOMPurifyLock {
  let doc = try SwiftSoup.parseBodyFragment("<table><tbody><tr><td></td></tr></tbody></table>")
  let td = try #require(doc.select("td").first())
  #expect(DOMPurify.sanitize(td) == "<td></td>")
  }
}

@Test("DOMPurify should deliver accurate results when sanitizing nodes 2")
func dompurifySanitizesNodeInputToDOMOuterHTML() throws {
  try withDOMPurifyLock {
  let doc = try SwiftSoup.parseBodyFragment("<table><tbody><tr><td></td></tr></tbody></table>")
  let td = try #require(doc.select("td").first())
  #expect(DOMPurify.sanitizeToDOM(td) == "<body><td></td></body>")
  }
}

@Test("DOMPurify should handle BODY node input") func dompurifySanitizesBodyNodeInput() throws {
  try withDOMPurifyLock {
  let doc = Document.createShell("")
  let body = try #require(doc.body())
  try body.html("<div></div>")

  #expect(DOMPurify.sanitize(body) == "<div></div>")
  #expect(DOMPurify.sanitizeToDOM(body) == "<body><div></div></body>")
  }
}

@Test("DOMPurify should handle HTML node input") func dompurifySanitizesHtmlNodeInput() throws {
  try withDOMPurifyLock {
  let doc = Document.createShell("")
  let html = try #require(doc.select("html").first())
  let head = try #require(doc.head())
  let body = try #require(doc.body())
  try head.html("<title>Test</title>")
  try body.html("<div></div>")

  #expect(DOMPurify.sanitize(html) == "<head><title>Test</title></head><body><div></div></body>")
  #expect(    DOMPurify.sanitizeToDOM(html)
      == "<html><head><title>Test</title></head><body><div></div></body></html>"
  )
  }
}

@Test("DOMPurify should expose sanitized document output")
func dompurifySanitizesToDocument() {
  withDOMPurifyLock {
  let result = DOMPurify.sanitizeToDocument("<div></div>")
  #expect(result.html.contains("<html>"))
  #expect(result.headHTML?.contains("<head") == true)
  #expect(result.bodyHTML?.contains("<div></div>") == true)
  }
}

@Test("DOMPurify should expose sanitized document output for wholeDocument")
func dompurifySanitizesToDocumentWholeDocument() {
  withDOMPurifyLock {
  var config = DOMPurify.Configuration.default
  config.wholeDocument = true

  let result = DOMPurify.sanitizeToDocument("<head><title>Hi</title></head><body><div></div></body>", config: config)
  #expect(result.html.contains("<html>"))
  #expect(result.headHTML?.contains("<title>Hi</title>") == true)
  #expect(result.bodyHTML?.contains("<div></div>") == true)
  }
}

@Test("DOMPurify should expose sanitized document output for XHTML")
func dompurifySanitizesToDocumentXHTML() {
  withDOMPurifyLock {
  var config = DOMPurify.Configuration.default
  config.parserMediaType = .applicationXHTMLXML
  config.namespaceURI = DOMPurify.htmlNamespaceURI

  let result = DOMPurify.sanitizeToDocument("<div></div>", config: config)
  #expect(result.html.contains("xmlns=\"http://www.w3.org/1999/xhtml\""))
  #expect(result.bodyHTML?.contains("<div></div>") == true)
  }
}

@Test("DOMPurify should expose sanitized document tree output")
func dompurifySanitizesToDocumentTree() throws {
  try withDOMPurifyLock {
  let doc = DOMPurify.sanitizeToDocumentTree("<img src=x onerror=alert(1)>")
  let body = try #require(doc.body())
  let html = try body.html()
  #expect(html == "<img src=\"x\">" || html == "<img src=\"x\" />")
  }
}

@Test("DOMPurify should sanitize document tree with SAFE_FOR_TEMPLATES")
func dompurifySanitizesDocumentTreeWithTemplates() throws {
  try withDOMPurifyLock {
  var config = DOMPurify.Configuration.default
  config.safeForTemplates = true

  let doc = DOMPurify.sanitizeToDocumentTree("<div>{{value}}</div>", config: config)
  let body = try #require(doc.body())
  let html = try body.html()
  #expect(html.contains("<div>"))
  #expect(!html.contains("{{"))
  #expect(!html.contains("}}"))
  }
}

@Test("DOMPurify should sanitize document tree with ALLOW_UNKNOWN_PROTOCOLS")
func dompurifySanitizesDocumentTreeWithUnknownProtocols() throws {
  try withDOMPurifyLock {
  var config = DOMPurify.Configuration.default
  config.allowUnknownProtocols = true

  let doc = DOMPurify.sanitizeToDocumentTree("<a href=\"custom:foo\">x</a>", config: config)
  let body = try #require(doc.body())
  let html = try body.html()
  #expect(html.contains("href=\"custom:foo\""))
  }
}

@Test("DOMPurify should preserve leading whitespace when FORCE_BODY is false")
func dompurifyPreservesLeadingWhitespaceInDocumentTree() throws {
  try withDOMPurifyLock {
  var config = DOMPurify.Configuration.default
  config.forceBody = false

  let doc = DOMPurify.sanitizeToDocumentTree("   <div></div>", config: config)
  let body = try #require(doc.body())
  let html = try body.html()
  #expect(html == "<div></div>")
  }
}

@Test("DOMPurify fragment output preserves leading whitespace when FORCE_BODY is false")
func dompurifyPreservesLeadingWhitespaceInFragment() {
  withDOMPurifyLock {
  var config = DOMPurify.Configuration.default
  config.forceBody = false

  let fragment = DOMPurify.sanitizeToFragment("   <div></div>", config: config)
  #expect(fragment.html.hasPrefix("   "))
  }
}

@Test("DOMPurify sanitizeAndGetRemoved should work for element input")
func dompurifySanitizeAndGetRemovedElement() throws {
  try withDOMPurifyLock {
  let doc = try SwiftSoup.parseBodyFragment("<a href=\"javascript:alert(1)\">x</a>")
  let anchor = try #require(doc.select("a").first())

  let result = DOMPurify.sanitizeAndGetRemoved(anchor)
  #expect(result.sanitized == "<a>x</a>" || result.sanitized == "<a>x</a>")
  #expect(result.removed.contains(where: { item in
    if case .attribute(let attr) = item {
      return attr.name == "href"
    }
    return false
  }))
  }
}

@Test("DOMPurify sanitizeAndGetRemoved should work for node input")
func dompurifySanitizeAndGetRemovedNode() {
  withDOMPurifyLock {
  let comment = Comment("boom".utf8Array, "".utf8Array)
  let result = DOMPurify.sanitizeAndGetRemoved(comment)
  #expect(result.sanitized.isEmpty)
  #expect(result.removed.contains(where: { item in
    if case .element(let element) = item {
      return element.nodeName == "#comment"
    }
    return false
  }))
  }
}

@Test("DOMPurify should handle element input with RETURN_DOM_FRAGMENT") func dompurifySanitizesElementToFragment() throws {
  try withDOMPurifyLock {
  let doc = Document.createShell("")
  let body = try #require(doc.body())
  try body.html("foo<div></div>")

  let fragment = DOMPurify.sanitizeToFragment(body)
  #expect(fragment.html == "foo<div></div>")
  #expect(fragment.firstChildNodeValue == "foo")
  }
}

@Test("DOMPurify should handle HTML element input with RETURN_DOM_FRAGMENT")
func dompurifySanitizesHtmlElementToFragment() throws {
  try withDOMPurifyLock {
  let doc = Document.createShell("")
  let html = try #require(doc.select("html").first())
  let head = try #require(doc.head())
  let body = try #require(doc.body())
  try head.html("<title>Test</title>")
  try body.html("foo<div></div>")

  let fragment = DOMPurify.sanitizeToFragment(html)
  #expect(fragment.html == "<head><title>Test</title></head><body>foo<div></div></body>")
  #expect(fragment.firstChildNodeValue == nil)
  }
}

@Test("DOMPurify should handle text node input") func dompurifySanitizesTextNodeInput() {
  withDOMPurifyLock {
  let textNode = TextNode("Hello", nil)
  #expect(DOMPurify.sanitize(textNode) == "Hello")
  #expect(DOMPurify.sanitizeToDOM(textNode) == "<body>Hello</body>")

  let fragment = DOMPurify.sanitizeToFragment(textNode)
  #expect(fragment.html == "Hello")
  #expect(fragment.firstChildNodeValue == "Hello")
  }
}

@Test("DOMPurify should drop comment node input") func dompurifySanitizesCommentNodeInput() {
  withDOMPurifyLock {
  let comment = Comment("boom".utf8Array, "".utf8Array)
  #expect(DOMPurify.sanitize(comment) == "")
  #expect(DOMPurify.sanitizeToDOM(comment) == "<body></body>")

  let fragment = DOMPurify.sanitizeToFragment(comment)
  #expect(fragment.html == "")
  #expect(fragment.firstChildNodeValue == nil)
  }
}

@Test("DOMPurify should handle data node input") func dompurifySanitizesDataNodeInput() {
  withDOMPurifyLock {
  let dataNode = DataNode("Hello".utf8Array, "".utf8Array)
  #expect(DOMPurify.sanitize(dataNode) == "Hello")
  #expect(DOMPurify.sanitizeToDOM(dataNode) == "<body>Hello</body>")

  let fragment = DOMPurify.sanitizeToFragment(dataNode)
  #expect(fragment.html == "Hello")
  #expect(fragment.firstChildNodeValue == "Hello")
  }
}

@Test("DOMPurify should handle Document node input") func dompurifySanitizesDocumentNodeInput() throws {
  try withDOMPurifyLock {
  let doc = Document.createShell("")
  let head = try #require(doc.head())
  let body = try #require(doc.body())
  try head.html("<title>Title</title>")
  try body.html("Hello")

  #expect(DOMPurify.sanitize(doc) == "Hello")
  #expect(DOMPurify.sanitizeToDOM(doc) == "<body>Hello</body>")

  let fragment = DOMPurify.sanitizeToFragment(doc)
  #expect(fragment.html == "Hello")
  #expect(fragment.firstChildNodeValue == "Hello")
  }
}

@Test("DOMPurify should handle DocumentType node input") func dompurifySanitizesDoctypeNodeInput() {
  withDOMPurifyLock {
  let doctype = DocumentType("html", "", "", "")
  #expect(DOMPurify.sanitize(doctype) == "<!DOCTYPE html>")
  #expect(DOMPurify.sanitizeToDOM(doctype) == "<body><!DOCTYPE html></body>")

  let fragment = DOMPurify.sanitizeToFragment(doctype)
  #expect(fragment.html == "<!DOCTYPE html>")
  #expect(fragment.firstChildNodeValue == nil)
  }
}

@Test("DOMPurify should drop XmlDeclaration node input") func dompurifySanitizesXmlDeclarationNodeInput() {
  withDOMPurifyLock {
  let declaration = XmlDeclaration("xml", "", false)
  #expect(DOMPurify.sanitize(declaration) == "")
  #expect(DOMPurify.sanitizeToDOM(declaration) == "<body></body>")

  let fragment = DOMPurify.sanitizeToFragment(declaration)
  #expect(fragment.html == "")
  #expect(fragment.firstChildNodeValue == nil)
  }
}

@Test("DOMPurify should apply SAFE_FOR_TEMPLATES to text node input")
func dompurifySanitizesTextNodeWithTemplates() {
  withDOMPurifyLock {
  let textNode = TextNode("{{value}}", nil)
  var config = DOMPurify.Configuration.default
  config.safeForTemplates = true

  #expect(DOMPurify.sanitize(textNode, config: config) == " ")
  }
}

@Test("DOMPurify should apply SAFE_FOR_TEMPLATES to data node input")
func dompurifySanitizesDataNodeWithTemplates() {
  withDOMPurifyLock {
  let dataNode = DataNode("{{value}}".utf8Array, "".utf8Array)
  var config = DOMPurify.Configuration.default
  config.safeForTemplates = true

  #expect(DOMPurify.sanitize(dataNode, config: config) == " ")
  }
}
