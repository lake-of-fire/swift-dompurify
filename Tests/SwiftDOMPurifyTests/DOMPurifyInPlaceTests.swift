import SwiftSoup
import Testing

@testable import SwiftDOMPurify

@Test("Config-Flag tests: IN_PLACE") func dompurifyInPlaceSanitizesInPlace() throws {
  try withDOMPurifyLock {
  let doc = try SwiftSoup.parseBodyFragment("<a></a>")
  let dirty = try #require(doc.select("a").first())
  try dirty.attr("href", "javascript:alert(1)")

  let clean = try DOMPurify.sanitizeInPlace(dirty)
  #expect(dirty === clean)
  #expect(try dirty.attr("href") == "")
  }
}

@Test("Config-Flag tests: IN_PLACE insecure root-nodes (script)")
func dompurifyInPlaceThrowsOnForbiddenScriptRootNode() throws {
  try withDOMPurifyLock {
  let doc = try SwiftSoup.parseBodyFragment("<script></script>")
  let dirty = try #require(doc.select("script").first())
  try dirty.attr("src", "data:,alert(1)")

  var didThrow = false
  do {
    _ = try DOMPurify.sanitizeInPlace(dirty)
  } catch {
    didThrow = true
  }
  #expect(didThrow)
  }
}

@Test("Config-Flag tests: IN_PLACE insecure root-nodes (iframe)")
func dompurifyInPlaceThrowsOnForbiddenIFrameRootNode() throws {
  try withDOMPurifyLock {
  let doc = try SwiftSoup.parseBodyFragment("<iframe></iframe>")
  let dirty = try #require(doc.select("iframe").first())
  try dirty.attr("src", "javascript:alert(1)")

  var didThrow = false
  do {
    _ = try DOMPurify.sanitizeInPlace(dirty)
  } catch {
    didThrow = true
  }
  #expect(didThrow)
  }
}

