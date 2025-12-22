import Foundation
import Testing

@testable import SwiftDOMPurify

private struct ConfigTestCase: Decodable, Sendable {
  let name: String
  let kind: String
  let payload: String
  let config: [String: JSONValue]?
  let expected: Expected

  enum Expected: Decodable, Sendable {
    case string(String)
    case strings([String])

    init(from decoder: Decoder) throws {
      let container = try decoder.singleValueContainer()
      if let string = try? container.decode(String.self) {
        self = .string(string)
        return
      }
      self = .strings(try container.decode([String].self))
    }
  }
}

private func loadDOMPurifyConfigTests() throws -> [ConfigTestCase] {
  guard let url = Bundle.module.url(    forResource: "config-tests",
    withExtension: "json",
    subdirectory: "Fixtures"
  ) else {
    throw CocoaError(.fileNoSuchFile)
  }

  let data = try Data(contentsOf: url)
  return try JSONDecoder().decode([ConfigTestCase].self, from: data)
}

@Test("DOMPurify test-suite config cases: sanitize() output matches") func dompurifyConfigCases() throws {
  try withDOMPurifyLock {
  let cases = try loadDOMPurifyConfigTests()

  for testCase in cases {
    let jsConfig = testCase.config ?? [:]
    var config = DOMPurify.Configuration.default

    if let mediaType = jsConfig["PARSER_MEDIA_TYPE"].flatMap(string(from:)),
       mediaType == DOMPurify.ParserMediaType.applicationXHTMLXML.rawValue {
      config.parserMediaType = .applicationXHTMLXML
    }

    if let namespace = jsConfig["NAMESPACE"].flatMap(string(from:)) {
      config.namespaceURI = namespace
    }

    if let allowedNamespaces = jsConfig["ALLOWED_NAMESPACES"].flatMap(stringArray(from:)) {
      config.allowedNamespaceURIs = Set(allowedNamespaces)
    }

    let transformCase: (String) -> String = config.parserMediaType == .applicationXHTMLXML
      ? { $0 }
      : { $0.lowercased() }

    if let useProfilesValue = jsConfig["USE_PROFILES"] {
      if case .object(let profileObject) = useProfilesValue {
        config.useProfiles = .init(          html: profileObject["html"].flatMap(bool(from:)) == true,
          svg: profileObject["svg"].flatMap(bool(from:)) == true,
          svgFilters: profileObject["svgFilters"].flatMap(bool(from:)) == true,
          mathML: profileObject["mathMl"].flatMap(bool(from:)) == true
        )
      } else {
        config.useProfiles = .init()
      }
    }

    if let keepContent = jsConfig["KEEP_CONTENT"].flatMap(bool(from:)) {
      config.keepContent = keepContent
    }
    if let safeForTemplates = jsConfig["SAFE_FOR_TEMPLATES"].flatMap(bool(from:)) {
      config.safeForTemplates = safeForTemplates
    }
    if let sanitizeDOM = jsConfig["SANITIZE_DOM"].flatMap(bool(from:)) {
      config.sanitizeDOM = sanitizeDOM
    }
    if let sanitizeNamedProps = jsConfig["SANITIZE_NAMED_PROPS"].flatMap(bool(from:)) {
      config.sanitizeNamedProps = sanitizeNamedProps
    }
    if let allowData = jsConfig["ALLOW_DATA_ATTR"].flatMap(bool(from:)) {
      config.allowDataAttributes = allowData
    }
    if let allowAria = jsConfig["ALLOW_ARIA_ATTR"].flatMap(bool(from:)) {
      config.allowAriaAttributes = allowAria
    }
    if let allowSelfClose = jsConfig["ALLOW_SELF_CLOSE_IN_ATTR"].flatMap(bool(from:)) {
      config.allowSelfCloseInAttributes = allowSelfClose
    }
    if let wholeDocument = jsConfig["WHOLE_DOCUMENT"].flatMap(bool(from:)) {
      config.wholeDocument = wholeDocument
    }

    if let allowedTags = jsConfig["ALLOWED_TAGS"].flatMap(stringArray(from:)) {
      config.allowedTags = Set(allowedTags.map(transformCase))
    }
    if let allowedAttrs = jsConfig["ALLOWED_ATTR"].flatMap(stringArray(from:)) {
      config.allowedAttributes = Set(allowedAttrs.map(transformCase))
    }
    if let forbidTags = jsConfig["FORBID_TAGS"].flatMap(stringArray(from:)) {
      config.forbidTags = Set(forbidTags.map(transformCase))
    }
    if let forbidAttrs = jsConfig["FORBID_ATTR"].flatMap(stringArray(from:)) {
      config.forbidAttributes = Set(forbidAttrs.map(transformCase))
    }
    if let forbidContents = jsConfig["FORBID_CONTENTS"].flatMap(stringArray(from:)) {
      config.forbidContents = Set(forbidContents.map(transformCase))
    }

    if let addTags = jsConfig["ADD_TAGS"].flatMap(stringArray(from:)) {
      config.addTags.formUnion(addTags.map(transformCase))
    }
    if let addAttrs = jsConfig["ADD_ATTR"].flatMap(stringArray(from:)) {
      config.addAttributes.formUnion(addAttrs.map(transformCase))
    }
    if let addForbidContents = jsConfig["ADD_FORBID_CONTENTS"].flatMap(stringArray(from:)) {
      config.forbidContents.formUnion(addForbidContents.map(transformCase))
    }

    if let regex = jsConfig["ALLOWED_URI_REGEXP"].flatMap(regexObject(from:)) {
      config.allowedURIRegExp = .init(pattern: regex.source, isCaseInsensitive: regex.flags.contains("i"))
    }

    let actual: String
    if jsConfig["RETURN_DOM"].flatMap(bool(from:)) == true {
      actual = DOMPurify.sanitizeToDOM(testCase.payload, config: config)
    } else if jsConfig["RETURN_DOM_FRAGMENT"].flatMap(bool(from:)) == true {
      actual = DOMPurify.sanitizeToFragment(testCase.payload, config: config).firstChildNodeValue ?? ""
    } else {
      actual = DOMPurify.sanitize(testCase.payload, config: config)
    }

    switch testCase.expected {
    case .string(let expected):
      let ok: Bool
      if testCase.kind == "equal" {
        ok = (actual == expected)
      } else {
        // Mirror QUnit assert.contains(): `expected.indexOf(actual) > -1`
        // In JS, every string contains the empty string.
        ok = actual.isEmpty || expected.contains(actual)
      }
      #expect(        ok,
        "Config test[\(testCase.name)] failed.\nPayload: \(String(reflecting: testCase.payload))\nConfig: \(String(reflecting: jsConfig))\nActual: \(String(reflecting: actual))\nExpected: \(String(reflecting: expected))\nKind: \(testCase.kind)"
      )
    case .strings(let expected):
      if testCase.kind == "equal" {
        #expect(          expected.contains(actual),
          "Config test[\(testCase.name)] failed.\nPayload: \(String(reflecting: testCase.payload))\nConfig: \(String(reflecting: jsConfig))\nActual: \(String(reflecting: actual))\nExpected one of: \(expected.map { String(reflecting: $0) })\nKind: \(testCase.kind)"
        )
      } else {
        #expect(          expected.contains(actual),
          "Config test[\(testCase.name)] failed.\nPayload: \(String(reflecting: testCase.payload))\nConfig: \(String(reflecting: jsConfig))\nActual: \(String(reflecting: actual))\nExpected one of: \(expected.map { String(reflecting: $0) })\nKind: \(testCase.kind)"
        )
      }
    }
  }
  }
}

@Test("DOMPurify USE_PROFILES combines with ADD_TAGS/ADD_ATTR")
func dompurifyUseProfilesAdditions() {
  withDOMPurifyLock {
  var config = DOMPurify.Configuration.default
  config.useProfiles = .init(svg: true)
  config.addTags = ["div"]
  config.addAttributes = ["keep"]

  let clean = DOMPurify.sanitize("<svg></svg><div keep=\"1\"></div>", config: config)
  #expect(clean.contains("<svg></svg>"))
  #expect(clean.contains("<div"))
  #expect(clean.contains("keep=\"1\""))
  }
}

@Test("DOMPurify USE_PROFILES svgFilters combines with ADD_TAGS")
func dompurifyUseProfilesSvgFiltersAdditions() {
  withDOMPurifyLock {
  var config = DOMPurify.Configuration.default
  config.useProfiles = .init(svg: true, svgFilters: true)
  config.addTags = ["div"]

  let clean = DOMPurify.sanitize("<svg><filter></filter></svg><div></div>", config: config)
  #expect(clean.contains("<filter></filter>") || clean.contains("<filter />"))
  #expect(clean.contains("<div></div>"))
  }
}
