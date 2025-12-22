import Foundation
import Testing

@testable import SwiftDOMPurify

private enum Payload: Decodable, Sendable {
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

private struct SuiteTestCase: Decodable, Sendable {
  let name: String
  let kind: String
  let payload: Payload
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

private func loadDOMPurifySuiteTests() throws -> [SuiteTestCase] {
  guard let url = Bundle.module.url(    forResource: "suite-tests",
    withExtension: "json",
    subdirectory: "Fixtures"
  ) else {
    throw CocoaError(.fileNoSuchFile)
  }

  let data = try Data(contentsOf: url)
  return try JSONDecoder().decode([SuiteTestCase].self, from: data)
}

@Test("DOMPurify test-suite extracted cases: sanitize() output matches") func dompurifySuiteCases() throws {
  try withDOMPurifyLock {
  let cases = try loadDOMPurifySuiteTests()

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
    if let allowUnknownProtocols = jsConfig["ALLOW_UNKNOWN_PROTOCOLS"].flatMap(bool(from:)) {
      config.allowUnknownProtocols = allowUnknownProtocols
    }
    if let forceBody = jsConfig["FORCE_BODY"].flatMap(bool(from:)) {
      config.forceBody = forceBody
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
    if let addURISafeAttrs = jsConfig["ADD_URI_SAFE_ATTR"].flatMap(stringArray(from:)) {
      config.uriSafeAttributes.formUnion(addURISafeAttrs.map(transformCase))
    }
    if let addDataURITags = jsConfig["ADD_DATA_URI_TAGS"].flatMap(stringArray(from:)) {
      config.dataURITags.formUnion(addDataURITags.map(transformCase))
    }

    if let customElement = jsConfig["CUSTOM_ELEMENT_HANDLING"],
       case .object(let obj) = customElement {
      var handling = DOMPurify.CustomElementHandling()
      if let tagRegex = obj["tagNameCheck"].flatMap(regexObject(from:)) {
        handling.tagNameCheck = .init(source: tagRegex.source, flags: tagRegex.flags)
      }
      if let attrRegex = obj["attributeNameCheck"].flatMap(regexObject(from:)) {
        handling.attributeNameCheck = .init(source: attrRegex.source, flags: attrRegex.flags)
      }
      if let allow = obj["allowCustomizedBuiltInElements"].flatMap(bool(from:)) {
        handling.allowCustomizedBuiltInElements = allow
      }
      config.customElementHandling = handling
    }

    if let regex = jsConfig["ALLOWED_URI_REGEXP"].flatMap(regexObject(from:)) {
      config.allowedURIRegExp = .init(pattern: regex.source, isCaseInsensitive: regex.flags.contains("i"))
    }

    let actual: String
    if jsConfig["RETURN_DOM"].flatMap(bool(from:)) == true {
      switch testCase.payload {
      case .string(let string):
        actual = DOMPurify.sanitizeToDOM(string, config: config)
      case .strings(let strings):
        actual = DOMPurify.sanitizeToDOM(strings.joined(separator: ","), config: config)
      }
    } else if jsConfig["RETURN_DOM_FRAGMENT"].flatMap(bool(from:)) == true {
      switch testCase.payload {
      case .string(let string):
        actual = DOMPurify.sanitizeToFragment(string, config: config).firstChildNodeValue ?? ""
      case .strings(let strings):
        actual = DOMPurify.sanitizeToFragment(strings.joined(separator: ","), config: config).firstChildNodeValue ?? ""
      }
    } else {
      switch testCase.payload {
      case .string(let string):
        actual = DOMPurify.sanitize(string, config: config)
      case .strings(let strings):
        actual = DOMPurify.sanitize(strings, config: config)
      }
    }

    switch testCase.expected {
    case .string(let expected):
      let ok: Bool
      if testCase.kind == "equal" {
        ok = (actual == expected)
      } else {
        ok = actual.isEmpty || expected.contains(actual)
      }
      #expect(        ok,
        "Suite test[\(testCase.name)] failed.\nPayload: \(String(reflecting: testCase.payload))\nConfig: \(String(reflecting: jsConfig))\nActual: \(String(reflecting: actual))\nExpected: \(String(reflecting: expected))\nKind: \(testCase.kind)"
      )
    case .strings(let expected):
      #expect(        expected.contains(actual),
        "Suite test[\(testCase.name)] failed.\nPayload: \(String(reflecting: testCase.payload))\nConfig: \(String(reflecting: jsConfig))\nActual: \(String(reflecting: actual))\nExpected one of: \(expected.map { String(reflecting: $0) })\nKind: \(testCase.kind)"
      )
    }
  }
  }
}
