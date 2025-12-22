import Foundation
import Testing

@testable import SwiftDOMPurify

private struct RemovedTestCase: Decodable, Sendable {
  let name: String
  let kind: String
  let payload: String
  let config: [String: JSONValue]?
  let expected: Expected

  enum Expected: Decodable, Sendable {
    case number(Int)
    case numbers([Int])

    init(from decoder: Decoder) throws {
      let container = try decoder.singleValueContainer()
      if let int = try? container.decode(Int.self) {
        self = .number(int)
        return
      }
      if let doubles = try? container.decode([Double].self) {
        self = .numbers(doubles.map { Int($0) })
        return
      }
      let double = try container.decode(Double.self)
      self = .number(Int(double))
    }
  }
}

private func loadDOMPurifyRemovedTests() throws -> [RemovedTestCase] {
  guard let url = Bundle.module.url(    forResource: "removed-tests",
    withExtension: "json",
    subdirectory: "Fixtures"
  ) else {
    throw CocoaError(.fileNoSuchFile)
  }

  let data = try Data(contentsOf: url)
  return try JSONDecoder().decode([RemovedTestCase].self, from: data)
}

@Test("DOMPurify test-suite removed cases: DOMPurify.removed count matches") func dompurifyRemovedCases() throws {
  try withDOMPurifyLock {
  let cases = try loadDOMPurifyRemovedTests()

  for testCase in cases {
    let jsConfig = testCase.config ?? [:]
    var config = DOMPurify.Configuration.default

    if let safeForTemplates = jsConfig["SAFE_FOR_TEMPLATES"].flatMap(bool(from:)) {
      config.safeForTemplates = safeForTemplates
    }
    if let wholeDocument = jsConfig["WHOLE_DOCUMENT"].flatMap(bool(from:)) {
      config.wholeDocument = wholeDocument
    }

    let result = DOMPurify.sanitizeAndGetRemoved(testCase.payload, config: config)
    let removedCount = result.removed.count

    switch testCase.expected {
    case .number(let expected):
      let ok: Bool
      if testCase.kind == "equal" {
        ok = (removedCount == expected)
      } else {
        ok = (removedCount == expected)
      }
      #expect(        ok,
        "Removed test[\(testCase.name)] failed.\nPayload: \(String(reflecting: testCase.payload))\nConfig: \(String(reflecting: jsConfig))\nActual removed count: \(removedCount)\nExpected: \(expected)\nKind: \(testCase.kind)"
      )
    case .numbers(let expected):
      if testCase.kind == "contains" {
        #expect(          expected.contains(removedCount),
          "Removed test[\(testCase.name)] failed.\nPayload: \(String(reflecting: testCase.payload))\nConfig: \(String(reflecting: jsConfig))\nActual removed count: \(removedCount)\nExpected one of: \(expected)\nKind: \(testCase.kind)"
        )
      } else {
        #expect(          expected.contains(removedCount),
          "Removed test[\(testCase.name)] failed.\nPayload: \(String(reflecting: testCase.payload))\nConfig: \(String(reflecting: jsConfig))\nActual removed count: \(removedCount)\nExpected one of: \(expected)\nKind: \(testCase.kind)"
        )
      }
    }
  }
  }
}
