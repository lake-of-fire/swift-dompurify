import Foundation
import Testing

@testable import SwiftDOMPurify

private struct FixtureTestCase: Decodable, Sendable {
  let title: String?
  let payload: String
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

private func loadDOMPurifyFixtures() throws -> [FixtureTestCase] {
  guard let url = Bundle.module.url(    forResource: "expect",
    withExtension: "mjs",
    subdirectory: "Fixtures"
  ) else {
    throw CocoaError(.fileNoSuchFile)
  }

  let text = try String(contentsOf: url, encoding: .utf8)

  guard let exportRange = text.range(of: "export default") else {
    throw CocoaError(.fileReadCorruptFile)
  }

  guard let arrayStart = text[exportRange.upperBound...].firstIndex(of: "["),
        let arrayEnd = text.lastIndex(of: "]") else {
    throw CocoaError(.fileReadCorruptFile)
  }

  let jsonText = String(text[arrayStart...arrayEnd])
  let jsonData = Data(jsonText.utf8)

  return try JSONDecoder().decode([FixtureTestCase].self, from: jsonData)
}

@Test("DOMPurify fixtures: sanitize() output matches") func dompurifyFixtures() throws {
  try withDOMPurifyLock {
  let fixtures = try loadDOMPurifyFixtures()

  for (index, testCase) in fixtures.enumerated() {
    let actual = DOMPurify.sanitize(testCase.payload)
    let title = testCase.title ?? "#\(index)"

    switch testCase.expected {
    case .string(let expected):
      #expect(        actual.isEmpty || expected.contains(actual),
        "Fixture[\(title)] failed.\nPayload: \(String(reflecting: testCase.payload))\nActual: \(String(reflecting: actual))\nExpected: \(String(reflecting: expected))\nExpected to contain actual."
      )
    case .strings(let expected):
      #expect(        expected.contains(actual),
        "Fixture[\(title)] failed.\nPayload: \(String(reflecting: testCase.payload))\nActual: \(String(reflecting: actual))\nExpected one of: \(expected.map { String(reflecting: $0) })"
      )
    }
  }
  }
}
