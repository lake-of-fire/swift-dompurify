import Foundation

enum JSONValue: Decodable, Sendable {
  case null
  case bool(Bool)
  case number(Double)
  case string(String)
  case array([JSONValue])
  case object([String: JSONValue])

  init(from decoder: Decoder) throws {
    let container = try decoder.singleValueContainer()
    if container.decodeNil() {
      self = .null
      return
    }
    if let bool = try? container.decode(Bool.self) {
      self = .bool(bool)
      return
    }
    if let number = try? container.decode(Double.self) {
      self = .number(number)
      return
    }
    if let string = try? container.decode(String.self) {
      self = .string(string)
      return
    }
    if let array = try? container.decode([JSONValue].self) {
      self = .array(array)
      return
    }
    self = .object(try container.decode([String: JSONValue].self))
  }
}

func stringArray(from value: JSONValue) -> [String]? {
  guard case .array(let array) = value else { return nil }
  var out: [String] = []
  out.reserveCapacity(array.count)
  for item in array {
    guard case .string(let string) = item else { return nil }
    out.append(string)
  }
  return out
}

func bool(from value: JSONValue) -> Bool? {
  guard case .bool(let bool) = value else { return nil }
  return bool
}

func string(from value: JSONValue) -> String? {
  guard case .string(let string) = value else { return nil }
  return string
}

func number(from value: JSONValue) -> Double? {
  guard case .number(let number) = value else { return nil }
  return number
}

func regexObject(from value: JSONValue) -> (source: String, flags: String)? {
  guard case .object(let obj) = value,
        case .string(let type)? = obj["__type"],
        type == "RegExp",
        case .string(let source)? = obj["source"],
        case .string(let flags)? = obj["flags"] else {
    return nil
  }
  return (source, flags)
}

private let domPurifyTestLock = NSLock()

@discardableResult
func withDOMPurifyLock<T>(_ body: () throws -> T) rethrows -> T {
  domPurifyTestLock.lock()
  defer { domPurifyTestLock.unlock() }
  return try body()
}
