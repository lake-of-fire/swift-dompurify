import Foundation

enum DOMPurifyUTF8Util {
  @inline(__always)
  static func asciiLowercased(_ bytes: [UInt8]) -> [UInt8] {
    var lowered = bytes
    for i in lowered.indices {
      let b = lowered[i]
      if b >= 65 && b <= 90 {
        lowered[i] = b &+ 32
      }
    }
    return lowered
  }

  @inline(__always)
  static func lowercasedUnicode(_ bytes: [UInt8]) -> [UInt8] {
    var hasUpperASCII = false
    for b in bytes {
      if b >= 128 {
        return String(decoding: bytes, as: UTF8.self).lowercased().utf8Array
      }
      if b >= 65 && b <= 90 {
        hasUpperASCII = true
      }
    }
    return hasUpperASCII ? asciiLowercased(bytes) : bytes
  }

  @inline(__always)
  static func containsASCII(lowercasedNeedle needle: [UInt8], in haystack: [UInt8]) -> Bool {
    guard !needle.isEmpty else { return true }
    guard haystack.count >= needle.count else { return false }
    let lastStart = haystack.count - needle.count
    var i = 0
    while i <= lastStart {
      var j = 0
      while j < needle.count {
        var b = haystack[i + j]
        if b >= 65 && b <= 90 {
          b &+= 32
        }
        if b != needle[j] {
          break
        }
        j &+= 1
      }
      if j == needle.count {
        return true
      }
      i &+= 1
    }
    return false
  }
}
