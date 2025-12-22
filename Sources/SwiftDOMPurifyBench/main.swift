import Foundation
import SwiftDOMPurify
import SwiftSoup

func runHookRepro() {
  DOMPurify.removeAllHooks()
  defer { DOMPurify.removeAllHooks() }

  DOMPurify.addHook(.beforeSanitizeElements) { node, _ in
    guard let node = node as? Element else { return }
    _ = try? node.attr("data-before-elements", "1")
  }
  DOMPurify.addHook(.beforeSanitizeAttributes) { node, _ in
    guard let node = node as? Element else { return }
    _ = try? node.attr("data-before-attrs", "1")
  }
  DOMPurify.addHook(.afterSanitizeAttributes) { node, _ in
    guard let node = node as? Element else { return }
    _ = try? node.attr("data-after-attrs", "1")
  }
  DOMPurify.addHook(.afterSanitizeElements) { node, _ in
    guard let node = node as? Element else { return }
    _ = try? node.attr("data-after-elements", "1")
  }

  let dirty = "<div></div>"
  let sanitized = DOMPurify.sanitize(dirty)
  print(sanitized)
}

if CommandLine.arguments.contains("--hook-repro") {
  runHookRepro()
  exit(0)
}

let iterations: Int = {
  for arg in CommandLine.arguments.dropFirst() {
    if let value = Int(arg) {
      return value
    }
  }
  return 2000
}()
let payload = "<div><a href=\"javascript:alert(1)\">x</a><svg><filter></filter></svg><math><mi></mi></math></div>"
let shouldWait = CommandLine.arguments.contains("--profile-wait")

if CommandLine.arguments.contains("--node-bench") {
  if shouldWait {
    Thread.sleep(forTimeInterval: 2.0)
  }
  let doc = try SwiftSoup.parse(payload)
  let body = doc.body() ?? doc
  bench("sanitize(node)") {
    DOMPurify.sanitize(body).count
  }
  bench("sanitizeToDOM(node)") {
    DOMPurify.sanitizeToDOM(body).count
  }
  bench("sanitizeToDocumentTree(node)") {
    let doc = DOMPurify.sanitizeToDocumentTree(body)
    return (try? doc.outerHtml().count) ?? 0
  }
  exit(0)
}

func bench(_ name: String, _ block: () -> Int) {
  let start = DispatchTime.now().uptimeNanoseconds
  var totalLength = 0
  for _ in 0..<iterations {
    totalLength += block()
  }
  let end = DispatchTime.now().uptimeNanoseconds
  let ms = Double(end - start) / 1_000_000.0
  let msString = String(format: "%.2f", ms)
  print("\(name) iterations=\(iterations) totalLength=\(totalLength) ms=\(msString)")
}

bench("sanitize") {
  DOMPurify.sanitize(payload).count
}

bench("sanitizeToDOM") {
  DOMPurify.sanitizeToDOM(payload).count
}

bench("sanitizeToDocumentTree") {
  let doc = DOMPurify.sanitizeToDocumentTree(payload)
  return (try? doc.outerHtml().count) ?? 0
}
