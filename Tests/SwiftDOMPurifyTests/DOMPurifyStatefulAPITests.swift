import Foundation
import SwiftSoup
import Testing

@testable import SwiftDOMPurify

private func appendClass(_ element: Element, token: String) {
  let existing = (try? element.attr("class")) ?? ""
  var tokens = existing.split(whereSeparator: { $0.isWhitespace }).map(String.init)
  if !tokens.contains(token) {
    tokens.append(token)
  }
  let joined = tokens.joined(separator: " ")
  _ = try? element.attr("class", joined)
}

@Test("DOMPurify stateful API: setConfig/clearConfig") func dompurifyPersistentConfigSetAndCleared() {
  withDOMPurifyLock {
    DOMPurify.clearConfig()
    defer { DOMPurify.clearConfig() }

    let dirty = "<foobar>abc</foobar>"
    #expect(DOMPurify.sanitize(dirty) == "abc")

    var config = DOMPurify.Configuration.default
    config.allowedTags.insert("foobar")
    DOMPurify.setConfig(config)
    #expect(DOMPurify.sanitize(dirty) == "<foobar>abc</foobar>")

    DOMPurify.clearConfig()
    #expect(DOMPurify.sanitize(dirty) == "abc")
  }
}

@Test("DOMPurify hooks: allow custom tags/attrs on the fly") func dompurifyHooksAllowCustomTagsAndAttributes() {
  withDOMPurifyLock {
    DOMPurify.removeAllHooks()
    defer { DOMPurify.removeAllHooks() }

    let customPattern = try! NSRegularExpression(pattern: #"^\w+-\w+$"#, options: [])

    DOMPurify.addHook(.uponSanitizeElement) { node, data in
      guard let node = node as? Element else { return }
      guard let data,
            let tagName = data.tagName,
            let allowedTags = data.allowedTags
      else { return }

      let nodeName = node.tagName()
      if customPattern.firstMatch(in: nodeName, options: [], range: NSRange(nodeName.startIndex..., in: nodeName)) != nil,
         !allowedTags[tagName] {
        allowedTags[tagName] = true
      }
    }

    DOMPurify.addHook(.uponSanitizeAttribute) { _node, data in
      guard let data,
            let attrName = data.attrName,
            let allowedAttributes = data.allowedAttributes
      else { return }

      if customPattern.firstMatch(in: attrName, options: [], range: NSRange(attrName.startIndex..., in: attrName)) != nil,
         !allowedAttributes[attrName] {
        allowedAttributes[attrName] = true
      }
    }

    let dirty =
      "<p>HE<iframe></iframe><is-custom onload=\"alert(1)\" super-custom=\"test\" />LLO</p>"
    let expected = "<p>HE<is-custom super-custom=\"test\">LLO</is-custom></p>"
    #expect(DOMPurify.sanitize(dirty) == expected)
  }
}

@Test("DOMPurify hooks: removeHook pops and can re-add") func dompurifyRemoveHookReturnsHook() {
  withDOMPurifyLock {
    DOMPurify.removeAllHooks()
    defer { DOMPurify.removeAllHooks() }

    let dirty = "<div class=\"hello\"></div>"
    let expected = "<div class=\"world\"></div>"

    _ = DOMPurify.addHook(.afterSanitizeAttributes) { node, _ in
      guard let node = node as? Element else { return }
      _ = try? node.attr("class", "world")
    }
    #expect(DOMPurify.sanitize(dirty) == expected)

    let removed = DOMPurify.removeHook(.afterSanitizeAttributes)
    #expect(DOMPurify.sanitize(dirty) == dirty)

    if let removed {
      DOMPurify.addHook(removed)
    }
    #expect(DOMPurify.sanitize(dirty) == expected)

    _ = DOMPurify.removeHook(.afterSanitizeAttributes)
  }
}

@Test("DOMPurify hooks: removeHook can remove a specific hook") func dompurifyRemoveHookByReference() {
  withDOMPurifyLock {
    DOMPurify.removeAllHooks()
    defer { DOMPurify.removeAllHooks() }

    let dirty = "<div class=\"original\"></div>"
    let expected = "<div class=\"original first third\"></div>"

    let firstHook = DOMPurify.addHook(.afterSanitizeAttributes) { node, _ in
      guard let node = node as? Element else { return }
      appendClass(node, token: "first")
    }
    let secondHook = DOMPurify.addHook(.afterSanitizeAttributes) { node, _ in
      guard let node = node as? Element else { return }
      appendClass(node, token: "second")
    }
    let thirdHook = DOMPurify.addHook(.afterSanitizeAttributes) { node, _ in
      guard let node = node as? Element else { return }
      appendClass(node, token: "third")
    }

    #expect(DOMPurify.removeHook(.afterSanitizeAttributes, secondHook) === secondHook)
    #expect(DOMPurify.removeHook(.afterSanitizeAttributes, secondHook) == nil)
    #expect(DOMPurify.sanitize(dirty) == expected)

    _ = DOMPurify.removeHook(.afterSanitizeAttributes, firstHook)
    _ = DOMPurify.removeHook(.afterSanitizeAttributes, thirdHook)
  }
}

@Test("DOMPurify hooks: keepAttr false removes attributes") func dompurifyHookKeepAttrRemovesInputType() {
  withDOMPurifyLock {
    DOMPurify.removeAllHooks()
    defer { DOMPurify.removeAllHooks() }

    DOMPurify.addHook(.uponSanitizeAttribute) { node, data in
      guard let node = node as? Element else { return }
      guard let data else { return }
      guard node.tagName().lowercased() == "input" else { return }
      guard let type = try? node.attr("type"), type == "file" else { return }
      data.keepAttr = false
    }

    let dirty = "<input type=\"file\" />"
    #expect(DOMPurify.sanitize(dirty) == "<input>")
  }
}

@Test("DOMPurify hooks: forceKeepAttr preserves unsafe attributes") func dompurifyHookForceKeepAttr() {
  withDOMPurifyLock {
    DOMPurify.removeAllHooks()
    defer { DOMPurify.removeAllHooks() }

    DOMPurify.addHook(.uponSanitizeAttribute) { _node, data in
      guard let data, data.attrName == "onclick" else { return }
      data.forceKeepAttr = true
    }

    let dirty = "<a onclick=\"alert(1)\">link</a>"
    #expect(DOMPurify.sanitize(dirty) == "<a onclick=\"alert(1)\">link</a>")
  }
}

@Test("DOMPurify hooks: attrValue can be mutated") func dompurifyHookMutatesAttributeValue() {
  withDOMPurifyLock {
    DOMPurify.removeAllHooks()
    defer { DOMPurify.removeAllHooks() }

    DOMPurify.addHook(.uponSanitizeAttribute) { _node, data in
      guard let data, data.attrName == "href" else { return }
      data.attrValue = "https://example.com"
    }

    let dirty = "<a href=\"javascript:alert(1)\">link</a>"
    #expect(DOMPurify.sanitize(dirty) == "<a href=\"https://example.com\">link</a>")
  }
}

@Test("DOMPurify hooks: before/after sanitize hooks fire") func dompurifyBeforeAfterHooksFire() {
  withDOMPurifyLock {
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
  let expected = "<div data-before-elements=\"1\" data-before-attrs=\"1\" data-after-attrs=\"1\" data-after-elements=\"1\"></div>"
  #expect(DOMPurify.sanitize(dirty) == expected)
  }
}

@Test("DOMPurify hooks: shadow DOM hooks fire") func dompurifyShadowHooksFire() {
  withDOMPurifyLock {
    DOMPurify.removeAllHooks()
    defer { DOMPurify.removeAllHooks() }

    DOMPurify.addHook(.beforeSanitizeShadowDOM) { node, _ in
      guard let node = node as? Element else { return }
      _ = try? node.attr("data-shadow-before", "1")
    }
    DOMPurify.addHook(.afterSanitizeShadowDOM) { node, _ in
      guard let node = node as? Element else { return }
      _ = try? node.attr("data-shadow-after", "1")
    }
    DOMPurify.addHook(.uponSanitizeShadowNode) { node, _ in
      guard let node = node as? Element else { return }
      _ = try? node.attr("class", "shadow-node")
    }

    var config = DOMPurify.Configuration.default
    config.allowedAttributes.insert("shadowroot")

    let dirty = "<template shadowroot=\"open\"><div></div></template>"
    let clean = DOMPurify.sanitize(dirty, config: config)
    #expect(clean.contains("shadowroot=\"open\""))
    #expect(clean.contains("data-shadow-before=\"1\""))
    #expect(clean.contains("data-shadow-after=\"1\""))
    #expect(clean.contains("<div class=\"shadow-node\"></div>"))
  }
}

@Test("DOMPurify hooks: shadowrootmode attribute triggers hooks") func dompurifyShadowModeHooksFire() {
  withDOMPurifyLock {
    DOMPurify.removeAllHooks()
    defer { DOMPurify.removeAllHooks() }

    DOMPurify.addHook(.beforeSanitizeShadowDOM) { node, _ in
      guard let node = node as? Element else { return }
      _ = try? node.attr("data-shadow-mode-before", "1")
    }
    DOMPurify.addHook(.afterSanitizeShadowDOM) { node, _ in
      guard let node = node as? Element else { return }
      _ = try? node.attr("data-shadow-mode-after", "1")
    }

    var config = DOMPurify.Configuration.default
    config.allowedAttributes.formUnion(["shadowrootmode", "data-shadow-mode-before", "data-shadow-mode-after"])

    let dirty = "<template shadowrootmode=\"open\"><span></span></template>"
    let clean = DOMPurify.sanitize(dirty, config: config)
    #expect(clean.contains("shadowrootmode=\"open\""))
    #expect(clean.contains("data-shadow-mode-before=\"1\""))
    #expect(clean.contains("data-shadow-mode-after=\"1\""))
  }
}

@Test("DOMPurify hooks: beforeSanitizeElements sees text nodes") func dompurifyHookSeesTextNode() {
  withDOMPurifyLock {
    DOMPurify.removeAllHooks()
    defer { DOMPurify.removeAllHooks() }

    var sawTextNode = false
    DOMPurify.addHook(.beforeSanitizeElements) { node, _ in
      if node is TextNode {
        sawTextNode = true
      }
    }

    _ = DOMPurify.sanitize("<span>hello</span>")
    #expect(sawTextNode)
  }
}

@Test("DOMPurify hooks: uponSanitizeShadowNode sees text nodes") func dompurifyShadowHookSeesTextNode() {
  withDOMPurifyLock {
    DOMPurify.removeAllHooks()
    defer { DOMPurify.removeAllHooks() }

    var sawTextNode = false
    DOMPurify.addHook(.uponSanitizeShadowNode) { node, _ in
      if node is TextNode {
        sawTextNode = true
      }
    }

    var config = DOMPurify.Configuration.default
    config.allowedAttributes.insert("shadowroot")

    _ = DOMPurify.sanitize("<template shadowroot=\"open\">hello</template>", config: config)
    #expect(sawTextNode)
  }
}

@Test("DOMPurify hooks: beforeSanitizeElements sees comment nodes") func dompurifyHookSeesCommentNode() {
  withDOMPurifyLock {
    DOMPurify.removeAllHooks()
    defer { DOMPurify.removeAllHooks() }

    var sawCommentNode = false
    DOMPurify.addHook(.beforeSanitizeElements) { node, _ in
      if node is SwiftSoup.Comment {
        sawCommentNode = true
      }
    }

    _ = DOMPurify.sanitize("<div><!--x--></div>")
    #expect(sawCommentNode)
  }
}

@Test("DOMPurify hooks: beforeSanitizeElements sees data nodes") func dompurifyHookSeesDataNode() {
  withDOMPurifyLock {
    DOMPurify.removeAllHooks()
    defer { DOMPurify.removeAllHooks() }

    var sawDataNode = false
    DOMPurify.addHook(.beforeSanitizeElements) { node, _ in
      if node is DataNode {
        sawDataNode = true
      }
    }

    let dataNode = DataNode("body{color:red}".utf8Array, "".utf8Array)
    _ = DOMPurify.sanitize(dataNode)
    #expect(sawDataNode)
  }
}

@Test("DOMPurify hooks: afterSanitizeElements sees text nodes") func dompurifyAfterHookSeesTextNode() {
  withDOMPurifyLock {
    DOMPurify.removeAllHooks()
    defer { DOMPurify.removeAllHooks() }

    var sawTextNode = false
    DOMPurify.addHook(.afterSanitizeElements) { node, _ in
      if node is TextNode {
        sawTextNode = true
      }
    }

    _ = DOMPurify.sanitize("<span>hello</span>")
    #expect(sawTextNode)
  }
}

@Test("DOMPurify hooks: afterSanitizeElements sees data nodes") func dompurifyAfterHookSeesDataNode() {
  withDOMPurifyLock {
    DOMPurify.removeAllHooks()
    defer { DOMPurify.removeAllHooks() }

    var sawDataNode = false
    DOMPurify.addHook(.afterSanitizeElements) { node, _ in
      if node is DataNode {
        sawDataNode = true
      }
    }

    let dataNode = DataNode("body{color:red}".utf8Array, "".utf8Array)
    _ = DOMPurify.sanitize(dataNode)
    #expect(sawDataNode)
  }
}

@Test("DOMPurify hooks: can mutate text nodes") func dompurifyHookMutatesTextNodes() {
  withDOMPurifyLock {
    DOMPurify.removeAllHooks()
    defer { DOMPurify.removeAllHooks() }

    DOMPurify.addHook(.afterSanitizeElements) { node, _ in
      guard let text = node as? TextNode else { return }
      _ = text.text("changed")
    }

    let dirty = "<span>hello</span>"
    #expect(DOMPurify.sanitize(dirty) == "<span>changed</span>")
  }
}

@Test("DOMPurify hooks: removeHooks clears entry") func dompurifyRemoveHooksClearsEntry() {
  withDOMPurifyLock {
    DOMPurify.removeAllHooks()
    defer { DOMPurify.removeAllHooks() }

    DOMPurify.addHook(.afterSanitizeAttributes) { node, _ in
      guard let node = node as? Element else { return }
      _ = try? node.attr("data-hooked", "1")
    }

    let dirty = "<div></div>"
    #expect(DOMPurify.sanitize(dirty) == "<div data-hooked=\"1\"></div>")

    DOMPurify.removeHooks(.afterSanitizeAttributes)
    #expect(DOMPurify.sanitize(dirty) == "<div></div>")
  }
}

@Test("DOMPurify hooks: removeAllHooks clears all entry points") func dompurifyRemoveAllHooksClears() {
  withDOMPurifyLock {
    DOMPurify.removeAllHooks()
    defer { DOMPurify.removeAllHooks() }

    DOMPurify.addHook(.afterSanitizeAttributes) { node, _ in
      guard let node = node as? Element else { return }
      _ = try? node.attr("data-hooked", "1")
    }
    DOMPurify.addHook(.beforeSanitizeElements) { node, _ in
      guard let node = node as? Element else { return }
      _ = try? node.attr("data-before", "1")
    }

    let dirty = "<div></div>"
    #expect(DOMPurify.sanitize(dirty) == "<div data-before=\"1\" data-hooked=\"1\"></div>")

    DOMPurify.removeAllHooks()
    #expect(DOMPurify.sanitize(dirty) == "<div></div>")
  }
}

@Test("DOMPurify hooks: uponSanitizeShadowNode sees comment nodes") func dompurifyShadowHookSeesCommentNode() {
  withDOMPurifyLock {
    DOMPurify.removeAllHooks()
    defer { DOMPurify.removeAllHooks() }

    var sawCommentNode = false
    DOMPurify.addHook(.uponSanitizeShadowNode) { node, _ in
      if node is SwiftSoup.Comment {
        sawCommentNode = true
      }
    }

    var config = DOMPurify.Configuration.default
    config.allowedAttributes.insert("shadowroot")

    _ = DOMPurify.sanitize("<template shadowroot=\"open\"><!--x--></template>", config: config)
    #expect(sawCommentNode)
  }
}

@Test("DOMPurify hooks: uponSanitizeShadowNode sees data nodes") func dompurifyShadowHookSeesDataNode() {
  withDOMPurifyLock {
    DOMPurify.removeAllHooks()
    defer { DOMPurify.removeAllHooks() }

    var sawDataNode = false
    DOMPurify.addHook(.uponSanitizeShadowNode) { node, _ in
      if node is DataNode {
        sawDataNode = true
      }
    }

    var config = DOMPurify.Configuration.default
    config.allowedAttributes.insert("shadowroot")

    _ = DOMPurify.sanitize(      "<template shadowroot=\"open\"><style>body{color:red}</style></template>",
      config: config
    )
    #expect(sawDataNode)
  }
}
