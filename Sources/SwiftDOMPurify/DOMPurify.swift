import Foundation
import SwiftSoup

public enum DOMPurify {
  private final class Locked<Value>: @unchecked Sendable {
    private var value: Value
    private let lock = NSRecursiveLock()

    init(_ value: Value) {
      self.value = value
    }

    func withLock<Result>(_ body: (inout Value) throws -> Result) rethrows -> Result {
      lock.lock()
      defer { lock.unlock() }
      return try body(&value)
    }

    func withLock<Result>(_ body: () throws -> Result) rethrows -> Result {
      lock.lock()
      defer { lock.unlock() }
      return try body()
    }

    func get() -> Value {
      withLock { $0 }
    }

    func set(_ newValue: Value) {
      withLock { $0 = newValue }
    }
  }

  private static let removedStorage = Locked<[RemovedItem]>([])
  private static let sanitizeGate = Locked(())
  private static let persistentConfigStorage = Locked<Configuration?>(nil)
  private static let hooksStorage = Locked<[HookName: [Hook]]>([:])

  enum Hooks {
    static func snapshot() -> [HookName: [Hook]] {
      hooksStorage.get()
    }
  }

  static func _withGlobalLock<Result>(_ body: () throws -> Result) rethrows -> Result {
    try sanitizeGate.withLock { try body() }
  }

  public enum HookName: String, Sendable {
    case afterSanitizeAttributes
    case afterSanitizeElements
    case afterSanitizeShadowDOM
    case beforeSanitizeAttributes
    case beforeSanitizeElements
    case beforeSanitizeShadowDOM
    case uponSanitizeAttribute
    case uponSanitizeElement
    case uponSanitizeShadowNode
  }

  public struct AllowedSetProxy: @unchecked Sendable {
    private let containsValue: (String) -> Bool
    private let setValue: (String, Bool) -> Void

    init(contains: @escaping (String) -> Bool, set: @escaping (String, Bool) -> Void) {
      self.containsValue = contains
      self.setValue = set
    }

    public subscript(_ key: String) -> Bool {
      get { containsValue(key) }
      nonmutating set { setValue(key, newValue) }
    }
  }

  public final class HookEvent: @unchecked Sendable {
    public let tagName: String?
    public let allowedTags: AllowedSetProxy?

    public let attrName: String?
    public var attrValue: String?
    public let allowedAttributes: AllowedSetProxy?

    public var keepAttr: Bool
    public var forceKeepAttr: Bool?

    init(
      tagName: String?,
      allowedTags: AllowedSetProxy?,
      attrName: String?,
      attrValue: String?,
      allowedAttributes: AllowedSetProxy?,
      keepAttr: Bool,
      forceKeepAttr: Bool?
    ) {
      self.tagName = tagName
      self.allowedTags = allowedTags
      self.attrName = attrName
      self.attrValue = attrValue
      self.allowedAttributes = allowedAttributes
      self.keepAttr = keepAttr
      self.forceKeepAttr = forceKeepAttr
    }
  }

  public typealias HookCallback = (Node, HookEvent?) -> Void

  public final class Hook: @unchecked Sendable {
    public let entryPoint: HookName
    let callback: HookCallback

    init(entryPoint: HookName, callback: @escaping HookCallback) {
      self.entryPoint = entryPoint
      self.callback = callback
    }
  }

  @discardableResult
  public static func addHook(_ entryPoint: HookName, _ hookFunction: @escaping HookCallback) -> Hook {
    sanitizeGate.withLock {
      let hook = Hook(entryPoint: entryPoint, callback: hookFunction)
      hooksStorage.withLock { hooksByName in
        hooksByName[entryPoint, default: []].append(hook)
      }
      return hook
    }
  }

  public static func addHook(_ hook: Hook) {
    sanitizeGate.withLock {
      hooksStorage.withLock { hooksByName in
        hooksByName[hook.entryPoint, default: []].append(hook)
      }
    }
  }

  @discardableResult
  public static func removeHook(_ entryPoint: HookName) -> Hook? {
    sanitizeGate.withLock {
      hooksStorage.withLock { hooksByName in
        guard var hooks = hooksByName[entryPoint], !hooks.isEmpty else { return nil }
        let removed = hooks.removeLast()
        hooksByName[entryPoint] = hooks
        return removed
      }
    }
  }

  @discardableResult
  public static func removeHook(_ entryPoint: HookName, _ hook: Hook) -> Hook? {
    sanitizeGate.withLock {
      hooksStorage.withLock { hooksByName in
        guard var hooks = hooksByName[entryPoint], !hooks.isEmpty else { return nil }
        guard let index = hooks.firstIndex(where: { $0 === hook }) else { return nil }
        let removed = hooks.remove(at: index)
        hooksByName[entryPoint] = hooks
        return removed
      }
    }
  }

  public static func removeHooks(_ entryPoint: HookName) {
    sanitizeGate.withLock {
      hooksStorage.withLock { hooksByName in
        hooksByName[entryPoint] = []
      }
    }
  }

  public static func removeAllHooks() {
    sanitizeGate.withLock {
      hooksStorage.set([:])
    }
  }

  public enum RemovedItem: Sendable, Equatable {
    case element(RemovedElement)
    case attribute(RemovedAttribute)
  }

  public struct RemovedElement: Sendable, Equatable {
    public var nodeName: String

    public init(nodeName: String) {
      self.nodeName = nodeName
    }
  }

  public struct RemovedAttribute: Sendable, Equatable {
    public var name: String
    public var fromNodeName: String

    public init(name: String, fromNodeName: String) {
      self.name = name
      self.fromNodeName = fromNodeName
    }
  }

  public struct UseProfiles: Sendable, Equatable {
    public var html: Bool
    public var svg: Bool
    public var svgFilters: Bool
    public var mathML: Bool

    public init(html: Bool = false, svg: Bool = false, svgFilters: Bool = false, mathML: Bool = false) {
      self.html = html
      self.svg = svg
      self.svgFilters = svgFilters
      self.mathML = mathML
    }
  }

  public struct SanitizedFragment: Sendable, Equatable {
    public var html: String
    public var firstChildNodeValue: String?

    public init(html: String, firstChildNodeValue: String?) {
      self.html = html
      self.firstChildNodeValue = firstChildNodeValue
    }
  }

  public struct SanitizedDOM: Sendable, Equatable {
    public var html: String
    public var headHTML: String?
    public var bodyHTML: String?

    public init(html: String, headHTML: String?, bodyHTML: String?) {
      self.html = html
      self.headHTML = headHTML
      self.bodyHTML = bodyHTML
    }
  }

  public enum InPlaceError: Error, Sendable, Equatable {
    case forbiddenRootNode(tagName: String)
  }

  public enum ParserMediaType: String, Sendable {
    case textHTML = "text/html"
    case applicationXHTMLXML = "application/xhtml+xml"
  }

  public static let htmlNamespaceURI = "http://www.w3.org/1999/xhtml"
  public static let svgNamespaceURI = "http://www.w3.org/2000/svg"
  public static let mathMLNamespaceURI = "http://www.w3.org/1998/Math/MathML"

  public struct RegExp: Sendable {
    public var source: String
    public var flags: String

    public init(source: String, flags: String = "") {
      self.source = source
      self.flags = flags
    }
  }

  public struct AllowedURIRegExp: Sendable {
    public var pattern: String
    public var isCaseInsensitive: Bool

    public init(pattern: String, isCaseInsensitive: Bool = true) {
      self.pattern = pattern
      self.isCaseInsensitive = isCaseInsensitive
    }
  }

  public struct CustomElementHandling: Sendable {
    public var tagNameCheck: RegExp?
    public var attributeNameCheck: RegExp?
    public var allowCustomizedBuiltInElements: Bool

    public init(
      tagNameCheck: RegExp? = nil,
      attributeNameCheck: RegExp? = nil,
      allowCustomizedBuiltInElements: Bool = false
    ) {
      self.tagNameCheck = tagNameCheck
      self.attributeNameCheck = attributeNameCheck
      self.allowCustomizedBuiltInElements = allowCustomizedBuiltInElements
    }
  }

  public struct Configuration: Sendable {
    public var allowedTags: Set<String>
    public var allowedAttributes: Set<String>
    public var forbidTags: Set<String>
    public var forbidAttributes: Set<String>
    public var useProfiles: UseProfiles?
    public var addTags: Set<String>
    public var addAttributes: Set<String>

    public var allowDataAttributes: Bool
    public var allowAriaAttributes: Bool
    public var allowUnknownProtocols: Bool
    public var allowSelfCloseInAttributes: Bool

    public var safeForXML: Bool
    public var safeForTemplates: Bool
    public var wholeDocument: Bool
    public var forceBody: Bool
    public var keepContent: Bool
    public var sanitizeDOM: Bool
    public var sanitizeNamedProps: Bool

    public var dataURITags: Set<String>
    public var uriSafeAttributes: Set<String>
    public var forbidContents: Set<String>
    public var allowedURIRegExp: AllowedURIRegExp?
    public var customElementHandling: CustomElementHandling
    public var parserMediaType: ParserMediaType
    public var namespaceURI: String
    public var allowedNamespaceURIs: Set<String>

    public init(
      allowedTags: Set<String>? = nil,
      allowedAttributes: Set<String>? = nil,
      forbidTags: Set<String> = [],
      forbidAttributes: Set<String> = [],
      useProfiles: UseProfiles? = nil,
      addTags: Set<String> = [],
      addAttributes: Set<String> = [],
      allowDataAttributes: Bool = true,
      allowAriaAttributes: Bool = true,
      allowUnknownProtocols: Bool = false,
      allowSelfCloseInAttributes: Bool = true,
      safeForXML: Bool = true,
      safeForTemplates: Bool = false,
      wholeDocument: Bool = false,
      forceBody: Bool = false,
      keepContent: Bool = true,
      sanitizeDOM: Bool = true,
      sanitizeNamedProps: Bool = false,
      dataURITags: Set<String>? = nil,
      uriSafeAttributes: Set<String>? = nil,
      forbidContents: Set<String>? = nil,
      allowedURIRegExp: AllowedURIRegExp? = nil,
      customElementHandling: CustomElementHandling = CustomElementHandling(),
      parserMediaType: ParserMediaType = .textHTML,
      namespaceURI: String = DOMPurify.htmlNamespaceURI,
      allowedNamespaceURIs: Set<String>? = nil
    ) {
      self.allowedTags = allowedTags ?? DOMPurifyDefaults.allowedTags
      self.allowedAttributes = allowedAttributes ?? DOMPurifyDefaults.allowedAttributes
      self.forbidTags = forbidTags
      self.forbidAttributes = forbidAttributes
      self.useProfiles = useProfiles
      self.addTags = addTags
      self.addAttributes = addAttributes
      self.allowDataAttributes = allowDataAttributes
      self.allowAriaAttributes = allowAriaAttributes
      self.allowUnknownProtocols = allowUnknownProtocols
      self.allowSelfCloseInAttributes = allowSelfCloseInAttributes
      self.safeForXML = safeForXML
      self.safeForTemplates = safeForTemplates
      self.wholeDocument = wholeDocument
      self.forceBody = forceBody
      self.keepContent = keepContent
      self.sanitizeDOM = sanitizeDOM
      self.sanitizeNamedProps = sanitizeNamedProps
      self.dataURITags = dataURITags ?? DOMPurifyDefaults.dataURITags
      self.uriSafeAttributes = uriSafeAttributes ?? DOMPurifyDefaults.uriSafeAttributes
      self.forbidContents = forbidContents ?? DOMPurifyDefaults.forbidContents
      self.allowedURIRegExp = allowedURIRegExp
      self.customElementHandling = customElementHandling
      self.parserMediaType = parserMediaType
      self.namespaceURI = namespaceURI
      self.allowedNamespaceURIs = allowedNamespaceURIs
        ?? Set([DOMPurify.htmlNamespaceURI, DOMPurify.svgNamespaceURI, DOMPurify.mathMLNamespaceURI])
    }

    public static let `default` = Configuration()
  }

  public static var removed: [RemovedItem] {
    removedStorage.get()
  }

  public static func sanitizeAndGetRemoved(
    _ dirty: String,
    config: Configuration = .default
  ) -> (sanitized: String, removed: [RemovedItem]) {
    sanitizeGate.withLock {
      removedStorage.set([])
      let effectiveConfig = persistentConfigStorage.get() ?? config
      let sanitizer = DOMPurifySanitizer(config: effectiveConfig, hooks: Hooks.snapshot())
      do {
        let output = try sanitizer.sanitize(dirty)
        removedStorage.set(sanitizer.removedItems)
        return (output, sanitizer.removedItems)
      } catch {
        removedStorage.set(sanitizer.removedItems)
        return ("", sanitizer.removedItems)
      }
    }
  }

  public static func sanitizeAndGetRemoved(
    _ dirty: Element,
    config: Configuration = .default
  ) -> (sanitized: String, removed: [RemovedItem]) {
    sanitizeGate.withLock {
      removedStorage.set([])
      let effectiveConfig = persistentConfigStorage.get() ?? config
      let sanitizer = DOMPurifySanitizer(config: effectiveConfig, hooks: Hooks.snapshot())
      do {
        let output = try sanitizer.sanitizeElementToString(dirty)
        removedStorage.set(sanitizer.removedItems)
        return (output, sanitizer.removedItems)
      } catch {
        removedStorage.set(sanitizer.removedItems)
        return ("", sanitizer.removedItems)
      }
    }
  }

  public static func sanitizeAndGetRemoved(
    _ dirty: Node,
    config: Configuration = .default
  ) -> (sanitized: String, removed: [RemovedItem]) {
    sanitizeGate.withLock {
      removedStorage.set([])
      let effectiveConfig = persistentConfigStorage.get() ?? config
      let sanitizer = DOMPurifySanitizer(config: effectiveConfig, hooks: Hooks.snapshot())
      do {
        let output = try sanitizer.sanitizeNodeToString(dirty)
        removedStorage.set(sanitizer.removedItems)
        return (output, sanitizer.removedItems)
      } catch {
        removedStorage.set(sanitizer.removedItems)
        return ("", sanitizer.removedItems)
      }
    }
  }

  public static func sanitize(_ dirty: String, config: Configuration = .default) -> String {
    sanitizeGate.withLock {
      removedStorage.set([])
      let effectiveConfig = persistentConfigStorage.get() ?? config
      let sanitizer = DOMPurifySanitizer(config: effectiveConfig, hooks: Hooks.snapshot())
      do {
        let output = try sanitizer.sanitize(dirty)
        removedStorage.set(sanitizer.removedItems)
        return output
      } catch {
        // DOMPurify is "best effort" and (outside of in-place node sanitization) aims to not throw.
        removedStorage.set(sanitizer.removedItems)
        return ""
      }
    }
  }

  public static func sanitize(_ dirty: [String], config: Configuration = .default) -> String {
    sanitize(dirty.joined(separator: ","), config: config)
  }

  public static func sanitize(_ dirty: Element, config: Configuration = .default) -> String {
    sanitizeGate.withLock {
      removedStorage.set([])
      let effectiveConfig = persistentConfigStorage.get() ?? config
      let sanitizer = DOMPurifySanitizer(config: effectiveConfig, hooks: Hooks.snapshot())
      do {
        let output = try sanitizer.sanitizeElementToString(dirty)
        removedStorage.set(sanitizer.removedItems)
        return output
      } catch {
        removedStorage.set(sanitizer.removedItems)
        return ""
      }
    }
  }

  public static func sanitize(_ dirty: Node, config: Configuration = .default) -> String {
    sanitizeGate.withLock {
      removedStorage.set([])
      let effectiveConfig = persistentConfigStorage.get() ?? config
      let sanitizer = DOMPurifySanitizer(config: effectiveConfig, hooks: Hooks.snapshot())
      do {
        let output = try sanitizer.sanitizeNodeToString(dirty)
        removedStorage.set(sanitizer.removedItems)
        return output
      } catch {
        removedStorage.set(sanitizer.removedItems)
        return ""
      }
    }
  }

  public static func sanitizeToDOM(_ dirty: String, config: Configuration = .default) -> String {
    sanitizeGate.withLock {
      removedStorage.set([])
      let effectiveConfig = persistentConfigStorage.get() ?? config
      let sanitizer = DOMPurifySanitizer(config: effectiveConfig, hooks: Hooks.snapshot())
      do {
        let output = try sanitizer.sanitizeDOMOuterHTML(dirty)
        removedStorage.set(sanitizer.removedItems)
        return output
      } catch {
        removedStorage.set(sanitizer.removedItems)
        return ""
      }
    }
  }

  public static func sanitizeToDOM(_ dirty: Element, config: Configuration = .default) -> String {
    sanitizeGate.withLock {
      removedStorage.set([])
      let effectiveConfig = persistentConfigStorage.get() ?? config
      let sanitizer = DOMPurifySanitizer(config: effectiveConfig, hooks: Hooks.snapshot())
      do {
        let output = try sanitizer.sanitizeElementToDOMOuterHTML(dirty)
        removedStorage.set(sanitizer.removedItems)
        return output
      } catch {
        removedStorage.set(sanitizer.removedItems)
        return ""
      }
    }
  }

  public static func sanitizeToDOM(_ dirty: Node, config: Configuration = .default) -> String {
    sanitizeGate.withLock {
      removedStorage.set([])
      let effectiveConfig = persistentConfigStorage.get() ?? config
      let sanitizer = DOMPurifySanitizer(config: effectiveConfig, hooks: Hooks.snapshot())
      do {
        let output = try sanitizer.sanitizeNodeToDOMOuterHTML(dirty)
        removedStorage.set(sanitizer.removedItems)
        return output
      } catch {
        removedStorage.set(sanitizer.removedItems)
        return ""
      }
    }
  }

  public static func sanitizeToDocument(_ dirty: String, config: Configuration = .default) -> SanitizedDOM {
    sanitizeGate.withLock {
      removedStorage.set([])
      let effectiveConfig = persistentConfigStorage.get() ?? config
      let sanitizer = DOMPurifySanitizer(config: effectiveConfig, hooks: Hooks.snapshot())
      do {
        let doc = try sanitizer.sanitizeToDocument(dirty)
        let html = try doc.outerHtml()
        let head = try? doc.head()?.outerHtml()
        let body = try? doc.body()?.outerHtml()
        removedStorage.set(sanitizer.removedItems)
        return SanitizedDOM(html: html, headHTML: head, bodyHTML: body)
      } catch {
        removedStorage.set(sanitizer.removedItems)
        return SanitizedDOM(html: "", headHTML: nil, bodyHTML: nil)
      }
    }
  }

  public static func sanitizeToDocument(_ dirty: Element, config: Configuration = .default) -> SanitizedDOM {
    sanitizeGate.withLock {
      removedStorage.set([])
      let effectiveConfig = persistentConfigStorage.get() ?? config
      let sanitizer = DOMPurifySanitizer(config: effectiveConfig, hooks: Hooks.snapshot())
      do {
        let doc = try sanitizer.sanitizeElementToDocument(dirty)
        let html = try doc.outerHtml()
        let head = try? doc.head()?.outerHtml()
        let body = try? doc.body()?.outerHtml()
        removedStorage.set(sanitizer.removedItems)
        return SanitizedDOM(html: html, headHTML: head, bodyHTML: body)
      } catch {
        removedStorage.set(sanitizer.removedItems)
        return SanitizedDOM(html: "", headHTML: nil, bodyHTML: nil)
      }
    }
  }

  public static func sanitizeToDocument(_ dirty: Node, config: Configuration = .default) -> SanitizedDOM {
    sanitizeGate.withLock {
      removedStorage.set([])
      let effectiveConfig = persistentConfigStorage.get() ?? config
      let sanitizer = DOMPurifySanitizer(config: effectiveConfig, hooks: Hooks.snapshot())
      do {
        let doc = try sanitizer.sanitizeNodeToDocument(dirty)
        let html = try doc.outerHtml()
        let head = try? doc.head()?.outerHtml()
        let body = try? doc.body()?.outerHtml()
        removedStorage.set(sanitizer.removedItems)
        return SanitizedDOM(html: html, headHTML: head, bodyHTML: body)
      } catch {
        removedStorage.set(sanitizer.removedItems)
        return SanitizedDOM(html: "", headHTML: nil, bodyHTML: nil)
      }
    }
  }

  public static func sanitizeToDocumentTree(_ dirty: String, config: Configuration = .default) -> Document {
    sanitizeGate.withLock {
      removedStorage.set([])
      let effectiveConfig = persistentConfigStorage.get() ?? config
      let sanitizer = DOMPurifySanitizer(config: effectiveConfig, hooks: Hooks.snapshot())
      do {
        let doc = try sanitizer.sanitizeToDocument(dirty)
        removedStorage.set(sanitizer.removedItems)
        return doc
      } catch {
        removedStorage.set(sanitizer.removedItems)
        return Document.createShell("")
      }
    }
  }

  public static func sanitizeToDocumentTree(_ dirty: Element, config: Configuration = .default) -> Document {
    sanitizeGate.withLock {
      removedStorage.set([])
      let effectiveConfig = persistentConfigStorage.get() ?? config
      let sanitizer = DOMPurifySanitizer(config: effectiveConfig, hooks: Hooks.snapshot())
      do {
        let doc = try sanitizer.sanitizeElementToDocument(dirty)
        removedStorage.set(sanitizer.removedItems)
        return doc
      } catch {
        removedStorage.set(sanitizer.removedItems)
        return Document.createShell("")
      }
    }
  }

  public static func sanitizeToDocumentTree(_ dirty: Node, config: Configuration = .default) -> Document {
    sanitizeGate.withLock {
      removedStorage.set([])
      let effectiveConfig = persistentConfigStorage.get() ?? config
      let sanitizer = DOMPurifySanitizer(config: effectiveConfig, hooks: Hooks.snapshot())
      do {
        let doc = try sanitizer.sanitizeNodeToDocument(dirty)
        removedStorage.set(sanitizer.removedItems)
        return doc
      } catch {
        removedStorage.set(sanitizer.removedItems)
        return Document.createShell("")
      }
    }
  }

  public static func sanitizeToFragment(_ dirty: String, config: Configuration = .default) -> SanitizedFragment {
    sanitizeGate.withLock {
      removedStorage.set([])
      let effectiveConfig = persistentConfigStorage.get() ?? config
      let sanitizer = DOMPurifySanitizer(config: effectiveConfig, hooks: Hooks.snapshot())
      do {
        let output = try sanitizer.sanitizeFragment(dirty)
        removedStorage.set(sanitizer.removedItems)
        return output
      } catch {
        removedStorage.set(sanitizer.removedItems)
        return SanitizedFragment(html: "", firstChildNodeValue: nil)
      }
    }
  }

  public static func sanitizeToFragment(_ dirty: Element, config: Configuration = .default) -> SanitizedFragment {
    sanitizeGate.withLock {
      removedStorage.set([])
      let effectiveConfig = persistentConfigStorage.get() ?? config
      let sanitizer = DOMPurifySanitizer(config: effectiveConfig, hooks: Hooks.snapshot())
      do {
        let output = try sanitizer.sanitizeElementToFragment(dirty)
        removedStorage.set(sanitizer.removedItems)
        return output
      } catch {
        removedStorage.set(sanitizer.removedItems)
        return SanitizedFragment(html: "", firstChildNodeValue: nil)
      }
    }
  }

  public static func sanitizeToFragment(_ dirty: Node, config: Configuration = .default) -> SanitizedFragment {
    sanitizeGate.withLock {
      removedStorage.set([])
      let effectiveConfig = persistentConfigStorage.get() ?? config
      let sanitizer = DOMPurifySanitizer(config: effectiveConfig, hooks: Hooks.snapshot())
      do {
        let output = try sanitizer.sanitizeNodeToFragment(dirty)
        removedStorage.set(sanitizer.removedItems)
        return output
      } catch {
        removedStorage.set(sanitizer.removedItems)
        return SanitizedFragment(html: "", firstChildNodeValue: nil)
      }
    }
  }

  @discardableResult
  public static func sanitizeInPlace(_ element: Element, config: Configuration = .default) throws -> Element {
    try sanitizeGate.withLock {
      removedStorage.set([])
      let effectiveConfig = persistentConfigStorage.get() ?? config
      let sanitizer = DOMPurifySanitizer(config: effectiveConfig, hooks: Hooks.snapshot())
      do {
        let output = try sanitizer.sanitizeInPlace(element)
        removedStorage.set(sanitizer.removedItems)
        return output
      } catch {
        removedStorage.set(sanitizer.removedItems)
        throw error
      }
    }
  }

  public static func setConfig(_ config: Configuration) {
    sanitizeGate.withLock {
      persistentConfigStorage.set(config)
    }
  }

  public static func clearConfig() {
    sanitizeGate.withLock {
      persistentConfigStorage.set(nil)
    }
  }
}
