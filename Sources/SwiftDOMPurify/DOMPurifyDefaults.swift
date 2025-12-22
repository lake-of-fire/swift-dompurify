import Foundation
import SwiftSoup

enum DOMPurifyDefaults {
  // Generated from DOMPurify's allow lists:
  // - vendor/DOMPurify/src/tags.ts
  // - vendor/DOMPurify/src/attrs.ts
  static let allowedTags: Set<String> = Set([
      "#text", "a", "abbr", "acronym", "address", "altglyph", "altglyphdef", "altglyphitem",
      "animatecolor", "animatemotion", "animatetransform", "area", "article", "aside", "audio",
      "b", "bdi", "bdo", "big", "blink", "blockquote", "body", "br", "button", "canvas", "caption",
      "center", "circle", "cite", "clippath", "code", "col", "colgroup", "content", "data",
      "datalist", "dd", "decorator", "defs", "del", "desc", "details", "dfn", "dialog", "dir",
      "div", "dl", "dt", "element", "ellipse", "em", "enterkeyhint", "exportparts", "feblend",
      "fecolormatrix", "fecomponenttransfer", "fecomposite", "feconvolvematrix",
      "fediffuselighting", "fedisplacementmap", "fedistantlight", "fedropshadow", "feflood",
      "fefunca", "fefuncb", "fefuncg", "fefuncr", "fegaussianblur", "feimage", "femerge",
      "femergenode", "femorphology", "feoffset", "fepointlight", "fespecularlighting",
      "fespotlight", "fetile", "feturbulence", "fieldset", "figcaption", "figure", "filter",
      "font", "footer", "form", "g", "glyph", "glyphref", "h1", "h2", "h3", "h4", "h5", "h6",
      "head", "header", "hgroup", "hkern", "hr", "html", "i", "image", "img", "input", "inputmode",
      "ins", "kbd", "label", "legend", "li", "line", "lineargradient", "main", "map", "mark",
      "marker", "marquee", "mask", "math", "menclose", "menu", "menuitem", "merror", "metadata",
      "meter", "mfenced", "mfrac", "mglyph", "mi", "mlabeledtr", "mmultiscripts", "mn", "mo",
      "mover", "mpadded", "mpath", "mphantom", "mprescripts", "mroot", "mrow", "ms", "mspace",
      "msqrt", "mstyle", "msub", "msubsup", "msup", "mtable", "mtd", "mtext", "mtr", "munder",
      "munderover", "nav", "nobr", "ol", "optgroup", "option", "output", "p", "part", "path",
      "pattern", "picture", "polygon", "polyline", "pre", "progress", "q", "radialgradient",
      "rect", "rp", "rt", "ruby", "s", "samp", "search", "section", "select", "shadow", "slot",
      "small", "source", "spacer", "span", "stop", "strike", "strong", "style", "sub", "summary",
      "sup", "svg", "switch", "symbol", "table", "tbody", "td", "template", "text", "textarea",
      "textpath", "tfoot", "th", "thead", "time", "title", "tr", "track", "tref", "tspan", "tt",
      "u", "ul", "var", "video", "view", "vkern", "wbr"
  ])
  static let allowedTagsUTF8: Set<[UInt8]> = Set(allowedTags.map { $0.utf8Array })
  static let allowedAttributesUTF8: Set<[UInt8]> = Set(allowedAttributes.map { $0.utf8Array })
  static let forbidTagsUTF8: Set<[UInt8]> = []
  static let forbidAttributesUTF8: Set<[UInt8]> = []

  static let allowedAttributes: Set<String> = Set([
      "accent", "accent-height", "accentunder", "accept", "accumulate", "action", "additive",
      "align", "alignment-baseline", "alt", "amplitude", "ascent", "attributename",
      "attributetype", "autocapitalize", "autocomplete", "autopictureinpicture", "autoplay",
      "azimuth", "background", "basefrequency", "baseline-shift", "begin", "bevelled", "bgcolor",
      "bias", "border", "by", "capture", "cellpadding", "cellspacing", "checked", "cite", "class",
      "clear", "clip", "clip-path", "clip-rule", "clippathunits", "close", "color",
      "color-interpolation", "color-interpolation-filters", "color-profile", "color-rendering",
      "cols", "colspan", "columnlines", "columnsalign", "columnspan", "controls", "controlslist",
      "coords", "crossorigin", "cx", "cy", "d", "datetime", "decoding", "default", "denomalign",
      "depth", "diffuseconstant", "dir", "direction", "disabled", "disablepictureinpicture",
      "disableremoteplayback", "display", "displaystyle", "divisor", "download", "draggable",
      "dur", "dx", "dy", "edgemode", "elevation", "encoding", "enctype", "end", "enterkeyhint",
      "exponent", "exportparts", "face", "fence", "fill", "fill-opacity", "fill-rule", "filter",
      "filterunits", "flood-color", "flood-opacity", "font-family", "font-size",
      "font-size-adjust", "font-stretch", "font-style", "font-variant", "font-weight", "for",
      "frame", "fx", "fy", "g1", "g2", "glyph-name", "glyphref", "gradienttransform",
      "gradientunits", "headers", "height", "hidden", "high", "href", "hreflang", "id",
      "image-rendering", "in", "in2", "inert", "inputmode", "integrity", "intercept", "ismap", "k",
      "k1", "k2", "k3", "k4", "kernelmatrix", "kernelunitlength", "kerning", "keypoints",
      "keysplines", "keytimes", "kind", "label", "lang", "largeop", "length", "lengthadjust",
      "letter-spacing", "lighting-color", "linethickness", "list", "loading", "local", "loop",
      "low", "lquote", "lspace", "marker-end", "marker-mid", "marker-start", "markerheight",
      "markerunits", "markerwidth", "mask", "mask-type", "maskcontentunits", "maskunits",
      "mathbackground", "mathcolor", "mathsize", "mathvariant", "max", "maxlength", "maxsize",
      "media", "method", "min", "minlength", "minsize", "mode", "movablelimits", "multiple",
      "muted", "name", "nonce", "noshade", "notation", "novalidate", "nowrap", "numalign",
      "numoctaves", "offset", "opacity", "open", "operator", "optimum", "order", "orient",
      "orientation", "origin", "overflow", "paint-order", "part", "path", "pathlength", "pattern",
      "patterncontentunits", "patterntransform", "patternunits", "placeholder", "playsinline",
      "points", "popover", "popovertarget", "popovertargetaction", "poster", "preload",
      "preservealpha", "preserveaspectratio", "primitiveunits", "pubdate", "r", "radiogroup",
      "radius", "readonly", "refx", "refy", "rel", "repeatcount", "repeatdur", "required",
      "restart", "result", "rev", "reversed", "role", "rotate", "rowalign", "rowlines", "rows",
      "rowspacing", "rowspan", "rquote", "rspace", "rx", "ry", "scale", "scope", "scriptlevel",
      "scriptminsize", "scriptsizemultiplier", "seed", "selected", "selection", "separator",
      "separators", "shape", "shape-rendering", "size", "sizes", "slope", "slot", "span",
      "specularconstant", "specularexponent", "spellcheck", "spreadmethod", "src", "srclang",
      "srcset", "start", "startoffset", "stddeviation", "step", "stitchtiles", "stop-color",
      "stop-opacity", "stretchy", "stroke", "stroke-dasharray", "stroke-dashoffset",
      "stroke-linecap", "stroke-linejoin", "stroke-miterlimit", "stroke-opacity", "stroke-width",
      "style", "subscriptshift", "summary", "supscriptshift", "surfacescale", "symmetric",
      "systemlanguage", "tabindex", "tablevalues", "targetx", "targety", "text-anchor",
      "text-decoration", "text-rendering", "textlength", "title", "transform", "transform-origin",
      "translate", "type", "u1", "u2", "unicode", "usemap", "valign", "value", "values", "version",
      "vert-adv-y", "vert-origin-x", "vert-origin-y", "viewbox", "visibility", "voffset", "width",
      "word-spacing", "wrap", "writing-mode", "x", "x1", "x2", "xchannelselector", "xlink:href",
      "xlink:title", "xml:id", "xml:space", "xmlns", "xmlns:xlink", "y", "y1", "y2",
      "ychannelselector", "z", "zoomandpan"
  ])

  // Profile allow lists (DOMPurify USE_PROFILES).
  static let profileTextTags: Set<String> = Set([
      "#text",
  ])

  static let profileHTMLTags: Set<String> = Set([
      "a", "abbr", "acronym", "address", "area", "article", "aside", "audio", "b", "bdi", "bdo",
      "big", "blink", "blockquote", "body", "br", "button", "canvas", "caption", "center", "cite",
      "code", "col", "colgroup", "content", "data", "datalist", "dd", "decorator", "del",
      "details", "dfn", "dialog", "dir", "div", "dl", "dt", "element", "em", "fieldset",
      "figcaption", "figure", "font", "footer", "form", "h1", "h2", "h3", "h4", "h5", "h6",
      "head", "header", "hgroup", "hr", "html", "i", "img", "input", "ins", "kbd", "label",
      "legend", "li", "main", "map", "mark", "marquee", "menu", "menuitem", "meter", "nav", "nobr",
      "ol", "optgroup", "option", "output", "p", "picture", "pre", "progress", "q", "rp", "rt",
      "ruby", "s", "samp", "search", "section", "select", "shadow", "slot", "small", "source",
      "spacer", "span", "strike", "strong", "style", "sub", "summary", "sup", "table", "tbody",
      "td", "template", "textarea", "tfoot", "th", "thead", "time", "tr", "track", "tt", "u",
      "ul", "var", "video", "wbr",
  ])

  static let profileSVGTags: Set<String> = Set([
      "svg", "a", "altglyph", "altglyphdef", "altglyphitem", "animatecolor", "animatemotion",
      "animatetransform", "circle", "clippath", "defs", "desc", "ellipse", "enterkeyhint",
      "exportparts", "filter", "font", "g", "glyph", "glyphref", "hkern", "image", "inputmode",
      "line", "lineargradient", "marker", "mask", "metadata", "mpath", "part", "path", "pattern",
      "polygon", "polyline", "radialgradient", "rect", "stop", "style", "switch", "symbol",
      "text", "textpath", "title", "tref", "tspan", "view", "vkern",
  ])

  static let profileSVGFiltersTags: Set<String> = Set([
      "feblend", "fecolormatrix", "fecomponenttransfer", "fecomposite", "feconvolvematrix",
      "fediffuselighting", "fedisplacementmap", "fedistantlight", "fedropshadow", "feflood",
      "fefunca", "fefuncb", "fefuncg", "fefuncr", "fegaussianblur", "feimage", "femerge",
      "femergenode", "femorphology", "feoffset", "fepointlight", "fespecularlighting",
      "fespotlight", "fetile", "feturbulence",
  ])

  static let profileMathMLTags: Set<String> = Set([
      "math", "menclose", "merror", "mfenced", "mfrac", "mglyph", "mi", "mlabeledtr",
      "mmultiscripts", "mn", "mo", "mover", "mpadded", "mphantom", "mroot", "mrow", "ms", "mspace",
      "msqrt", "mstyle", "msub", "msup", "msubsup", "mtable", "mtd", "mtext", "mtr", "munder",
      "munderover", "mprescripts",
  ])

  static let profileHTMLAttributes: Set<String> = Set([
      "accept", "action", "align", "alt", "autocapitalize", "autocomplete", "autopictureinpicture",
      "autoplay", "background", "bgcolor", "border", "capture", "cellpadding", "cellspacing",
      "checked", "cite", "class", "clear", "color", "cols", "colspan", "controls", "controlslist",
      "coords", "crossorigin", "datetime", "decoding", "default", "dir", "disabled",
      "disablepictureinpicture", "disableremoteplayback", "download", "draggable", "enctype",
      "enterkeyhint", "exportparts", "face", "for", "headers", "height", "hidden", "high", "href",
      "hreflang", "id", "inert", "inputmode", "integrity", "ismap", "kind", "label", "lang", "list",
      "loading", "loop", "low", "max", "maxlength", "media", "method", "min", "minlength",
      "multiple", "muted", "name", "nonce", "noshade", "novalidate", "nowrap", "open", "optimum",
      "part", "pattern", "placeholder", "playsinline", "popover", "popovertarget",
      "popovertargetaction", "poster", "preload", "pubdate", "radiogroup", "readonly", "rel",
      "required", "rev", "reversed", "role", "rows", "rowspan", "spellcheck", "scope", "selected",
      "shape", "size", "sizes", "slot", "span", "srclang", "start", "src", "srcset", "step",
      "style", "summary", "tabindex", "title", "translate", "type", "usemap", "valign", "value",
      "width", "wrap", "xmlns",
  ])

  static let profileSVGAttributes: Set<String> = Set([
      "accent-height", "accumulate", "additive", "alignment-baseline", "amplitude", "ascent",
      "attributename", "attributetype", "azimuth", "basefrequency", "baseline-shift", "begin",
      "bias", "by", "class", "clip", "clippathunits", "clip-path", "clip-rule", "color",
      "color-interpolation", "color-interpolation-filters", "color-profile", "color-rendering",
      "cx", "cy", "d", "dx", "dy", "diffuseconstant", "direction", "display", "divisor", "dur",
      "edgemode", "elevation", "end", "exponent", "fill", "fill-opacity", "fill-rule", "filter",
      "filterunits", "flood-color", "flood-opacity", "font-family", "font-size",
      "font-size-adjust", "font-stretch", "font-style", "font-variant", "font-weight", "fx", "fy",
      "g1", "g2", "glyph-name", "glyphref", "gradientunits", "gradienttransform", "height", "href",
      "id", "image-rendering", "in", "in2", "intercept", "k", "k1", "k2", "k3", "k4", "kerning",
      "keypoints", "keysplines", "keytimes", "lang", "lengthadjust", "letter-spacing",
      "kernelmatrix", "kernelunitlength", "lighting-color", "local", "marker-end", "marker-mid",
      "marker-start", "markerheight", "markerunits", "markerwidth", "maskcontentunits",
      "maskunits", "max", "mask", "mask-type", "media", "method", "mode", "min", "name",
      "numoctaves", "offset", "operator", "opacity", "order", "orient", "orientation", "origin",
      "overflow", "paint-order", "path", "pathlength", "patterncontentunits", "patterntransform",
      "patternunits", "points", "preservealpha", "preserveaspectratio", "primitiveunits", "r",
      "rx", "ry", "radius", "refx", "refy", "repeatcount", "repeatdur", "restart", "result",
      "rotate", "scale", "seed", "shape-rendering", "slope", "specularconstant",
      "specularexponent", "spreadmethod", "startoffset", "stddeviation", "stitchtiles",
      "stop-color", "stop-opacity", "stroke-dasharray", "stroke-dashoffset", "stroke-linecap",
      "stroke-linejoin", "stroke-miterlimit", "stroke-opacity", "stroke", "stroke-width", "style",
      "surfacescale", "systemlanguage", "tabindex", "tablevalues", "targetx", "targety",
      "transform", "transform-origin", "text-anchor", "text-decoration", "text-rendering",
      "textlength", "type", "u1", "u2", "unicode", "values", "viewbox", "visibility", "version",
      "vert-adv-y", "vert-origin-x", "vert-origin-y", "width", "word-spacing", "wrap",
      "writing-mode", "xchannelselector", "ychannelselector", "x", "x1", "x2", "xmlns", "y", "y1",
      "y2", "z", "zoomandpan",
  ])

  static let profileMathMLAttributes: Set<String> = Set([
      "accent", "accentunder", "align", "bevelled", "close", "columnsalign", "columnlines",
      "columnspan", "denomalign", "depth", "dir", "display", "displaystyle", "encoding", "fence",
      "frame", "height", "href", "id", "largeop", "length", "linethickness", "lspace", "lquote",
      "mathbackground", "mathcolor", "mathsize", "mathvariant", "maxsize", "minsize",
      "movablelimits", "notation", "numalign", "open", "rowalign", "rowlines", "rowspacing",
      "rowspan", "rspace", "rquote", "scriptlevel", "scriptminsize", "scriptsizemultiplier",
      "selection", "separator", "separators", "stretchy", "subscriptshift", "supscriptshift",
      "symmetric", "voffset", "width", "xmlns", "xlink:href", "xml:id", "xlink:title", "xml:space",
      "xmlns:xlink",
  ])

  static let profileXMLAttributes: Set<String> = Set([
      "xlink:href", "xml:id", "xlink:title", "xml:space", "xmlns:xlink",
  ])

  // DOMPurify's internal sets.
  static let dataURITags: Set<String> = Set(["audio", "video", "img", "source", "image", "track"])
  static let dataURITagsUTF8: Set<[UInt8]> = Set(dataURITags.map { $0.utf8Array })
  static let uriSafeAttributes: Set<String> = Set([
    "alt", "class", "for", "id", "label", "name", "pattern", "placeholder", "role", "summary",
    "title", "value", "style", "xmlns",
  ])
  static let uriSafeAttributesUTF8: Set<[UInt8]> = Set(uriSafeAttributes.map { $0.utf8Array })
  static let forbidContents: Set<String> = Set([
    "annotation-xml", "audio", "colgroup", "desc", "foreignobject", "head", "iframe", "math", "mi",
    "mn", "mo", "ms", "mtext", "noembed", "noframes", "noscript", "plaintext", "script", "style",
    "svg", "template", "thead", "title", "video", "xmp",
  ])
  static let forbidContentsUTF8: Set<[UInt8]> = Set(forbidContents.map { $0.utf8Array })

  // Used for namespace checks.
  static let allSVGTAGs: Set<String> = Set([
      "a", "altglyph", "altglyphdef", "altglyphitem", "animate", "animatecolor", "animatemotion",
      "animatetransform", "circle", "clippath", "color-profile", "cursor", "defs", "desc",
      "discard", "ellipse", "enterkeyhint", "exportparts", "feblend", "fecolormatrix",
      "fecomponenttransfer", "fecomposite", "feconvolvematrix", "fediffuselighting",
      "fedisplacementmap", "fedistantlight", "fedropshadow", "feflood", "fefunca", "fefuncb",
      "fefuncg", "fefuncr", "fegaussianblur", "feimage", "femerge", "femergenode", "femorphology",
      "feoffset", "fepointlight", "fespecularlighting", "fespotlight", "fetile", "feturbulence",
      "filter", "font", "font-face", "font-face-format", "font-face-name", "font-face-src",
      "font-face-uri", "foreignobject", "g", "glyph", "glyphref", "hatch", "hatchpath", "hkern",
      "image", "inputmode", "line", "lineargradient", "marker", "mask", "mesh", "meshgradient",
      "meshpatch", "meshrow", "metadata", "missing-glyph", "mpath", "part", "path", "pattern",
      "polygon", "polyline", "radialgradient", "rect", "script", "set", "solidcolor", "stop",
      "style", "svg", "switch", "symbol", "text", "textpath", "title", "tref", "tspan", "unknown",
      "use", "view", "vkern"
  ])
  static let allSVGTAGsUTF8: Set<[UInt8]> = Set(allSVGTAGs.map { $0.utf8Array })

  static let allMathMLTags: Set<String> = Set([
      "annotation", "annotation-xml", "maction", "maligngroup", "malignmark", "math", "menclose",
      "merror", "mfenced", "mfrac", "mglyph", "mi", "mlabeledtr", "mlongdiv", "mmultiscripts",
      "mn", "mo", "mover", "mpadded", "mphantom", "mprescripts", "mroot", "mrow", "ms",
      "mscarries", "mscarry", "msgroup", "msline", "mspace", "msqrt", "msrow", "mstack", "mstyle",
      "msub", "msubsup", "msup", "mtable", "mtd", "mtext", "mtr", "munder", "munderover", "none",
      "semantics"
  ])
  static let allMathMLTagsUTF8: Set<[UInt8]> = Set(allMathMLTags.map { $0.utf8Array })

  static let commonSVGAndHTMLElements: Set<String> = Set(["title", "style", "font", "a", "script"])
  static let commonSVGAndHTMLElementsUTF8: Set<[UInt8]> = Set(commonSVGAndHTMLElements.map { $0.utf8Array })
  static let mathMLTextIntegrationPoints: Set<String> = Set(["mi", "mo", "mn", "ms", "mtext"])
  static let htmlIntegrationPoints: Set<String> = Set(["annotation-xml"])
  static let mathMLTextIntegrationPointsUTF8: Set<[UInt8]> = Set(mathMLTextIntegrationPoints.map { $0.utf8Array })
  static let htmlIntegrationPointsUTF8: Set<[UInt8]> = Set(htmlIntegrationPoints.map { $0.utf8Array })

  // Used for SANITIZE_DOM clobbering protection (DOMPurify checks membership against `document` and a `<form>`).
  static let clobberableDocumentAndFormProps: Set<String> = Set([
    "acceptCharset",
    "activeElement",
    "adoptNode",
    "attributes",
    "body",
    "children",
    "cookie",
    "createElement",
    "createNodeIterator",
    "firstElementChild",
    "getElementById",
    "hasChildNodes",
    "implementation",
    "location",
    "namespaceURI",
    "nodeName",
    "textContent",
    "nodeType",
    "parentNode",
    "removeAttributeNode",
    "removeChild",
    "setAttribute",
    "submit",
  ])
}
