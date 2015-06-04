"use strict";

/**
 * Module dependencies.
 */

var he = require("he");
var gumbo = require("gumbo-parser");

/**
 * Copy properties from sources to target.
 *
 * @param {Object} target The target object.
 * @param {...Object} sources The source object.
 * @return {Object} The target object.
 * @private
 */

function extend (target /* ...sources */) {
  var source, key, i = 1;
  while (source = arguments[i++]) {
    for (key in source) target[key] = source[key];
  }
  return target;
};

/**
 * Helper functions
 */

function toHash (xs) {
  return xs ? xs.reduce(function (memo, it) {
    return memo[it] = true, memo;
  }, {}) : {};
}

function toHash2 (that) {
  var result = {}, key;
  for (key in that) result[key] = toHash(that[key]);
  return result;
}

function toHash3 (that) {
  var result = {}, key;
  for (key in that) result[key] = toHash2(that[key]);
  return result;
}

/**
 * Sanitize cleans input HTML using the given options.
 *
 * @param {String} [html] The HTML string to sanitize.
 * @param {Object} [options] The sanitize configuration to use.
 * @return {String} When called as a function, returns the sanitized HTML.
 */

var Sanitize = module.exports = function Sanitize (html, options) {
  if (typeof html == "object") options = html, html = null;

  // sanitize(html, options)
  if (!(this instanceof Sanitize)) return Sanitize.sanitize(html, options);

  // new Sanitize(options)
  this.setOptions(options);

  if (html) this.parse(html);
};

/**
 * Sanitize the input HTML using the given options.
 *
 * @param {String} html The HTML string to sanitize.
 * @param {Object} [options] The sanitize configuration to use.
 * @return {String} When called as a function, returns the sanitized HTML.
 */

Sanitize.sanitize = function (html, options) {
  return new Sanitize(options).sanitize(html);
}

/**
 * Matches an attribute value that could be treated by a browser as a URL
 * with a protocol prefix, such as "http:" or "javascript:". Any string of
 * zero or more characters followed by a colon is considered a match, even
 * if the colon is encoded as an entity and even if it's an incomplete
 * entity (which IE6 and Opera will still parse).
 */

Sanitize.REGEX_PROTOCOL = /^\s*([^\/#]*?)(?:\:|&#0*58|&#x0*3a)/i;

/**
 * Matches Unicode characters that should be stripped from HTML before to
 * passing it the parser.
 *
 * @see http://www.w3.org/TR/unicode-xml/#Charlist
 */

Sanitize.REGEX_UNSUITABLE_CHARS = /([\u0340\u0341\u17a3\u17d3\u2028\u2029\u202a-\u202e\u206a-\u206f\ufff9-\ufffb\ufeff\ufffc]|\ud834[\udd73-\udd7a]|\udb40[\udc00-\udc7f])/g;

/**
 * Matches a content-type value of "text/html; charset=utf-8".
 */

Sanitize.META_CONTENT_TYPE_REGEX =
  /^\s*text\/html\s*(;\s*charset\s*=\s*utf-8\s*)?$/i;

/**
 * Relative URL sentinel.
 */

Sanitize.RELATIVE = ":relative";

/**
 * Default sanitize configuration.
 */

Sanitize.DEFAULT = {
  selfClosing: [
    "area", "base", "br", "col", "command", "embed", "hr", "img", "input",
    "keygen", "link", "meta", "param", "source", "track", "wbr"
  ],
  whitespace: {
    address:    {before: " ", after: " "},
    article:    {before: " ", after: " "},
    aside:      {before: " ", after: " "},
    blockquote: {before: " ", after: " "},
    br:         {before: " ", after: " "},
    dd:         {before: " ", after: " "},
    div:        {before: " ", after: " "},
    dl:         {before: " ", after: " "},
    dt:         {before: " ", after: " "},
    footer:     {before: " ", after: " "},
    h1:         {before: " ", after: " "},
    h2:         {before: " ", after: " "},
    h3:         {before: " ", after: " "},
    h4:         {before: " ", after: " "},
    h5:         {before: " ", after: " "},
    h6:         {before: " ", after: " "},
    header:     {before: " ", after: " "},
    hgroup:     {before: " ", after: " "},
    hr:         {before: " ", after: " "},
    li:         {before: " ", after: " "},
    nav:        {before: " ", after: " "},
    ol:         {before: " ", after: " "},
    p:          {before: " ", after: " "},
    pre:        {before: " ", after: " "},
    section:    {before: " ", after: " "},
    ul:         {before: " ", after: " "}
  }
};

/**
 * Restricted sanitize configuration.
 */

Sanitize.RESTRICTED = extend({}, Sanitize.DEFAULT, {
  elements: ["b", "em", "i", "strong", "u"]
});

/**
 * Basic sanitize configuration.
 */

Sanitize.BASIC = extend({}, Sanitize.RESTRICTED, {
  elements: Sanitize.RESTRICTED.elements.concat(
    "a", "abbr", "blockquote", "br", "cite", "code", "dd", "dfn", "dl",
    "dt", "kbd", "li", "mark", "ol", "p", "pre", "q", "s", "samp", "small",
    "strike", "sub", "sup", "time", "ul", "var"
  ),
  attributes: {
    a:          ["href"],
    abbr:       ["title"],
    blockquote: ["cite"],
    dfn:        ["title"],
    q:          ["cite"],
    time:       ["datetime", "pubdate"]
  },
  addAttributes: {
    a: {rel: "nofollow"}
  },
  protocols: {
    a:          {href: ["ftp", "http", "https", "mailto", Sanitize.RELATIVE]},
    blockquote: {cite: ["http", "https", Sanitize.RELATIVE]},
    q:          {cite: ["http", "https", Sanitize.RELATIVE]}
  }
});

/**
 * Relaxed sanitize configuration.
 */

Sanitize.RELAXED = extend({}, Sanitize.BASIC, {
  elements: Sanitize.BASIC.elements.concat(
    "address", "article", "aside", "bdi", "bdo", "body", "caption", "col",
    "colgroup", "data", "del", "div", "figcaption", "figure", "footer",
    "h1", "h2", "h3", "h4", "h5", "h6", "head", "header", "hgroup", "hr",
    "html", "img", "ins", "main", "nav", "rp", "rt", "ruby", "section",
    "span", "style", "summary", "sup", "table", "tbody", "td", "tfoot",
    "th", "thead", "title", "tr", "wbr"
  ),
  attributes: extend({}, Sanitize.BASIC.attributes, {
    _:        ["class", "dir", "hidden", "id", "lang", "style", "tabindex",
               "title", "translate"],
    a:        ["href", "hreflang", "name", "rel"],
    col:      ["span", "width"],
    colgroup: ["span", "width"],
    data:     ["value"],
    del:      ["cite", "datetime"],
    img:      ["align", "alt", "border", "height", "src", "width"],
    ins:      ["cite", "datetime"],
    li:       ["value"],
    ol:       ["reversed", "start", "type"],
    style:    ["media", "scoped", "type"],
    table:    ["align", "bgcolor", "border", "cellpadding", "cellspacing",
               "frame", "rules", "sortable", "summary", "width"],
    td:       ["abbr", "align", "axis", "colspan", "headers", "rowspan",
               "valign", "width"],
    th:       ["abbr", "align", "axis", "colspan", "headers", "rowspan",
               "scope", "sorted", "valign", "width"],
    ul:       ["type"]
  }),
  addAttributes: null,
  protocols: extend({}, Sanitize.BASIC.protocols, {
    del: {cite: ["http", "https", Sanitize.RELATIVE]},
    img: {src:  ["http", "https", Sanitize.RELATIVE]},
    ins: {cite: ["http", "https", Sanitize.RELATIVE]}
  })
});

/**
 * Set options on Sanitize instance.
 */

Sanitize.prototype.setOptions = function (options) {
  if (!options || options === this.options) return;

  // set defaults
  this.options = options = extend({}, Sanitize.DEFAULT, options);

  // for fast lookups
  this.elements = toHash(options.elements)
  this.attributes = toHash2(options.attributes);
  this.addAttributes = options.addAttributes || {};
  this.protocols = toHash3(options.protocols)
  this.selfClosing = toHash(options.selfClosing);
  this.whitespace = options.whitespace || {};
};

/**
 * Default configuration.
 */

Sanitize.prototype.setOptions(Sanitize.DEFAULT);

/**
 * Options for HTML entity encoder.
 */

Sanitize.prototype.heOptions = {strict: true, useNamedReferences: true};

/**
 * Parse the given HTML string.
 *
 * @param {String} html The HTML string.
 * @param {Object} [options] Gumbo parser options.
 */

Sanitize.prototype.parse = function (html, options) {
  html = html.replace(Sanitize.REGEX_UNSUITABLE_CHARS, "");
  this.parseTree = gumbo(html, options);
};

/**
 * Sanitize the given HTML string.
 *
 * @param {String} html The HTML string.
 * @param {Object} [options] Gumbo parser options.
 * @return {String} The sanitized HTML string.
 */

Sanitize.prototype.sanitize = function (html, options) {
  return this.parse(html, options), this.toString();
};

/**
 * Generate clean HTML using the gumbo parse tree.
 */

Sanitize.prototype.toString = function () {
  var root = this.parseTree.document || this.parseTree;
  return this.s = "", this.visit(root), this.s;
};

/**
 * Visit a node.
 *
 * @param {Node} node
 */

Sanitize.prototype.visit = function (node) {
  switch (node.nodeType) {
    case 1: // element
      this.visitElement(node);
      break;

    case 2: // attribute
      this.visitAttribute(node);
      break;

    case 3: // text
      this.visitText(node);
      break;

    case 8: // comment
      this.visitComment(node);
      break;

    case 9: // document
      this.visitDocument(node);
      break;
  }
};

/**
 * Visit an Element node.
 *
 * @param {Element} node
 */

Sanitize.prototype.visitElement = function (node) {
  var virtual = !node.originalTag;
  var tag = node.tagName;
  var ws = this.whitespace[tag];
  var attrs, name, value;

  // opening tag
  if (virtual) {
    // no-op
  } else if (this.elements[tag]) {
    this.s += "<" + tag;
    if (node.attributes) {
      if (tag == "meta") this.visitMeta(node);
      node.attributes.forEach(function (it) {
        this.visitAttribute(it, tag);
      }, this);
    }
    if (attrs = this.addAttributes[tag]) {
      for (name in attrs) {
        value = he.encode(attrs[name], this.heOptions)
        this.s += " " + name + "=" + JSON.stringify(value);
      }
    }
    this.s += ">";
  } else if (ws && ws.before) {
    this.s += ws.before;
  }

  // closing tag
  if (!this.selfClosing[tag]) {
    if (node.childNodes) node.childNodes.forEach(this.visit, this);
    if (virtual) { /* no-op */ }
    else if (this.elements[tag]) this.s += "</" + tag + ">";
    else if (ws && ws.after) this.s += ws.after;
  }
};

/**
 * Visit an Attribute node.
 *
 * @param {Attribute} attr
 */

Sanitize.prototype.visitAttribute = function (attr, tag) {
  var name = attr.name, value = attr.value, match;
  var attrs = this.attributes[tag];
  var dattrs = this.attributes._;
  var protos;

  // filter attributes
  if (!(attrs && attrs[name] || dattrs && dattrs[name])) return;

  // filter alues
  if (!value) {
    // no-op
  } else if ((protos = this.protocols[tag]) && (protos = protos[name])) {
    if (match = Sanitize.REGEX_PROTOCOL.exec(value)) {
      if (!protos[match[1].toLowerCase()]) return;
    } else if (!protos[Sanitize.RELATIVE]) {
      return;
    }
    value = value.trim();
  }

  // encode value
  value = value ? he.encode(value, this.heOptions) : "";

  // output attribute
  this.s += " " + name + "=" + JSON.stringify(value);
};

/**
 * Visit a Text node.
 *
 * @param {TextNode} node
 */

Sanitize.prototype.visitText = function (node) {
  if (node.nodeName == "#text") {
    this.s += he.encode(node.textContent, this.heOptions);
  }
};

/**
 * Visit a Comment node.
 *
 * @param {CommentNode} node
 */

Sanitize.prototype.visitComment = function (node) {
  // ignore
};

/**
 * Visit a Document.
 *
 * @param {Document} node
 */

Sanitize.prototype.visitDocument = function (node) {
  node.childNodes.forEach(this.visit, this);
};

/**
 * Visit a meta node.
 *
 * @param {Element} node
 */

Sanitize.prototype.visitMeta = function (node) {
  if (!node.attributes) return;

  var attrs = node.attributes.reduce(function (attrs, it) {
    return attrs[it.name.toLowerCase()] = it.value, attrs;
  }, {});

  var httpEquiv = attrs["http-equiv"];
  if (!httpEquiv || httpEquiv.trim().toLowerCase() != "content-type") return;

  // we only output text/html; charset=utf-8
  if (Sanitize.META_CONTENT_TYPE_REGEX.test(attrs.content)) return;

  // set content-type
  node.attributes.some(function (it) {
    if (it.name == "content") {
      return it.value = "text/html; charset=utf-8";
    }
  });
};
