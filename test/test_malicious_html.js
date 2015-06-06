"use strict";

/**
 * Module dependencies.
 */

var Sanitize = require("../index");
var assert = require("assert");

/**
 * Test Sanitize on malicious HTML.
 *
 * @see https://www.owasp.org/index.php/XSS_Filter_Evasion_Cheat_Sheet
 */

describe("Malicious HTML", function () {

  before(function () {
    this.s = new Sanitize(Sanitize.RELAXED);
  });

  describe("comments", function () {
    it("should not allow script injection via conditional comments", function () {
      var subject = this.s.fragment(
        "<!--[if gte IE 4]>\n<script>alert('XSS');</script>\n<![endif]-->");
      assert.equal(subject, "");
    });
  });

  describe("interpolation (ERB, PHP, etc.)", function () {
    it("should escape ERB-style tags", function () {
      assert.equal(
        this.s.fragment("<% naughty_ruby_code %>"),
        "&lt;% naughty_ruby_code %&gt;");
      assert.equal(
        this.s.fragment("<%= naughty_ruby_code %>"),
        '&lt;%= naughty_ruby_code %&gt;');
    });

    it("should remove PHP-style tags", function () {
      assert.equal(this.s.fragment("<? naughtyPHPCode(); ?>"), "");
      assert.equal(this.s.fragment("<?= naughtyPHPCode(); ?>"), "");
    });
  });

  describe("<body>", function () {
    it("should not be possible to inject JS via a malformed event attribute", function () {
      assert.equal(
        this.s.document('<html><head></head><body onload!#$%&()*~+-_.,:;?@[/|\\]^`=alert("XSS")></body></html>'),
        "<html><head></head><body></body></html>");
    });
  });

  describe("<iframe>", function () {
    it("should not be possible to inject an iframe using an improperly closed tag", function () {
      assert.equal(
        this.s.fragment("<iframe src=http://ha.ckers.org/scriptlet.html <"),
        "");
    });
  });

  describe("<img>", function () {
    it("should not be possible to inject JS via an unquoted <img> src attribute", function () {
      assert.equal(
        this.s.fragment("<img src=javascript:alert('XSS')>"), "<img>");
    });

    it("should not be possible to inject JS using grave accents as <img> src delimiters", function () {
      assert.equal(
        this.s.fragment("<img src=`javascript:alert('XSS')`>"), "<img>");
    });

    it("should not be possible to inject <script> via a malformed <img> tag", function () {
      assert.equal(
        this.s.fragment('<img """><script>alert("XSS")</script>">'),
        '<img>alert(&quot;XSS&quot;)&quot;&gt;');
    });

    it("should not be possible to inject protocol-based JS", function () {
      assert.equal(
        this.s.fragment('<img src=&#106;&#97;&#118;&#97;&#115;&#99;&#114;&#105;&#112;&#116;&#58;&#97;&#108;&#101;&#114;&#116;&#40;&#39;&#88;&#83;&#83;&#39;&#41;>'),
        "<img>")

      assert.equal(
        this.s.fragment('<img src=&#0000106&#0000097&#0000118&#0000097&#0000115&#0000099&#0000114&#0000105&#0000112&#0000116&#0000058&#0000097&#0000108&#0000101&#0000114&#0000116&#0000040&#0000039&#0000088&#0000083&#0000083&#0000039&#0000041>'),
        "<img>");

      assert.equal(
        this.s.fragment('<img src=&#x6A&#x61&#x76&#x61&#x73&#x63&#x72&#x69&#x70&#x74&#x3A&#x61&#x6C&#x65&#x72&#x74&#x28&#x27&#x58&#x53&#x53&#x27&#x29>'),
        "<img>");

      // Encoded tab character.
      assert.equal(
        this.s.fragment("<img src=\"jav&#x09;ascript:alert('XSS');\">"),
        "<img>");

      // Encoded newline.
      assert.equal(
        this.s.fragment("<img src=\"jav&#x0A;ascript:alert('XSS');\">"),
        "<img>");

      // Encoded carriage return.
      assert.equal(
        this.s.fragment("<img src=\"jav&#x0D;ascript:alert('XSS');\">"),
        "<img>");

      // Null byte.
      assert.equal(
        this.s.fragment('<img src=java\0script:alert("XSS")>'),
        "<img>");

      // Spaces plus meta char.
      assert.equal(
        this.s.fragment("<img src=\" &#14;  javascript:alert('XSS');\">"),
        "<img>");

      // Mixed spaces and tabs.
      assert.equal(
        this.s.fragment("<img src=\"j\na v\tascript://alert('XSS');\">"),
        "<img>");
    });

    it("should not be possible to inject protocol-based JS via whitespace", function () {
      assert.equal(
        this.s.fragment("<img src=\"jav\tascript:alert('XSS');\">"),
        "<img>");
    });

    it("should not be possible to inject JS using a half-open <img> tag", function () {
      assert.equal(
        this.s.fragment("<img src=\"javascript:alert('XSS')\""),
        "");
    });
  });

  describe('<script>', function () {
    it("should not be possible to inject <script> using a malformed non-alphanumeric tag name", function () {
      assert.equal(
        this.s.fragment("<script/xss src=\"http://ha.ckers.org/xss.js\">alert(1)</script>"),
        "alert(1)");
    });

    it("should not be possible to inject <script> via extraneous open brackets", function () {
      assert.equal(
        this.s.fragment('<<script>alert("XSS");//<</script>'),
        '&lt;alert(&quot;XSS&quot;);//&lt;');
    });
  });
});
