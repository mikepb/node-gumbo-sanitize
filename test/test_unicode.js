"use strict";

/**
 * Module dependencies.
 */

var Sanitize = require("../index");
var assert = require("assert");

/**
 * Test Sanitize on Unicode characters.
 */

describe("Unicode", function () {

  // http://www.w3.org/TR/unicode-xml/#Charlist
  describe("Unsuitable characters", function () {
    before(function () {
      this.s = new Sanitize(Sanitize.RELAXED);
    });

    it("should strip deprecated grave and acute clones", function () {
      // assert.equal(
      //   this.s.document("a\u0340b\u0341c"),
      //   "<html><head></head><body>abc</body></html>");
      assert.equal(this.s.sanitize("a\u0340b\u0341c"), "abc");
    });

    it("should strip deprecated Khmer characters", function () {
      // assert.equal(
      //   this.s.document("a\u17a3b\u17d3c"),
      //   "<html><head></head><body>abc</body></html>");
      assert.equal(this.s.sanitize("a\u17a3b\u17d3c"), "abc");
    });

    it("should strip line and paragraph separator punctuation", function () {
      // assert.equal(
      //   this.s.document("a\u2028b\u2029c"),
      //   "<html><head></head><body>abc</body></html>");
      assert.equal(this.s.sanitize("a\u2028b\u2029c"), "abc");
    });

    it("should strip bidi embedding control characters", function () {
      // assert.equal(
      //   this.s.document("a\u202ab\u202bc\u202cd\u202de\u202e"),
      //   "<html><head></head><body>abcde</body></html>");
      assert.equal(this.s.sanitize("a\u202ab\u202bc\u202cd\u202de\u202e"), "abcde");
    });

    it("should strip deprecated symmetric swapping characters", function () {
      // assert.equal(
      //   this.s.document("a\u206ab\u206bc"),
      //   "<html><head></head><body>abc</body></html>");
      assert.equal(this.s.sanitize("a\u206ab\u206bc"), "abc");
    });

    it("should strip deprecated Arabic form shaping characters", function () {
      // assert.equal(
      //   this.s.document("a\u206cb\u206dc"),
      //   "<html><head></head><body>abc</body></html>");
      assert.equal(this.s.sanitize("a\u206cb\u206dc"), "abc");
    });

    it("should strip deprecated National digit(shape characters", function () {
      // assert.equal(
      //   this.s.document("a\u206eb\u206fc"),
      //   "<html><head></head><body>abc</body></html>");
      assert.equal(this.s.sanitize("a\u206eb\u206fc"), "abc");
    });

    it("should strip interlinear annotation characters", function () {
      // assert.equal(
      //   this.s.document("a\ufff9b\ufffac\ufffb"),
      //   "<html><head></head><body>abc</body></html>");
      assert.equal(this.s.sanitize("a\ufff9b\ufffac\ufffb"), "abc");
    });

    it("should strip BOM/zero-width non-breaking space characters", function () {
      // assert.equal(
      //   this.s.document("a\ufeffbc"),
      //   "<html><head></head><body>abc</body></html>");
      assert.equal(this.s.sanitize("a\ufeffbc"), "abc");
    });

    it("should strip object replacement characters", function () {
      // assert.equal(
      //   this.s.document("a\ufffcbc"),
      //   "<html><head></head><body>abc</body></html>");
      assert.equal(this.s.sanitize("a\ufffcbc"), "abc");
    });

    it("should strip musical notation scoping characters", function () {
      // assert.equal(
      //   this.s.document("a\ud834\udd73b\ud834\udd74c\ud834\udd75d\ud834\udd76e\ud834\udd77f\ud834\udd78g\ud834\udd79h\ud834\udd7a"),
      //   "<html><head></head><body>abcdefgh</body></html>");
      assert.equal(
        this.s.sanitize("a\ud834\udd73b\ud834\udd74c\ud834\udd75d\ud834\udd76e\ud834\udd77f\ud834\udd78g\ud834\udd79h\ud834\udd7a"),
        "abcdefgh");
    });

    it("should strip language tag code point characters", function () {
      var i, chars = [];
      for (i = 0xE0000; i <= 0xE007F; i++) chars.push(i);
      var str = "a" + String.fromCodePoint.apply(String, chars) + "b";
      // assert.equal(
      //   this.s.document(str),
      //   "<html><head></head><body>ab</body></html>");
      assert.equal(this.s.sanitize(str), "ab");
    });
  });
});
