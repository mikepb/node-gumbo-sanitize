"use strict";

/**
 * Module dependencies.
 */

var Sanitize = require("../index");
var assert = require("assert");

/**
 * Test Sanitize.
 */

describe("Sanitize", function () {

  describe("instance methods", function () {

    before(function () {
      this.s = new Sanitize();
    });

    describe("#document", function () {
      before(function () {
        this.s = new Sanitize({elements: ["html"]});
      });

      it("should populate configuration", function () {
        assert.deepEqual(this.s.elements, {html: true});
        assert.deepEqual(this.s.attributes, {});
        assert.deepEqual(this.s.addAttributes, {});
        assert.deepEqual(this.s.protocols, {});
      });

      it("should sanitize an HTML document", function () {
        var subject = this.s.sanitize(
          '<!doctype html><html><b>Lo<!-- comment -->rem</b> <a href="pants" title="foo">ipsum</a> <a href="http://foo.com/"><strong>dolor</strong></a> sit<br/>amet <script>alert("hello world");</script></html>');
        assert.equal(subject, '<html>Lorem ipsum dolor sit amet alert(&quot;hello world&quot;);</html>');
      });
    });

    describe("#fragment", function () {
      it("should sanitize an HTML fragment", function () {
        var subject = this.s.sanitize(
          '<b>Lo<!-- comment -->rem</b> <a href="pants" title="foo">ipsum</a> <a href="http://foo.com/"><strong>dolor</strong></a> sit<br/>amet <script>alert("hello world");</script>');
        assert.equal(subject, 'Lorem ipsum dolor sit amet alert(&quot;hello world&quot;);');
      });

      it("should not choke on fragments containing <html> or <body>", function () {
        assert.equal(this.s.sanitize("<html><b>foo</b></html>"), "foo");
        assert.equal(this.s.sanitize("<body><b>foo</b></body>"), "foo");
        assert.equal(this.s.sanitize(
          "<html><body><b>foo</b></body></html>"), "foo");
        assert.equal(this.s.sanitize(
          "<!DOCTYPE html><html><body><b>foo</b></body></html>"), "foo");
      });
    });
  });

});
