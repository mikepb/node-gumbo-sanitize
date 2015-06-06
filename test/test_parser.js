"use strict";

/**
 * Module dependencies.
 */

var Sanitize = require("../index");
var assert = require("assert");

/**
 * Test Parser.
 */

describe('Parser', function () {

  it('should translate valid entities into characters', function () {
    assert.equal(Sanitize.fragment("&apos;&eacute;&amp;"),
      "&apos;&eacute;&amp;");
  });

  it('should translate orphaned ampersands into entities', function () {
    assert.equal(Sanitize.fragment('at&t'), 'at&amp;t')
  });

  it('should not add newlines after tags when serializing a fragment', function () {
    assert.equal(
      Sanitize.fragment("<div>foo\n\n<p>bar</p><div>\nbaz</div></div><div>quux</div>", {elements: ['div', 'p']}),
      "<div>foo\n\n<p>bar</p><div>\nbaz</div></div><div>quux</div>");
  });

  it('should not have the Nokogiri 1.4.2+ unterminated script/style element bug', function () {
    assert.equal(Sanitize.fragment('foo <script>bar'), 'foo bar');
    assert.equal(Sanitize.fragment('foo <style>bar'), 'foo bar');
  });

  it('ambiguous non-tag brackets like "1 > 2 and 2 < 1" should be parsed correctly', function () {
    assert.equal(Sanitize.fragment('1 > 2 and 2 < 1'), '1 &gt; 2 and 2 &lt; 1');
    assert.equal(
      Sanitize.fragment('OMG HAPPY BIRTHDAY! *<:-D'),
      'OMG HAPPY BIRTHDAY! *&lt;:-D');
  });

  // https://github.com/sparklemotion/nokogiri/issues/1008
  it('should work around the libxml2 content-type meta tag bug', function () {
    assert.equal(
      Sanitize.document('<html><head></head><body>Howdy!</body></html>',
      {elements: ["html", "head", "body"]}),
      "<html><head></head><body>Howdy!</body></html>");

    assert.equal(
      Sanitize.document('<html><head></head><body>Howdy!</body></html>',
      {elements: ["html", "head", "meta", "body"]}),
      "<html><head></head><body>Howdy!</body></html>")

    assert.equal(
      Sanitize.document('<html><head><meta charset="utf-8"></head><body>Howdy!</body></html>', {
        elements: ["html", "head", "meta", "body"],
        attributes: {meta: ['charset']}
      }),
      "<html><head><meta charset=\"utf-8\"></head><body>Howdy!</body></html>");

    assert.equal(
      Sanitize.document('<html><head><meta http-equiv="Content-Type" content="text/html;charset=utf-8"></head><body>Howdy!</body></html>', {
        elements: ["html", "head", "meta", "body"],
        attributes: {meta: ["charset", "content", "http-equiv"]}
      }),
      "<html><head><meta http-equiv=\"Content-Type\" content=\"text/html;charset=utf-8\"></head><body>Howdy!</body></html>");

    // Edge case: an existing content-type meta tag with a non-UTF-8 content type
    // will be converted to UTF-8, since that's the only output encoding we
    // support.
    assert.equal(
      Sanitize.document('<html><head><meta http-equiv="content-type" content="text/html;charset=us-ascii"></head><body>Howdy!</body></html>', {
        elements: ["html", "head", "meta", "body"],
        attributes: {meta: ["charset", "content", "http-equiv"]}
      }),
      "<html><head><meta http-equiv=\"content-type\" content=\"text/html; charset=utf-8\"></head><body>Howdy!</body></html>");
  });

  xdescribe('when siblings are added after a node during traversal', function () {
    it('the added siblings should be traversed', function () {
      var html = '\
        <div id="one">\
            <div id="one_one">\
                <div id="one_one_one"></div>\
            </div>\
            <div id="one_two"></div>\
        </div>\
        <div id="two">\
            <div id="two_one"><div id="two_one_one"></div></div>\
            <div id="two_two"></div>\
        </div>\
        <div id="three"></div>\
      ';

      var siblings = [];

      Sanitize.fragment(html, {
        transformers: function (env) {
          var name = env.node.name

          if (name == 'div') {
            env.node.add_next_sibling('<b id="added_' + env.node.id + '">')
          } else if (name == 'b') {
            siblings.push(env.node.id);
          };

          return {node_whitelist: [env.node]};
        }
      });

      // All siblings should be traversed, and in the order added.
      assert.deepEqual(siblings, [
        "added_one_one_one",
        "added_one_one",
        "added_one_two",
        "added_one",
        "added_two_one_one",
        "added_two_one",
        "added_two_two",
        "added_two",
        "added_three"
      ]);
    });
  });
});
