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

describe("Clean Element", function () {

  var strings = {
    basic: {
      html: '<b>Lo<!-- comment -->rem</b> <a href="pants" title="foo" style="text-decoration: underline;">ipsum</a> <a href="http://foo.com/"><strong>dolor</strong></a> sit<br/>amet <style>.foo { color: #fff; }</style> <script>alert("hello world");</script>',

      default: 'Lorem ipsum dolor sit amet .foo { color: #fff; } alert(&quot;hello world&quot;);',
      restricted: '<b>Lorem</b> ipsum <strong>dolor</strong> sit amet .foo { color: #fff; } alert(&quot;hello world&quot;);',
      basic: '<b>Lorem</b> <a href="pants" rel="nofollow">ipsum</a> <a href="http://foo.com/" rel="nofollow"><strong>dolor</strong></a> sit<br>amet .foo { color: #fff; } alert(&quot;hello world&quot;);',
      relaxed: '<b>Lorem</b> <a href="pants" title="foo" style="text-decoration: underline;">ipsum</a> <a href="http://foo.com/"><strong>dolor</strong></a> sit<br>amet <style>.foo { color: #fff; }</style> alert(&quot;hello world&quot;);'
    },

    malformed: {
      html: 'Lo<!-- comment -->rem</b> <a href=pants title="foo>ipsum <a href="http://foo.com/"><strong>dolor</a></strong> sit<br/>amet <script>alert("hello world");',

      default: 'Lorem dolor sit amet alert(&quot;hello world&quot;);',
      restricted: 'Lorem <strong>dolor</strong> sit amet alert(&quot;hello world&quot;);',
      basic: 'Lorem <a href="pants" rel="nofollow"><strong>dolor</strong></a> sit<br>amet alert(&quot;hello world&quot;);',
      relaxed: 'Lorem <a href="pants" title="foo&gt;ipsum &lt;a href="><strong>dolor</strong></a> sit<br>amet alert(&quot;hello world&quot;);',
    },

    unclosed: {
      html: '<p>a</p><blockquote>b',

      default: ' a  b ',
      restricted: ' a  b ',
      basic: '<p>a</p><blockquote>b</blockquote>',
      relaxed: '<p>a</p><blockquote>b</blockquote>'
    },

    malicious: {
      html: '<b>Lo<!-- comment -->rem</b> <a href="javascript:pants" title="foo">ipsum</a> <a href="http://foo.com/"><strong>dolor</strong></a> sit<br/>amet <<foo>script>alert("hello world");</script>',

      default: 'Lorem ipsum dolor sit amet &lt;script&gt;alert(&quot;hello world&quot;);',
      restricted: '<b>Lorem</b> ipsum <strong>dolor</strong> sit amet &lt;script&gt;alert(&quot;hello world&quot;);',
      basic: '<b>Lorem</b> <a rel="nofollow">ipsum</a> <a href="http://foo.com/" rel="nofollow"><strong>dolor</strong></a> sit<br>amet &lt;script&gt;alert(&quot;hello world&quot;);',
      relaxed: '<b>Lorem</b> <a title="foo">ipsum</a> <a href="http://foo.com/"><strong>dolor</strong></a> sit<br>amet &lt;script&gt;alert(&quot;hello world&quot;);'
    }
  };

  var protocols = {
    'protocol-based JS injection: simple, no spaces':  {
      html: '<a href="javascript:alert(\'XSS\');">foo</a>',
      default: 'foo',
      restricted: 'foo',
      basic: '<a rel="nofollow">foo</a>',
      relaxed: '<a>foo</a>'
    },

    'protocol-based JS injection: simple, spaces before':  {
      html: '<a href="javascript    :alert(\'XSS\');">foo</a>',
      default: 'foo',
      restricted: 'foo',
      basic: '<a rel="nofollow">foo</a>',
      relaxed: '<a>foo</a>'
    },

    'protocol-based JS injection: simple, spaces after':  {
      html: '<a href="javascript:    alert(\'XSS\');">foo</a>',
      default: 'foo',
      restricted: 'foo',
      basic: '<a rel="nofollow">foo</a>',
      relaxed: '<a>foo</a>'
    },

    'protocol-based JS injection: simple, spaces before and after':  {
      html: '<a href="javascript    :   alert(\'XSS\');">foo</a>',
      default: 'foo',
      restricted: 'foo',
      basic: '<a rel="nofollow">foo</a>',
      relaxed: '<a>foo</a>'
    },

    'protocol-based JS injection: preceding colon':  {
      html: '<a href=":javascript:alert(\'XSS\');">foo</a>',
      default: 'foo',
      restricted: 'foo',
      basic: '<a rel="nofollow">foo</a>',
      relaxed: '<a>foo</a>'
    },

    'protocol-based JS injection: UTF-8 encoding':  {
      html: '<a href="javascript&#58;">foo</a>',
      default: 'foo',
      restricted: 'foo',
      basic: '<a rel="nofollow">foo</a>',
      relaxed: '<a>foo</a>'
    },

    'protocol-based JS injection: long UTF-8 encoding':  {
      html: '<a href="javascript&#0058;">foo</a>',
      default: 'foo',
      restricted: 'foo',
      basic: '<a rel="nofollow">foo</a>',
      relaxed: '<a>foo</a>'
    },

    'protocol-based JS injection: long UTF-8 encoding without semicolons':  {
      html: '<a href=&#0000106&#0000097&#0000118&#0000097&#0000115&#0000099&#0000114&#0000105&#0000112&#0000116&#0000058&#0000097&#0000108&#0000101&#0000114&#0000116&#0000040&#0000039&#0000088&#0000083&#0000083&#0000039&#0000041>foo</a>',
      default: 'foo',
      restricted: 'foo',
      basic: '<a rel="nofollow">foo</a>',
      relaxed: '<a>foo</a>'
    },

    'protocol-based JS injection: hex encoding':  {
      html: '<a href="javascript&#x3A;">foo</a>',
      default: 'foo',
      restricted: 'foo',
      basic: '<a rel="nofollow">foo</a>',
      relaxed: '<a>foo</a>'
    },

    'protocol-based JS injection: long hex encoding':  {
      html: '<a href="javascript&#x003A;">foo</a>',
      default: 'foo',
      restricted: 'foo',
      basic: '<a rel="nofollow">foo</a>',
      relaxed: '<a>foo</a>'
    },

    'protocol-based JS injection: hex encoding without semicolons':  {
      html: '<a href=&#x6A&#x61&#x76&#x61&#x73&#x63&#x72&#x69&#x70&#x74&#x3A&#x61&#x6C&#x65&#x72&#x74&#x28&#x27&#x58&#x53&#x53&#x27&#x29>foo</a>',
      default: 'foo',
      restricted: 'foo',
      basic: '<a rel="nofollow">foo</a>',
      relaxed: '<a>foo</a>'
    },

    'protocol-based JS injection: null char':  {
      html: "<img src=java\0script:alert(\"XSS\")>",
      default: '',
      restricted: '',
      basic: '',
      relaxed: '<img>'
    },

    'protocol-based JS injection: invalid URL char':  {
      html: '<img src=java\script:alert("XSS")>',
      default: '',
      restricted: '',
      basic: '',
      relaxed: '<img>'
    },

    'protocol-based JS injection: spaces and entities':  {
      html: '<img src=" &#14;  javascript:alert(\'XSS\');">',
      default: '',
      restricted: '',
      basic: '',
      relaxed: '<img>'
    },

    'protocol whitespace':  {
      html: '<a href=" http://example.com/"></a>',
      default: '',
      restricted: '',
      basic: '<a href="http://example.com/" rel="nofollow"></a>',
      relaxed: '<a href="http://example.com/"></a>'
    }
  };

  describe('Default config', function () {
    it('should remove non-whitelisted elements, leaving safe contents behind', function () {
      assert.equal(
        Sanitize.sanitize('foo <b>bar</b> <strong><a href="#a">baz</a></strong> quux'),
        'foo bar baz quux');

      assert.equal(
        Sanitize.sanitize('<script>alert("<xss>");</script>'),
        'alert(&quot;&lt;xss&gt;&quot;);');

      assert.equal(
        Sanitize.sanitize('<<script>script>alert("<xss>");</<script>>'),
        '&lt;script&gt;alert(&quot;&lt;xss&gt;&quot;);&lt;/&lt;script&gt;&gt;');

      assert.equal(
        Sanitize.sanitize('< script <>> alert("<xss>");</script>'),
        '&lt; script &lt;&gt;&gt; alert(&quot;&quot;);');
    });

    it('should surround the contents of whitespace elements with space characters when removing the element', function () {
      assert.equal(
        Sanitize.sanitize('foo<div>bar</div>baz'),
        'foo bar baz');

      assert.equal(
        Sanitize.sanitize('foo<br>bar<br>baz'),
        'foo bar baz');

      assert.equal(
        Sanitize.sanitize('foo<hr>bar<hr>baz'),
        'foo bar baz');
    });

    it('should not choke on several instances of the same element in a row', function () {
      assert.equal(
        Sanitize.sanitize('<img src="http://www.google.com/intl/en_ALL/images/logo.gif"><img src="http://www.google.com/intl/en_ALL/images/logo.gif"><img src="http://www.google.com/intl/en_ALL/images/logo.gif"><img src="http://www.google.com/intl/en_ALL/images/logo.gif">'),
        '');
    });

    Object.keys(strings).forEach(function (name) {
      var data = strings[name];
      it("should clean " + name + " HTML", function () {
        assert.equal(Sanitize.sanitize(data.html), data.default);
      });
    });

    Object.keys(protocols).forEach(function (name) {
      var data = protocols[name];
      it("should not allow " + name, function () {
        assert.equal(Sanitize.sanitize(data.html), data.default);
      });
    });
  });

  describe('Restricted config', function () {
    before(function () {
      this.s = new Sanitize(Sanitize.RESTRICTED);
    });

    Object.keys(strings).forEach(function (name) {
      var data = strings[name];
      it("should clean " + name + " HTML", function () {
        assert.equal(this.s.sanitize(data.html), data.restricted);
      });
    });

    Object.keys(protocols).forEach(function (name) {
      var data = protocols[name];
      it("should not allow " + name, function () {
        assert.equal(this.s.sanitize(data.html), data.restricted);
      });
    });
  });

  describe('Basic config', function () {
    before(function () {
      this.s = new Sanitize(Sanitize.BASIC)
    });

    it('should not choke on valueless attributes', function () {
      assert.equal(
        this.s.sanitize('foo <a href>foo</a> bar'),
        'foo <a href="" rel="nofollow">foo</a> bar');
    });

    it('should downcase attribute names', function () {
      assert.equal(
        this.s.sanitize('<a HREF="javascript:alert(\'foo\')">bar</a>'),
        '<a rel="nofollow">bar</a>');
    });

    Object.keys(strings).forEach(function (name) {
      var data = strings[name];
      it("should clean " + name + " HTML", function () {
        assert.equal(this.s.sanitize(data.html), data.basic);
      });
    });

    Object.keys(protocols).forEach(function (name) {
      var data = protocols[name];
      it("should not allow " + name, function () {
        assert.equal(this.s.sanitize(data.html), data.basic);
      });
    });
  });

  describe('Relaxed config', function () {
    before(function () {
      this.s = new Sanitize(Sanitize.RELAXED);
    });

    it('should encode special chars in attribute values', function () {
      assert.equal(
        this.s.sanitize('<a href="http://example.com" title="<b>&eacute;xamples</b> & things">foo</a>'),
        '<a href="http://example.com" title="&lt;b&gt;&eacute;xamples&lt;/b&gt; &amp; things">foo</a>');
    });

    Object.keys(strings).forEach(function (name) {
      var data = strings[name];
      it("should clean " + name + " HTML", function () {
        assert.equal(this.s.sanitize(data.html), data.relaxed);
      });
    });

    Object.keys(protocols).forEach(function (name) {
      var data = protocols[name];
      it("should not allow " + name, function () {
        assert.equal(this.s.sanitize(data.html), data.relaxed);
      });
    });
  });

  describe('Custom configs', function () {
    it('should allow attributes on all elements if whitelisted under :all', function () {
      var input = '<p class="foo">bar</p>';

      assert.equal(Sanitize.sanitize(input), ' bar ');

      assert.equal(Sanitize.sanitize(input, {
        elements: ['p'],
        attributes: {_: ['class']}
      }), input);

      assert.equal(Sanitize.sanitize(input, {
        elements: ['p'],
        attributes: {div: ['class']}
      }), '<p>bar</p>');

      assert.equal(Sanitize.sanitize(input, {
        elements: ['p'],
        attributes: {p: ['title'], _: ['class']}
      }), input);
    });

    it('should allow relative URLs containing colons when the colon is not in the first path segment', function () {
      var input = '<a href="/wiki/Special:Random">Random Page</a>';

      assert.equal(Sanitize.sanitize(input, {
        elements: ['a'],
        attributes: {a: ['href']},
        protocols: {a: {href: [Sanitize.RELATIVE]}}
      }), input);
    });

    it('should allow relative URLs containing colons when the colon is part of an anchor', function () {
      var input = '<a href="#fn:1">Footnote 1</a>';

      assert.equal(Sanitize.sanitize(input, {
        elements: ['a'],
        attributes: {a: ['href']},
        protocols: {a: {href: [Sanitize.RELATIVE]}}
      }), input);

      input = '<a href="somepage#fn:1">Footnote 1</a>';

      assert.equal(Sanitize.sanitize(input, {
        elements: ['a'],
        attributes: {a: ['href']},
        protocols: {a: {href: [Sanitize.RELATIVE]}}
      }), input);
    });

    xit('should remove the contents of filtered nodes when :remove_contents is true', function () {
      assert.equal(
        Sanitize.sanitize('foo bar <div>baz<span>quux</span></div>',
        {removeContents: true}
      ), 'foo bar   ');
    });

    xit('should remove the contents of specified nodes when :remove_contents is an Array of element names as strings', function () {
      assert.equal(
        Sanitize.sanitize('foo bar <div>baz<span>quux</span><script>alert("hello!");</script></div>',
          {removeContents: ['script', 'span']}
        ), 'foo bar  baz ');
    });

    xit('should remove the contents of specified nodes when :remove_contents is an Array of element names as symbols', function () {
      assert.equal(
        Sanitize.sanitize('foo bar <div>baz<span>quux</span><script>alert("hello!");</script></div>',
        {removeContents: ["script", "span"]}
      ), 'foo bar  baz ')
    });

    it('should not allow arbitrary HTML5 data attributes by default', function () {
      assert.equal(Sanitize.sanitize('<b data-foo="bar"></b>', {
        elements: ['b']
      }), '<b></b>');

      assert.equal(Sanitize.sanitize('<b class="foo" data-foo="bar"></b>', {
        attributes: {'b':  ['class']},
        elements: ['b']
      }), '<b class="foo"></b>');
    });

    xit('should allow arbitrary HTML5 data attributes when the :attributes config includes :data', function () {
      var s = new Sanitize({
        attributes: {'b':  [":data"]},
        elements: ['b']
      });

      assert.equal(
        s.sanitize('<b data-foo="valid" data-bar="valid"></b>'),
        '<b data-foo="valid" data-bar="valid"></b>');

      assert.equal(
        s.sanitize('<b data-="invalid"></b>'),
        '<b></b>');

      assert.equal(
        s.sanitize('<b data-="invalid"></b>'),
        '<b></b>');

      assert.equal(
        s.sanitize('<b data-xml="invalid"></b>'),
        '<b></b>');

      assert.equal(
        s.sanitize('<b data-xmlfoo="invalid"></b>'),
        '<b></b>');

      assert.equal(
        s.sanitize('<b data-f:oo="valid"></b>'),
        '<b></b>');

      assert.equal(
        s.sanitize('<b data-f/oo="partial"></b>'),
        '<b data-f=""></b>');

      assert.equal(
        s.sanitize('<b data-éfoo="valid"></b>'),
        '<b></b>');
    });

    it('should replace whitespace_elements with configured :before and :after values', function () {
      var s = new Sanitize({
        whitespace: {
          p:   {before: "\n", after: "\n"},
          div: {before: "\n", after: "\n"},
          br:  {before: "\n", after: "\n"},
        }
      });

      assert.equal(s.sanitize('<p>foo</p>'), "\nfoo\n");
      assert.equal(s.sanitize('<p>foo</p><p>bar</p>'), "\nfoo\n\nbar\n");
      assert.equal(s.sanitize('foo<div>bar</div>baz'), "foo\nbar\nbaz");
      assert.equal(s.sanitize('foo<br>bar<br>baz'), "foo\nbar\nbaz");
    });
  });

});
