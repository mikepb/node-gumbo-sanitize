# gumbo-sanitize

Gumbo Sanitize is a loose port of the [Ruby Sanitize library][sanitize] by Ryan
Grove based on [Google's Gumbo parser][gumbo]. This module differs from
[Sanitize.js][sanitize.js] in that it only supports nodejs and a subset of the
Ruby Sanitize API.

## Install

```sh
npm install --save gumbo-sanitize
```

## Usage

```js
var sanitize = require("gumbo-sanitize");
console.log(sanitize("<img src=javascript:alert('XSS')>", sanitize.RELAXED));
// prints <img>
```

Alternatively, you may also use the `Sanitize` class directly:

```js
var Sanitize = require("gumbo-sanitize");
var s = new Sanitize(Sanitize.RELAXED);
console.log(s.sanitize("<img src=javascript:alert('XSS')>"));
```

## Documentation

For now, please see the source code for documentation. Open to contributions :)

## License

MIT

[gumbo]: https://github.com/google/gumbo-parser
[sanitize]: https://github.com/rgrove/sanitize
[sanitize.js]: https://github.com/gbirke/Sanitize.js
