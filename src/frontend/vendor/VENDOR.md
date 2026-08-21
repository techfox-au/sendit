# Vendored third-party libraries

Readable upstream sources only. Production minified copies are produced by
`scripts/build-frontend.py` into `public/vendor/*.min.js` (same pipeline as
first-party JS).

| File | Package | Version | Purpose |
|------|---------|---------|---------|
| nacl-fast.js | tweetnacl | 1.0.3 | X25519 scalar mult / keypair (ECDH) |
| qrcode.js | qrcode-generator | 2.0.4 | TOTP enrollment QR rendering |

Sources:
- https://www.npmjs.com/package/tweetnacl
- https://www.npmjs.com/package/qrcode-generator

`qrcode.js` is the official npm package entry (`dist/qrcode.js` from
qrcode-generator@2.0.4) plus two local patches required for a classic
`<script>` load:

- missing semicolon after `renderTo2dContext` so the minifier does not
  fuse the following `return`
- UMD wrapper assigns `globalThis.qrcode` (upstream only handles AMD /
  CommonJS, so a browser global is otherwise missing)

`nacl-fast.js` is byte-identical to tweetnacl@1.0.3 on npm.

AES-256-GCM and HKDF-SHA-256 use the browser Web Crypto API (no third-party).
