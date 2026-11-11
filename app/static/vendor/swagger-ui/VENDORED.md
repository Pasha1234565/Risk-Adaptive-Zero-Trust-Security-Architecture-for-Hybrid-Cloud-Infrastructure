# Vendored Swagger UI

These files are an unmodified copy of four files from the npm package
[`swagger-ui-dist`](https://www.npmjs.com/package/swagger-ui-dist), served locally at
`/api/docs` so the application's Content-Security-Policy (`script-src 'self'`) does not need
an external CDN, `'unsafe-inline'` or `'unsafe-eval'`, and the docs work offline.

| Item | Value |
| --- | --- |
| Package | `swagger-ui-dist` |
| Version | `5.34.1` |
| Licence | Apache-2.0 (see `LICENSE` and `NOTICE` in this folder) |
| Source tarball | `https://registry.npmjs.org/swagger-ui-dist/-/swagger-ui-dist-5.34.1.tgz` |
| Tarball integrity (npm `dist.integrity`, verified before extraction) | `sha512-VSr8fXfI93obYaQicLJbLUKGRxDojj/SfRJDDLCioGTUBj4BK/Nj4eE9jCeCAnJxVLi7iS+08PbiZLyrQKBkJQ==` |

| File | Bytes | SHA-256 |
| --- | --- | --- |
| `swagger-ui-bundle.js` | 1,685,697 | `36eeb4d5640b9c036b1d0f854499af1cceebbdb260b790a03a18be5e8488fbf5` |
| `swagger-ui.css` | 187,576 | `c3cfe8248c4b0b89673600fb829924eafbac6de4bc4b2b06f5f5243483074d0a` |
| `LICENSE` | 11,358 | `cfc7749b96f63bd31c3c42b5c471bf756814053e847c10f3eb003417bc523d30` |
| `NOTICE` | 55 | `0d20d1adef18aee3f40dd258172155521ce702ac445cb5f7b7d60ed32dad2fb2` |

The page itself is `app/templates/api_docs.html`; the initialisation script is
`app/static/js/api-docs.js` (no inline script). `swagger-ui.css` ends with a
`sourceMappingURL` comment; the `.map` file is not vendored, so browser developer tools may log a
harmless 404 for it.

## Updating

1. Read the version's `dist.tarball` and `dist.integrity` from
   `https://registry.npmjs.org/swagger-ui-dist/<version>`.
2. Download the tarball and check that its SHA-512 (base64) equals `dist.integrity`.
3. Copy `package/swagger-ui-bundle.js`, `package/swagger-ui.css`, `package/LICENSE` and
   `package/NOTICE` into this folder unchanged, then update the tables above.
4. Run `pytest -q` and open `http://127.0.0.1:8000/api/docs` in a browser; the developer console
   must show no Content-Security-Policy violations.
