# Vendored fonts

These woff2 files are self-hosted so BENCchat never fetches fonts from a CDN at
runtime. Vendored subsets per family: `latin` + `latin-ext` for all three,
plus `cyrillic` / `cyrillic-ext` / `vietnamese` where the family ships them
upstream — IBM Plex Mono has all three, VT323 has `vietnamese` only, and Share
Tech Mono is latin-only upstream. Scripts no vendored family covers fall back
via the `--font-*` stacks in `style.css`: CJK (Japanese/Chinese/Korean) routes
to named OS fonts through `--cjk-fallback` (not vendored — CJK fonts are 5–40 MB
and would dwarf the binary), and anything else lands on the system monospace.

All three families are licensed under the **SIL Open Font License, Version 1.1**
(<https://scripts.sil.org/OFL>), which permits bundling and redistribution.

| Family         | Weights | Source                                             |
| -------------- | ------- | -------------------------------------------------- |
| VT323          | 400     | Google Fonts / <https://github.com/phoikoi/VT323>  |
| Share Tech Mono| 400     | Google Fonts / Carrois Apostrophe                  |
| IBM Plex Mono  | 400,500 | Google Fonts / <https://github.com/IBM/plex>       |

The woff2 files were retrieved from Google Fonts' `fonts.gstatic.com` CDN
(the same binaries Google serves) and subset per `unicode-range` in `fonts.css`.
To refresh, re-fetch the css2 API with a modern browser User-Agent and pull the
`latin` / `latin-ext` woff2 URLs.
