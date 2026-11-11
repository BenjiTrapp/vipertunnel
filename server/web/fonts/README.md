These two files are here so the dashboard renders the same on a measurement
host with no internet as it does on a laptop with one, and so the page's
`Content-Security-Policy: default-src 'self'` stays true. Fetching them from
a font CDN at load time would have broken both.

Latin subsets, variable weight axis, taken from Google Fonts.

| File | Family | Licence |
|---|---|---|
| `orbitron-latin.woff2` | Orbitron, by Matt McInerney | SIL Open Font License 1.1 |
| `jetbrains-mono-latin.woff2` | JetBrains Mono, by JetBrains | SIL Open Font License 1.1 |

The OFL permits redistribution, bundling and embedding, including in a
commercial context, as long as the font files keep their own licence. It
does not extend to this repository's own code.

- https://openfontlicense.org/
- https://fonts.google.com/specimen/Orbitron
- https://www.jetbrains.com/lp/mono/
