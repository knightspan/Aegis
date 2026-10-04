# Sanctum Forensics — control surface

React + TypeScript + Vite. Five screens, one design system, no network beyond
the API it is served from.

```
npm install
npm run dev      # 127.0.0.1:5173, proxying the API on 127.0.0.1:8787
npm run build    # tsc -b && vite build -> dist/, served by the API
npm run lint     # oxlint
```

## The design system

`src/tokens.css` holds every value; `src/index.css` builds the primitives out of
them and records why each one is shaped the way it is. Screens use the tokens
directly and hardcode neither a colour nor a pixel size.

The pieces a screen reaches for, all exported from `src/components/widgets.tsx`:

| Piece | What it is for |
|---|---|
| `Verdict` | A judgement the tool has made: the word at `--type-lg`, the thing it was derived from underneath. Capability level, PASS/FAIL, confidence bucket. |
| `Railed` | The instrument table's left-edge state gutter, for panels and lists rather than rows. |
| `Evidence` | Label/value pairs. `stacked` in a side panel or a dialog. |
| `FilePath` | A path in a fixed-width cell: the directory elides, the filename never does. |
| `.itable` | The one table. `.irow` is 52px and two-line, `.irow.is-compact` is 30px, and neither height depends on content. |

The look is neo-brutal in the Sanctum Forensics brand: a black navigation
rail with the logo, ink borders, hard offset shadows, pink `#f65ba2` /
`#f72191` for actions and "where you are", lime `#cdf546` and white on black.
Brick Sans is the display face (titles and figures only: it has capitals and
digits and no punctuation), Croogla 4F is the reading face, and Atkinson
Hyperlegible Mono stays for serials, hashes and paths, because the confirm step
has an operator type a device serial and the two brand faces draw 0/O and 1/l/I
alike. All three are bundled from `src/assets/fonts/`. Light is the default;
dark is one toggle away in the page foot and follows the system when nothing
has been chosen.

A colour never carries meaning on its own. Every state has a word beside it, so
the interface reads in greyscale and survives a projector that has crushed the
reds into the background.

## Design preview

`preview.html` renders the real screens against fixture data at the projector's
1280x720, with the server replaced at the `fetch` and `EventSource` boundary and
the interesting state reached by driving the real controls. It is a dev-only
entry: `vite build` takes `index.html` as its single input, so nothing under
`src/preview/` reaches `dist/`.

```
npm run dev
# then, per screen:
#   http://127.0.0.1:5173/preview.html?screen=home        (also home-case, cases)
#   http://127.0.0.1:5173/preview.html?screen=devices     (add &theme=dark for dark)
#   http://127.0.0.1:5173/preview.html?screen=sanitize
#   http://127.0.0.1:5173/preview.html?screen=files
#   http://127.0.0.1:5173/preview.html?screen=recovery
#   http://127.0.0.1:5173/preview.html?screen=audit
```

The page sets `data-preview-ready` on `<html>` once it has finished driving, so
a screenshot tool can poll for that instead of guessing at a sleep.
