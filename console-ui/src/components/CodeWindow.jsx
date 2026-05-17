import React from 'react';

/**
 * Render a ±context window around `focusLine` with line numbers.
 *
 * Props:
 *   source     — full source text (multi-line string)
 *   focusLine  — 1-based line number to center on. If null, falls back to start.
 *   context    — lines above/below focus (default 2)
 *   variant    — 'bad' (red highlight) | 'good' (green highlight) | 'neutral'
 *   maxLines   — safety cap (default 40). If source < maxLines, show whole thing
 *                ungrouped — small patches benefit from full visibility.
 */
export default function CodeWindow({
  source = '',
  focusLine = null,
  context = 2,
  variant = 'neutral',
  maxLines = 40,
}) {
  if (!source) {
    return <pre className="code-window empty">(no source captured)</pre>;
  }

  const lines = source.replace(/\r\n/g, '\n').split('\n');
  const N = lines.length;
  let start, end, focusIdx;

  if (!focusLine || focusLine < 1) {
    // No focus — show first maxLines
    start = 0;
    end = Math.min(N, maxLines);
    focusIdx = -1;
  } else if (N <= maxLines) {
    // Small file: show whole thing, still highlight focus
    start = 0;
    end = N;
    focusIdx = focusLine - 1;
  } else {
    focusIdx = Math.max(0, Math.min(N - 1, focusLine - 1));
    start = Math.max(0, focusIdx - context);
    end = Math.min(N, focusIdx + context + 1);
  }

  const gutterWidth = String(end).length;
  const visible = lines.slice(start, end);
  const showElide = end < N;
  const showTopElide = start > 0;

  return (
    <pre className={`code-window v-${variant}`}>
      {showTopElide && (
        <div className="cw-elide">
          <span className="cw-gutter">…</span>
          <span className="cw-line">{start} earlier line{start !== 1 ? 's' : ''} hidden</span>
        </div>
      )}
      {visible.map((line, i) => {
        const lineNo = start + i + 1;
        const isFocus = lineNo === focusIdx + 1;
        return (
          <div key={lineNo} className={`cw-row ${isFocus ? `cw-focus cw-focus-${variant}` : ''}`}>
            <span className="cw-gutter" style={{ minWidth: `${gutterWidth + 1}ch` }}>
              {isFocus ? '►' : ' '}{String(lineNo).padStart(gutterWidth, ' ')}
            </span>
            <span className="cw-line">{line.length === 0 ? ' ' : line}</span>
          </div>
        );
      })}
      {showElide && (
        <div className="cw-elide">
          <span className="cw-gutter">…</span>
          <span className="cw-line">{N - end} more line{N - end !== 1 ? 's' : ''} below</span>
        </div>
      )}
    </pre>
  );
}
