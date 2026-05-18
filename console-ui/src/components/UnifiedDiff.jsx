import React from 'react';

/**
 * Render a unified diff between `before` and `after` with +/- markers and
 * `contextLines` of unchanged context above and below each change hunk.
 *
 * Props:
 *   before        — original source (string)
 *   after         — patched source (string)
 *   contextLines  — unchanged lines above & below each hunk (default 1)
 *   focusLine     — optional: original line number used to keep gutter aligned
 */
export default function UnifiedDiff({
  before = '',
  after = '',
  contextLines = 1,
  focusLine = null,
}) {
  const rows = computeUnifiedRows(before, after, contextLines);

  if (rows.length === 0) {
    return <pre className="udiff empty">(no changes)</pre>;
  }

  const beforeMax = Math.max(
    ...rows.map(r => (r.beforeNo ?? 0)),
    focusLine || 0,
  );
  const afterMax = Math.max(...rows.map(r => (r.afterNo ?? 0)));
  const beforeWidth = String(beforeMax || 1).length;
  const afterWidth = String(afterMax || 1).length;

  return (
    <pre className="udiff">
      {rows.map((r, i) => {
        if (r.type === 'gap') {
          return (
            <div key={`gap-${i}`} className="udiff-gap">
              <span className="udiff-gutter">…</span>
              <span className="udiff-line">@@ {r.gapSize} unchanged line{r.gapSize !== 1 ? 's' : ''} @@</span>
            </div>
          );
        }
        const cls = r.type === '+' ? 'udiff-add' : r.type === '-' ? 'udiff-del' : 'udiff-ctx';
        return (
          <div key={i} className={`udiff-row ${cls}`}>
            <span className="udiff-gutter" style={{ minWidth: `${beforeWidth + 1}ch` }}>
              {r.beforeNo != null ? String(r.beforeNo).padStart(beforeWidth, ' ') : ' '.repeat(beforeWidth)}
            </span>
            <span className="udiff-gutter" style={{ minWidth: `${afterWidth + 1}ch` }}>
              {r.afterNo != null ? String(r.afterNo).padStart(afterWidth, ' ') : ' '.repeat(afterWidth)}
            </span>
            <span className="udiff-sign">{r.type}</span>
            <span className="udiff-line">{r.line.length === 0 ? ' ' : r.line}</span>
          </div>
        );
      })}
    </pre>
  );
}

function computeUnifiedRows(beforeRaw, afterRaw, ctx) {
  const A = (beforeRaw || '').replace(/\r\n/g, '\n').split('\n');
  const B = (afterRaw || '').replace(/\r\n/g, '\n').split('\n');

  const ops = lcsDiff(A, B);

  // Group ops into hunks separated by long runs of unchanged lines (> 2*ctx)
  const rows = [];
  let pendingEqual = []; // list of { a, b, line }
  let hunkOpen = false;

  const flushTrailingContext = () => {
    if (!hunkOpen) {
      pendingEqual = [];
      return;
    }
    const take = Math.min(ctx, pendingEqual.length);
    for (let i = 0; i < take; i++) {
      const e = pendingEqual[i];
      rows.push({ type: ' ', line: e.line, beforeNo: e.a, afterNo: e.b });
    }
    const remaining = pendingEqual.length - take;
    if (remaining > 0) {
      rows.push({ type: 'gap', gapSize: remaining });
    }
    pendingEqual = [];
    hunkOpen = false;
  };

  for (const op of ops) {
    if (op.type === '=') {
      pendingEqual.push({ a: op.a, b: op.b, line: op.line });
      continue;
    }
    // Change op — emit leading/trailing context from pendingEqual
    if (pendingEqual.length > 0) {
      if (hunkOpen && pendingEqual.length > 2 * ctx) {
        // Run of unchanged lines is too long! Close the previous hunk.
        const take = Math.min(ctx, pendingEqual.length);
        for (let i = 0; i < take; i++) {
          const e = pendingEqual[i];
          rows.push({ type: ' ', line: e.line, beforeNo: e.a, afterNo: e.b });
        }
        const gapSize = pendingEqual.length - 2 * ctx;
        if (gapSize > 0) {
          rows.push({ type: 'gap', gapSize: gapSize });
        }
        // The remaining ctx lines serve as leading context for the next change
        const lead = pendingEqual.slice(-ctx);
        for (const e of lead) {
          rows.push({ type: ' ', line: e.line, beforeNo: e.a, afterNo: e.b });
        }
      } else {
        // Contiguous context
        const lead = hunkOpen ? pendingEqual : pendingEqual.slice(-ctx);
        if (!hunkOpen && pendingEqual.length > ctx && rows.length > 0) {
          rows.push({ type: 'gap', gapSize: pendingEqual.length - ctx });
        }
        for (const e of lead) {
          rows.push({ type: ' ', line: e.line, beforeNo: e.a, afterNo: e.b });
        }
      }
      pendingEqual = [];
    }
    rows.push({
      type: op.type,
      line: op.line,
      beforeNo: op.type === '-' ? op.a : null,
      afterNo: op.type === '+' ? op.b : null,
    });
    hunkOpen = true;
  }

  flushTrailingContext();
  return rows;
}

// Simple LCS-based line diff. Memory O(N*M) — fine for source files under ~2KLoC.
function lcsDiff(A, B) {
  const n = A.length, m = B.length;
  // Build LCS table
  const dp = Array.from({ length: n + 1 }, () => new Uint32Array(m + 1));
  for (let i = n - 1; i >= 0; i--) {
    for (let j = m - 1; j >= 0; j--) {
      dp[i][j] = A[i] === B[j] ? dp[i + 1][j + 1] + 1 : Math.max(dp[i + 1][j], dp[i][j + 1]);
    }
  }
  const ops = [];
  let i = 0, j = 0;
  while (i < n && j < m) {
    if (A[i] === B[j]) {
      ops.push({ type: '=', a: i + 1, b: j + 1, line: A[i] });
      i++; j++;
    } else if (dp[i + 1][j] >= dp[i][j + 1]) {
      ops.push({ type: '-', a: i + 1, line: A[i] });
      i++;
    } else {
      ops.push({ type: '+', b: j + 1, line: B[j] });
      j++;
    }
  }
  while (i < n) { ops.push({ type: '-', a: i + 1, line: A[i] }); i++; }
  while (j < m) { ops.push({ type: '+', b: j + 1, line: B[j] }); j++; }
  return ops;
}
