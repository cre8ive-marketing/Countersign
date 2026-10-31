import { useEffect, useRef, useState } from 'react';

// Renders every page of a PDF at the container's width; children get each page's size for overlays.
// shortcut: pages with a /Rotate flag render rotated but field stamping assumes unrotated pages; normalize rotation on upload if this shows up.
export default function PdfPages({ url, renderOverlay, onLoad, gap = 24 }) {
  const wrap = useRef(null);
  const [pages, setPages] = useState(null); // [{ width, height }] in PDF points
  const [width, setWidth] = useState(0);
  const [error, setError] = useState(null);
  const pdfRef = useRef(null);

  useEffect(() => {
    let cancelled = false;
    (async () => {
      try {
        const pdfjs = await import('pdfjs-dist');
        pdfjs.GlobalWorkerOptions.workerSrc = '/pdf.worker.min.mjs';
        const pdf = await pdfjs.getDocument({ url, withCredentials: true }).promise;
        if (cancelled) return;
        pdfRef.current = pdf;
        const sizes = [];
        for (let i = 1; i <= pdf.numPages; i++) {
          const vp = (await pdf.getPage(i)).getViewport({ scale: 1 });
          sizes.push({ width: vp.width, height: vp.height });
        }
        if (cancelled) return;
        setPages(sizes);
        onLoad?.(sizes);
      } catch (e) {
        if (!cancelled) setError('This document could not be displayed.');
      }
    })();
    return () => { cancelled = true; };
  }, [url]); // eslint-disable-line react-hooks/exhaustive-deps

  useEffect(() => {
    const el = wrap.current;
    if (!el) return;
    const ro = new ResizeObserver(([entry]) => setWidth(Math.floor(entry.contentRect.width)));
    ro.observe(el);
    return () => ro.disconnect();
  }, []);

  if (error) return <div className="pdf-error" role="alert">{error}</div>;

  return (
    <div ref={wrap} className="pdf-pages" style={{ gap }}>
      {!pages || !width
        ? <div className="pdf-skeleton" aria-label="Loading document" />
        : pages.map((p, i) => {
            const cssW = width;
            const cssH = (p.height / p.width) * width;
            return (
              <div key={i} className="pdf-page" style={{ width: cssW, height: cssH }} data-page={i}>
                <PageCanvas pdf={pdfRef.current} index={i} cssW={cssW} cssH={cssH} />
                {renderOverlay?.(i, { width: cssW, height: cssH, ptWidth: p.width, ptHeight: p.height })}
              </div>
            );
          })}
    </div>
  );
}

function PageCanvas({ pdf, index, cssW, cssH }) {
  const ref = useRef(null);
  useEffect(() => {
    let task;
    let cancelled = false;
    (async () => {
      const page = await pdf.getPage(index + 1);
      if (cancelled) return;
      const base = page.getViewport({ scale: 1 });
      const dpr = Math.min(window.devicePixelRatio || 1, 2);
      const viewport = page.getViewport({ scale: (cssW / base.width) * dpr });
      const canvas = ref.current;
      canvas.width = Math.floor(viewport.width);
      canvas.height = Math.floor(viewport.height);
      task = page.render({ canvas, viewport });
      await task.promise.catch(() => {});
    })();
    return () => { cancelled = true; task?.cancel(); };
  }, [pdf, index, cssW]);
  return <canvas ref={ref} style={{ width: cssW, height: cssH }} aria-label={`Page ${index + 1}`} role="img" />;
}
