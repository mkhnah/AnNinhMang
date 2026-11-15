// Run in a fresh child process per fixture. Actual PDF.js + native canvas; not a browser RSS claim.
const fs = require('node:fs');
const { webcrypto } = require('node:crypto');
const canvas = require('../frontend/node_modules/@napi-rs/canvas');
const { build } = require('../frontend/node_modules/esbuild');
(async()=>{
  const built=await build({entryPoints:['frontend/src/components/PDFViewer/pdfBudget.ts'],bundle:true,write:false,platform:'node',format:'cjs'});
  const mod={exports:{}};new Function('module','exports',built.outputFiles[0].text)(mod,mod.exports);
  const {MAX_PDF_BYTES,boundedScale}=mod.exports;
  Object.assign(globalThis,{DOMMatrix:canvas.DOMMatrix,ImageData:canvas.ImageData,Path2D:canvas.Path2D});
  const pdfjs=await import('../frontend/node_modules/pdfjs-dist/legacy/build/pdf.mjs');
  const rssBefore=process.memoryUsage().rss;const started=performance.now();
  let bytes=new Uint8Array(fs.readFileSync(process.argv[2]));const size=bytes.byteLength;
  if(size>MAX_PDF_BYTES)throw new Error('Fixture too large');
  await webcrypto.subtle.digest('SHA-256',bytes);
  const task=pdfjs.getDocument({data:bytes,isEvalSupported:false,maxImageSize:16_000_000,canvasMaxAreaInBytes:16_000_000});
  bytes=null;
  const doc=await task.promise;const page=await doc.getPage(1);
  const natural=page.getViewport({scale:2});const viewport=page.getViewport({scale:boundedScale(natural.width,natural.height,2)});
  const target=canvas.createCanvas(Math.max(1,Math.floor(viewport.width)),Math.max(1,Math.floor(viewport.height)));
  await page.render({canvasContext:target.getContext('2d'),viewport}).promise;
  const pixels=target.width*target.height;
  page.cleanup();await task.destroy();target.width=1;target.height=1;
  if(global.gc)global.gc();
  console.log(JSON.stringify({pdfjs:pdfjs.version,node:process.version,fixture_bytes:size,canvas_pixels:pixels,elapsed_ms:Math.round(performance.now()-started),rss_before_mb:rssBefore/1048576,rss_after_cleanup_mb:process.memoryUsage().rss/1048576,process_peak_rss_mb:process.resourceUsage().maxRSS/1024,scope:'Node legacy PDF.js + native canvas; one synthetic blank page, not browser heap/worker/GPU memory'}));
})().catch(error=>{console.error(error);process.exitCode=1;});
