'use strict';

/**
 * demo-server.js
 * Serves demo-site/index.html on localhost:8080
 * Run: node demo-server.js   (in a separate terminal)
 */

const http = require('http');
const fs   = require('fs');
const path = require('path');

const PORT    = 8080;
const SITE_DIR = __dirname;

const MIME = {
  '.html': 'text/html',
  '.css':  'text/css',
  '.js':   'application/javascript',
  '.png':  'image/png',
  '.svg':  'image/svg+xml',
  '.ico':  'image/x-icon',
};

const server = http.createServer((req, res) => {
  let filePath = path.join(SITE_DIR, req.url === '/' ? 'index.html' : req.url);

  // Prevent directory traversal
  if (!filePath.startsWith(SITE_DIR)) {
    res.writeHead(403);
    return res.end('Forbidden');
  }

  fs.readFile(filePath, (err, data) => {
    if (err) {
      // Fall back to index.html for SPA-style routing
      fs.readFile(path.join(SITE_DIR, 'index.html'), (err2, data2) => {
        if (err2) { res.writeHead(404); return res.end('Not found'); }
        res.writeHead(200, { 'Content-Type': 'text/html' });
        res.end(data2);
      });
      return;
    }
    const ext  = path.extname(filePath);
    const mime = MIME[ext] || 'application/octet-stream';
    res.writeHead(200, { 'Content-Type': mime });
    res.end(data);
  });
});

server.listen(PORT, () => {
  console.log(`\n🌐  DemoBank site running on http://localhost:${PORT}`);
  console.log(`   Open this in Chrome with the VaultBase extension installed.\n`);
});
