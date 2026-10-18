'use strict';

/**
 * VaultBase Dashboard Dev Server
 * Serves dashboard static React SPA on localhost:3000
 */

const http = require('http');
const fs   = require('fs');
const path = require('path');

const PORT = 3000;
const SITE_DIR = __dirname;

const MIME = {
  '.html': 'text/html',
  '.css':  'text/css',
  '.js':   'application/javascript',
  '.jsx':  'application/javascript',
  '.png':  'image/png',
  '.svg':  'image/svg+xml',
  '.ico':  'image/x-icon',
  '.json': 'application/json',
};

const server = http.createServer((req, res) => {
  let reqPath = req.url.split('?')[0];
  let filePath = path.join(SITE_DIR, reqPath === '/' ? 'index.html' : reqPath);

  // Prevent directory traversal
  if (!filePath.startsWith(SITE_DIR)) {
    res.writeHead(403);
    return res.end('Forbidden');
  }

  fs.readFile(filePath, (err, data) => {
    if (err) {
      // Fall back to index.html for SPA-style routing
      fs.readFile(path.join(SITE_DIR, 'index.html'), (err2, data2) => {
        if (err2) {
          res.writeHead(404);
          return res.end('Not found');
        }
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
  console.log(`\n🛡️  VaultBase Security Dashboard running on http://localhost:${PORT}`);
  console.log(`   Connected to VaultBase Auth API on http://localhost:5000\n`);
});

module.exports = server;
