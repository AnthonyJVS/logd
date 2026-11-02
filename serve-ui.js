// Serves ui/ with the mock backend for previewing the design in a browser.
const http = require('http'), fs = require('fs'), path = require('path');
const root = path.join(__dirname, 'ui');
const types = { '.html': 'text/html', '.css': 'text/css', '.js': 'text/javascript' };
http.createServer((req, res) => {
  const f = path.join(root, decodeURIComponent(req.url.split('?')[0]) === '/' ? 'index.html' : req.url.split('?')[0]);
  if (!f.startsWith(root) || !fs.existsSync(f)) { res.writeHead(404); return res.end(); }
  res.writeHead(200, { 'content-type': (types[path.extname(f)] || 'text/plain') + '; charset=utf-8', 'cache-control': 'no-store' });
  fs.createReadStream(f).pipe(res);
}).listen(+process.env.PORT || 5173, function () { console.log('ready http://localhost:' + this.address().port); });
