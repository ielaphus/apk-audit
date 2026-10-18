// apk-scan.js - static APK inspection with no dependencies.
// usage: node apk-scan.js <file.apk>
// prints: entries, permissions, package ids, tracker/ads/Play markers, URL hosts, signing.
// part of https://github.com/ielaphus/apk-audit
// apk-scan.js - static check of an APK without external tools:
//   node apk-scan.js <file.apk>
// prints: entry summary, package ids, permissions, tracker/ad/Play markers, URL hosts, signature.
const fs = require('fs');
const zlib = require('zlib');

const path = process.argv[2];
if (!path) { console.log('usage: node apk-scan.js <file.apk>'); process.exit(2); }
const buf = fs.readFileSync(path);

function eocd(b) { for (let i = b.length - 22; i >= Math.max(0, b.length - 66000); i--) if (b.readUInt32LE(i) === 0x06054b50) return i; return -1; }
const e = eocd(buf);
if (e < 0) { console.log('NOT A ZIP/APK: ' + path); process.exit(3); }
const total = buf.readUInt16LE(e + 10), cdOff = buf.readUInt32LE(e + 16);
const entries = [];
let p = cdOff;
for (let i = 0; i < total; i++) {
  if (buf.readUInt32LE(p) !== 0x02014b50) break;
  const ent = {
    method: buf.readUInt16LE(p + 10), csize: buf.readUInt32LE(p + 20), usize: buf.readUInt32LE(p + 24),
    nlen: buf.readUInt16LE(p + 28), elen: buf.readUInt16LE(p + 30), clen: buf.readUInt16LE(p + 32),
    lho: buf.readUInt32LE(p + 42)
  };
  ent.name = buf.toString('utf8', p + 46, p + 46 + ent.nlen);
  entries.push(ent);
  p += 46 + ent.nlen + ent.elen + ent.clen;
}
function readEntry(ent) {
  const p2 = ent.lho;
  if (buf.readUInt32LE(p2) !== 0x04034b50) return null;
  const nlen = buf.readUInt16LE(p2 + 26), elen = buf.readUInt16LE(p2 + 28);
  const s = p2 + 30 + nlen + elen;
  const d = buf.slice(s, s + ent.csize);
  if (ent.method === 0) return d;
  if (ent.method === 8) { try { return zlib.inflateRawSync(d); } catch (x) { return null; } }
  return null;
}

console.log('=========================================================');
console.log('APK : ' + path);
console.log('size: ' + (buf.length / 1048576).toFixed(1) + ' MB, entries: ' + total);
const dex = entries.filter(function (x) { return /^classes\d*\.dex$/.test(x.name); });
const so = entries.filter(function (x) { return /^lib\/.*\.so$/.test(x.name); });
console.log('dex: ' + dex.length + ' (' + dex.map(function (x) { return (x.usize / 1048576).toFixed(1); }).join('+') + ' MB)');
console.log('native libs: ' + so.length);
so.forEach(function (x) { console.log('   ' + x.name + '  ' + (x.usize / 1048576).toFixed(1) + ' MB'); });

// --- manifest ---
const man = entries.filter(function (x) { return x.name === 'AndroidManifest.xml'; })[0];
let mdata = man ? readEntry(man) : null;
if (mdata) {
  const u16 = mdata.toString('utf16le'), lat = mdata.toString('latin1');
  const perms = {};
  [u16, lat].forEach(function (src) {
    const re = /android\.permission\.[A-Z_0-9]+/g; let m;
    while ((m = re.exec(src)) !== null) perms[m[0]] = 1;
  });
  console.log('--- permissions (' + Object.keys(perms).length + ') ---');
  console.log('   ' + Object.keys(perms).sort().join('\n   '));

  const pkgs = {};
  [u16, lat].forEach(function (src) {
    const re = /\b(com|org|net|io|ru|de|app)\.[a-z0-9_]+(\.[a-z0-9_]+){1,4}\b/g; let m, n = 0;
    while ((m = re.exec(src)) !== null && n < 4000) { pkgs[m[0]] = (pkgs[m[0]] || 0) + 1; n++; }
  });
  const top = Object.keys(pkgs).sort(function (a, b) { return pkgs[b] - pkgs[a]; }).slice(0, 12);
  console.log('--- package-ish ids (top by frequency) ---');
  top.forEach(function (k) { console.log('   ' + k + ' (' + pkgs[k] + ')'); });

  const play = /com\.android\.vending|play\.google\.com|com\.google\.android\.play|installreferrer/i.test(u16 + lat);
  console.log('playstore_refs: ' + (play ? 'YES' : 'no'));
} else console.log('AndroidManifest.xml: not found');

// --- markers ---
const markers = ['com/google/android/gms', 'com.google.firebase', 'com/google/android/play', 'com.android.vending',
  'play.google.com', 'installreferrer', 'crashlytics', 'app-measurement', 'firebaseinstallations',
  'appsflyer', 'adjust.com', 'appmetrica', 'umeng', 'bugly', 'sentry.io', 'mixpanel', 'amplitude',
  'onesignal', 'admob', 'unityads', 'applovin', 'ironsource', 'vungle', 'chartboost', 'tapjoy',
  'bytedance', 'pangle', 'startapp', 'mopub', 'facebook.ads', 'com.android.billingclient', 'CHECK_LICENSE'];
const hits = {};
markers.forEach(function (k) { hits[k] = 0; });
const urls = {};
function scanText(t) {
  const low = t.toLowerCase();
  markers.forEach(function (m) {
    const mm = m.toLowerCase();
    let i = 0, n = 0;
    while ((i = low.indexOf(mm, i)) >= 0) { n++; i += mm.length; }
    if (n) hits[m] += n;
  });
  const re = /https?:\/\/[A-Za-z0-9._~:\/?#\[\]@!$&'()*+,;=%\-]{4,140}/g; let m;
  while ((m = re.exec(t)) !== null) {
    const h = m[0].replace(/^https?:\/\//, '').split(/[\/?#]/)[0].toLowerCase();
    urls[h] = (urls[h] || 0) + 1;
  }
}
const targets = entries.filter(function (x) {
  return /^(classes\d*\.dex|resources\.arsc)$/.test(x.name) || /^lib\/.*\.so$/.test(x.name) || /^assets\/.*\.(json|js|txt|xml)$/.test(x.name);
});
let scanned = 0;
targets.forEach(function (ent) {
  const d = readEntry(ent);
  if (!d) return;
  scanText(d.toString('latin1'));
  scanText(d.toString('utf16le'));
  scanned++;
});
console.log('scanned files: ' + scanned);

console.log('--- tracker / ad / Play markers ---');
const kk = Object.keys(hits).filter(function (k) { return hits[k] > 0; }).sort(function (a, b) { return hits[b] - hits[a]; });
if (!kk.length) console.log('   (none)');
kk.forEach(function (k) { console.log('   ' + k + ' : ' + hits[k]); });

const docs = /^(www\.)?(w3\.org|unicode\.org|docs\.|developer\.|schemas\.|xml|ns\.|dashif|aomedia|vt100|web\.archive|dartbug|flutter|android\.googlesource|github\.com|xmlpull|default\.url)/;
const hosts = Object.keys(urls).filter(function (h) { return h && !docs.test(h); })
  .sort(function (a, b) { return urls[b] - urls[a]; });
console.log('--- URL hosts, non-doc (top 25) ---');
hosts.slice(0, 25).forEach(function (h) { console.log('   ' + h + ' : ' + urls[h]); });
console.log('   distinct hosts total: ' + Object.keys(urls).length);

console.log('--- signing ---');
const sig = entries.filter(function (x) { return /^META-INF\/.*\.(RSA|DSA|EC|SF)$/i.test(x.name); });
console.log('   ' + (sig.length ? sig.map(function (x) { return x.name; }).join(', ') : 'no v1 files')
  + ' | v2/v3 block: ' + (buf.indexOf(Buffer.from('APK Sig Block 42')) >= 0 ? 'yes' : 'no'));
