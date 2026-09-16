#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
fw2sbom-service - localhost drag-and-drop web UI for fw2sbom.

Runs a small stdlib-only HTTP server (no pip dependencies, matching
fw2sbom's own "stdlib only" design). Open http://127.0.0.1:8765/ in a
browser, drop a firmware .bin file onto the page, and it is analyzed
in-process via fw2sbom's pipeline. The page shows a summary and offers
the full CycloneDX 1.6 SBOM as a JSON download.

Binds to 127.0.0.1 only - firmware being analyzed may be sensitive, and
this is meant for local, single-user use.
"""

import base64
import time
import threading
import collections
import json
import os
import socket
import re
import sys
import uuid
import io
import webbrowser
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import evidence_report
import fw2sbom as core
import image_input
import spdx_report
import vendor_sbom

HOST = "127.0.0.1"
PORT = int(os.environ.get("FW2SBOM_PORT", "8765"))

# Generated SBOMs kept in memory (id -> {json, xlsx, filenames}) so the browser
# can fetch them for download right after analysis. Cleared on restart.
#
# A deliverable pair for a large image is a few MB, and the browser collects it
# seconds after the upload; without a bound, a service left running all week
# would hold every analysis anyone ever ran. Entries expire by age and the
# oldest are dropped once the store is full.
SBOM_STORE_MAX_ENTRIES = 32
SBOM_STORE_TTL_SECONDS = 3600
_SBOM_STORE = collections.OrderedDict()
_SBOM_STORE_LOCK = threading.Lock()


def _store_put(sbom_id, entry):
    """Insert one result, expiring old entries and capping the total."""
    now = time.time()
    entry["stored_at"] = now
    with _SBOM_STORE_LOCK:
        for old_id in [k for k, v in _SBOM_STORE.items()
                       if now - v["stored_at"] > SBOM_STORE_TTL_SECONDS]:
            del _SBOM_STORE[old_id]
        _SBOM_STORE[sbom_id] = entry
        while len(_SBOM_STORE) > SBOM_STORE_MAX_ENTRIES:
            _SBOM_STORE.popitem(last=False)


def _store_get(sbom_id):
    """One result, or None if it is unknown or has expired."""
    with _SBOM_STORE_LOCK:
        entry = _SBOM_STORE.get(sbom_id)
        if entry is None:
            return None
        if time.time() - entry["stored_at"] > SBOM_STORE_TTL_SECONDS:
            del _SBOM_STORE[sbom_id]
            return None
        return entry


def resource_path(name):
    """Resolve a bundled asset, in a checkout or in the portable package.

    Both keep the assets beside this module; the portable package ships sources
    next to an official interpreter rather than a frozen binary.
    """
    return os.path.join(os.path.dirname(os.path.abspath(__file__)), name)


def _data_uri(filename, mime="image/png"):
    try:
        with open(resource_path(filename), "rb") as f:
            b64 = base64.b64encode(f.read()).decode("ascii")
        return f"data:{mime};base64,{b64}"
    except OSError:
        return ""


LOGO_DATA_URI = _data_uri("onecra_logo.png")
ICON_DATA_URI = _data_uri("onecra_icon.png")

PAGE_TEMPLATE = """<!doctype html>
<html lang="zh-Hant">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>fw2sbom - Firmware SBOM Generator</title>
<link rel="icon" type="image/png" href="__ICON_DATA_URI__">
<style>
  :root {
    color-scheme: light dark;
    --bg: #f5f6f8; --fg: #1b1f24; --heading: #0d1b46; --card: #ffffff; --border: #dfe3ea;
    --accent: #e2105f; --accent-strong: #c00d51; --accent-fg: #ffffff;
    --accent-soft: rgba(226, 16, 95, 0.08); --muted: #667085;
    --high: #0b8f6f; --medium: #b45309; --low: #6b7280; --err: #b91c1c;
    --shadow: 0 1px 2px rgba(13, 27, 70, .04), 0 8px 24px rgba(13, 27, 70, .06);
    --brand-navy: #0d1b46; --brand-pink: #e2105f; --brand-teal: #0b8f89;
  }
  @media (prefers-color-scheme: dark) {
    :root {
      --bg: #0b0d12; --fg: #e7e9ee; --heading: #f2f4f8; --card: #14171f; --border: #262b35;
      --accent: #ff4d8a; --accent-strong: #ff6b9c; --accent-fg: #0b0d12;
      --accent-soft: rgba(255, 77, 138, 0.12); --muted: #9aa1ac;
      --high: #34d399; --medium: #fbbf24; --low: #9aa1ac; --err: #f87171;
      --shadow: 0 1px 2px rgba(0, 0, 0, .3), 0 8px 24px rgba(0, 0, 0, .35);
    }
  }
  * { box-sizing: border-box; }
  body {
    margin: 0; padding: 0 1rem 4rem; background: var(--bg); color: var(--fg);
    font-family: -apple-system, "Segoe UI", Roboto, "Noto Sans TC", sans-serif;
    display: flex; flex-direction: column; align-items: center;
  }
  .topbar {
    width: 100%; height: 4px;
    background: linear-gradient(90deg, var(--brand-navy), var(--brand-pink), var(--brand-teal));
  }
  header { display: flex; flex-direction: column; align-items: center; margin: 2.5rem 0 1.5rem; }
  .brand-logo { height: 40px; width: auto; display: block; }
  .tagline {
    margin: .9rem 0 .3rem; font-size: .8rem; font-weight: 600; letter-spacing: .06em;
    text-transform: uppercase; color: var(--muted);
  }
  .sub { color: var(--muted); font-size: .9rem; margin: 0; text-align: center; max-width: 34rem; }
  .wrap { width: 100%; max-width: 780px; }
  #drop {
    border: 2px dashed var(--border); border-radius: 14px; padding: 3rem 1rem;
    text-align: center; background: var(--card); cursor: pointer; box-shadow: var(--shadow);
    transition: border-color .15s, background .15s, transform .15s;
  }
  #drop:hover { transform: translateY(-1px); }
  #drop.drag { border-color: var(--accent); background: var(--accent-soft); }
  #drop p { margin: .25rem 0; }
  #drop .hint { color: var(--muted); font-size: .85rem; }
  #file-input { display: none; }
  #status { margin-top: 1rem; font-size: .9rem; color: var(--muted); text-align: center; min-height: 1.2em; }
  #status.err { color: var(--err); }
  .card {
    background: var(--card); border: 1px solid var(--border); border-radius: 14px;
    padding: 1.25rem; margin-top: 1.25rem; display: none; box-shadow: var(--shadow);
    opacity: 0; transform: translateY(4px); transition: opacity .2s, transform .2s;
  }
  .card.show { display: block; opacity: 1; transform: translateY(0); }
  .meta { display: flex; flex-wrap: wrap; gap: .5rem 1.5rem; font-size: .85rem; color: var(--muted); margin-bottom: 1rem; }
  .meta b { color: var(--heading); }
  table { width: 100%; border-collapse: collapse; font-size: .9rem; }
  th, td { text-align: left; padding: .5rem .6rem; border-bottom: 1px solid var(--border); }
  th { color: var(--muted); font-weight: 600; font-size: .8rem; text-transform: uppercase; }
  tr:last-child td { border-bottom: none; }
  .lvl { padding: .1rem .5rem; border-radius: 999px; font-size: .75rem; font-weight: 600; }
  .lvl-high { color: var(--high); background: color-mix(in srgb, var(--high) 15%, transparent); }
  .lvl-medium { color: var(--medium); background: color-mix(in srgb, var(--medium) 15%, transparent); }
  .lvl-low { color: var(--low); background: color-mix(in srgb, var(--low) 15%, transparent); }
  .tag {
    padding: .1rem .4rem; border-radius: 999px; font-size: .7rem; font-weight: 600;
    color: var(--brand-teal); background: color-mix(in srgb, var(--brand-teal) 15%, transparent);
  }
  .actions { margin-top: 1rem; display: flex; gap: .75rem; align-items: center; }
  #download {
    background: var(--accent); color: var(--accent-fg); border: none; border-radius: 8px;
    padding: .6rem 1.1rem; font-size: .9rem; font-weight: 600; cursor: pointer; text-decoration: none;
    transition: background .15s;
  }
  #download:hover { background: var(--accent-strong); }
  #download-spdx, #download-evidence {
    display: inline-block; padding: .6rem 1.1rem;
    background: transparent; color: var(--accent); border: 1px solid var(--accent);
    border-radius: 8px; font-weight: 600; text-decoration: none; font-size: .9rem;
  }
  #download-spdx:hover, #download-evidence:hover { background: var(--accent-soft); }
  .actions { flex-wrap: wrap; }
  .empty { color: var(--muted); font-size: .9rem; }
  .notice {
    border: 1px solid color-mix(in srgb, var(--medium) 40%, var(--border));
    background: color-mix(in srgb, var(--medium) 10%, transparent);
    border-radius: 10px; padding: .8rem 1rem; margin-bottom: 1rem; font-size: .85rem;
    display: none;
  }
  .notice.show { display: block; }
  .notice b { color: var(--heading); }
  .notice ul { margin: .5rem 0 0; padding-left: 1.1rem; color: var(--muted); }
  .notice li { margin: .15rem 0; }
  #vendor-zone {
    margin-top: .75rem; border: 1px dashed var(--border); border-radius: 12px;
    padding: .9rem 1rem; background: var(--card); font-size: .85rem;
  }
  #vendor-zone.drag { border-color: var(--accent); background: var(--accent-soft); }
  #vendor-zone .row { display: flex; align-items: baseline; gap: .6rem; flex-wrap: wrap; }
  #vendor-zone b { color: var(--heading); font-size: .85rem; }
  #vendor-zone .why { color: var(--muted); margin: .35rem 0 0; line-height: 1.5; }
  #vendor-pick {
    color: var(--accent); cursor: pointer; text-decoration: underline;
    text-underline-offset: 2px; background: none; border: none; padding: 0;
    font: inherit;
  }
  #vendor-input { display: none; }
  #vendor-list { margin: .5rem 0 0; display: flex; flex-wrap: wrap; gap: .4rem; }
  .chip {
    display: inline-flex; align-items: center; gap: .4rem; padding: .2rem .5rem;
    border-radius: 999px; font-size: .78rem; background: var(--accent-soft);
    color: var(--accent);
  }
  .chip button { background: none; border: none; color: inherit; cursor: pointer; font: inherit; padding: 0; }
  .vendor-doc { border-top: 1px solid var(--border); padding-top: .8rem; margin-top: .8rem; }
  .vendor-doc:first-child { border-top: none; padding-top: 0; margin-top: 0; }
  .vendor-doc h3 { margin: 0 0 .3rem; font-size: .9rem; color: var(--heading); }
  .vendor-doc .counts { color: var(--muted); font-size: .8rem; margin: 0 0 .5rem; }
  .conflict {
    border-left: 3px solid var(--err); padding: .4rem .7rem; margin: .4rem 0;
    background: color-mix(in srgb, var(--err) 8%, transparent); border-radius: 0 6px 6px 0;
  }
  .conflict b { color: var(--heading); }
  .conflict .v { font-family: ui-monospace, "SF Mono", Menlo, Consolas, monospace; }
  .not-observed { color: var(--muted); font-size: .82rem; margin: .4rem 0 0; line-height: 1.6; }
  .disclaimer { margin-top: 1.5rem; font-size: .78rem; color: var(--muted); line-height: 1.5; }
  footer { margin-top: 2rem; font-size: .78rem; color: var(--muted); }
</style>
</head>
<body>
  <div class="topbar"></div>
  <header>
    <img class="brand-logo" src="__LOGO_DATA_URI__" alt="Onecra">
    <p class="tagline">fw2sbom &middot; Firmware SBOM Generator &middot; v__TOOL_VERSION__</p>
    <p class="sub">拖曳 firmware 到下方，產生 evidence-based CycloneDX 1.6 或 SPDX 2.3 SBOM。<br>
      收 raw <code>.bin</code>、<code>.hex</code>、<code>.s19</code>、<code>.uf2</code>、<code>.elf</code>、
      ESP32 映像與整顆 flash dump，以及廠商封包格式（自動去框）</p>
  </header>

  <div class="wrap">
    <div id="drop">
      <p><strong>拖曳 firmware 檔案到這裡</strong></p>
      <p class="hint">任何副檔名皆可（本機分析，檔案不會寫入磁碟、也不會外傳）</p>
      <input type="file" id="file-input" accept="*/*">
    </div>

    <div id="vendor-zone">
      <div class="row">
        <b>廠商 SBOM（選用）</b>
        <button type="button" id="vendor-pick">選擇或拖曳 CycloneDX / SPDX JSON</button>
      </div>
      <p class="why">
        映像加密就讀不到裡面的元件，任何靜態工具都一樣 —— 這時唯一的出路是向供應商
        索取他們自己的 SBOM（CRA 下製造商本來就有權要求）。放進來之後不是把兩份清單
        接起來，而是<strong>逐項比對</strong>：哪些獲映像佐證、哪些版本對不上、哪些
        只有廠商說有。可同時放多份（不同供應商）。
      </p>
      <input type="file" id="vendor-input" accept=".json,application/json" multiple>
      <div id="vendor-list"></div>
    </div>
    <div id="status"></div>

    <div class="card" id="result">
      <div class="meta" id="meta"></div>
      <div class="notice" id="notice"></div>
      <table id="table">
        <thead><tr><th>Component</th><th>Version</th><th>Confidence</th><th>Level</th></tr></thead>
        <tbody id="tbody"></tbody>
      </table>
      <div class="notice" id="vendor-notice"></div>
      <div id="vendor-report"></div>
      <div class="actions">
        <a id="download" href="#">下載 SBOM (CycloneDX JSON)</a>
        <a id="download-spdx" href="#">下載 SBOM (SPDX 2.3 JSON)</a>
        <a id="download-evidence" href="#">下載證據報告 (Excel)</a>
      </div>
    </div>
    <p class="disclaimer">
      這是 <em>binary-derived</em> SBOM：元件與版本判定為啟發式（evidence-based），可能不完整或有誤；
      「沒偵測到」不代表「不存在」。confidence 上限為 0.97。
    </p>
    <footer>Powered by Onecra &middot; fw2sbom</footer>
  </div>

<script>
const drop = document.getElementById('drop');
const input = document.getElementById('file-input');
const status = document.getElementById('status');
const card = document.getElementById('result');
const meta = document.getElementById('meta');
const tbody = document.getElementById('tbody');
const download = document.getElementById('download');
const spdxLink = document.getElementById('download-spdx');
const evidenceLink = document.getElementById('download-evidence');
const vendorZone = document.getElementById('vendor-zone');
const vendorInput = document.getElementById('vendor-input');
const vendorList = document.getElementById('vendor-list');
const vendorReport = document.getElementById('vendor-report');
const vendorNotice = document.getElementById('vendor-notice');

// Vendor documents are held here, not uploaded on their own: they only mean
// something next to an image to compare them against.
let vendorFiles = [];
let lastFirmware = null;

function escapeHtml(text) {
  return String(text == null ? '' : text).replace(/[&<>"']/g, function (ch) {
    return { '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[ch];
  });
}

function renderVendorList() {
  vendorList.innerHTML = '';
  vendorFiles.forEach(function (file, index) {
    const chip = document.createElement('span');
    chip.className = 'chip';
    chip.innerHTML = escapeHtml(file.name) + ' <button type="button" title="移除">&times;</button>';
    chip.querySelector('button').addEventListener('click', function () {
      vendorFiles.splice(index, 1);
      renderVendorList();
      // The comparison is part of the result, so changing the inputs has to
      // change the result rather than leave a stale one on screen.
      if (lastFirmware) { handleFile(lastFirmware); }
    });
    vendorList.appendChild(chip);
  });
}

function addVendorFiles(files) {
  for (const file of files) {
    if (!vendorFiles.some(function (f) { return f.name === file.name && f.size === file.size; })) {
      vendorFiles.push(file);
    }
  }
  renderVendorList();
  if (lastFirmware) { handleFile(lastFirmware); }
}

function setStatus(msg, isErr) {
  status.textContent = msg || '';
  status.className = isErr ? 'err' : '';
}

function levelClass(level) {
  return level === 'high' ? 'lvl-high' : level === 'medium' ? 'lvl-medium' : 'lvl-low';
}

async function handleFile(file) {
  if (!file) return;
  setStatus('分析中: ' + file.name + ' ...');
  card.classList.remove('show');

  lastFirmware = file;
  const fd = new FormData();
  fd.append('file', file, file.name);
  for (const vendorFile of vendorFiles) {
    fd.append('vendor', vendorFile, vendorFile.name);
  }

  let res;
  try {
    res = await fetch('/analyze', { method: 'POST', body: fd });
  } catch (e) {
    setStatus('連線失敗: ' + e, true);
    return;
  }

  let data;
  try {
    data = await res.json();
  } catch (e) {
    setStatus('伺服器回應格式錯誤', true);
    return;
  }

  if (!res.ok) {
    setStatus('錯誤: ' + (data.error || res.status), true);
    return;
  }

  setStatus(data.components.length + ' 個 component 已識別（' + file.name + '）');
  meta.innerHTML =
    '<span><b>檔案大小:</b> ' + data.file_size_bytes + ' bytes</span>' +
    '<span><b>字串數:</b> ' + data.n_strings + '</span>' +
    '<span><b>架構:</b> ' + (data.architecture || '未識別') + '</span>' +
    (data.opacity ? '<span><b>Payload:</b> ' + data.opacity.verdict +
       '（entropy ' + data.opacity.entropy.toFixed(3) + ' bits/byte）</span>' : '') +
    (data.container ? '<span><b>封包容器:</b> ' + data.container.stride + ' bytes/record × ' +
       data.container.records + '，framing ' + data.container.framing_width + 'B + payload ' +
       data.container.payload_width + 'B（已去框，' + data.container.payload_bytes +
       ' bytes）</span>' : '') +
    (data.file_magic ? '<span><b>file(1):</b> ' + data.file_magic + '</span>' : '');

  const notice = document.getElementById('notice');
  notice.classList.remove('show');
  if (data.opacity && data.opacity.opaque) {
    notice.innerHTML =
      '<b>Payload 無法解析（' + data.opacity.verdict + '）</b><br>' +
      '此映像的內容為加密／混淆或未知壓縮格式，任何靜態工具都無法列舉其元件。' +
      'SBOM 僅記錄一個 opaque component，需向供應商索取明文映像或原廠 SBOM 才能補齊。' +
      '<ul>' + data.opacity.reasons.map(function (r) {
        return '<li>' + r + '</li>';
      }).join('') + '</ul>';
    notice.classList.add('show');
  }

  tbody.innerHTML = '';
  if (data.components.length === 0) {
    tbody.innerHTML = '<tr><td colspan="4" class="empty">' +
      (data.opacity && data.opacity.opaque
        ? 'Payload 為 opaque，無可識別元件（SBOM 僅含 metadata + opaque component）'
        : '未識別出任何已知元件（SBOM 僅含 metadata）') + '</td></tr>';
  } else {
    for (const c of data.components) {
      const tr = document.createElement('tr');
      // A vendor's assertion and our observation are both components, but they
      // are not the same kind of claim; the table has to keep them apart.
      const tag =
        c.evidence_class === 'embedded-standard-data' ? '標準資料' :
        c.evidence_class === 'vendor-sbom' ? '廠商聲明' :
        c.evidence_class === 'esp-idf-app-descriptor' ? '映像自述' :
        c.evidence_class === 'package-database' ? '套件資料庫' : '';
      tr.innerHTML =
        '<td>' + escapeHtml(c.name) +
          (tag ? ' <span class="tag">' + tag + '</span>' : '') + '</td>' +
        '<td>' + escapeHtml(c.version || '?') + '</td>' +
        '<td>' + (c.confidence === null || c.confidence === undefined
                    ? '<span class="empty">未觀察到</span>'
                    : c.confidence) + '</td>' +
        '<td>' + (c.confidence_level
                    ? '<span class="lvl ' + levelClass(c.confidence_level) + '">' +
                      escapeHtml(c.confidence_level) + '</span>'
                    : '') + '</td>';
      tbody.appendChild(tr);
    }
  }

  renderVendor(data);

  download.href = data.download_url;
  download.download = data.download_filename;
  spdxLink.href = data.spdx_url;
  spdxLink.download = data.spdx_filename;
  evidenceLink.href = data.evidence_url;
  evidenceLink.download = data.evidence_filename;
  card.classList.add('show');
}

function renderVendor(data) {
  vendorNotice.classList.remove('show');
  vendorNotice.innerHTML = '';
  vendorReport.innerHTML = '';

  // A document we could not read must never look like a document that agreed
  // with us: "0 conflicts" and "we never opened it" are opposite findings.
  if (data.vendor_errors && data.vendor_errors.length) {
    vendorNotice.innerHTML = '<b>有廠商 SBOM 讀不到，未列入比對</b><ul>' +
      data.vendor_errors.map(function (e) {
        return '<li>' + escapeHtml(e) + '</li>';
      }).join('') + '</ul>';
    vendorNotice.classList.add('show');
  }

  if (!data.vendor || !data.vendor.length) { return; }

  vendorReport.innerHTML = data.vendor.map(function (doc) {
    const conflicts = doc.conflicts.map(function (c) {
      return '<div class="conflict"><b>' + escapeHtml(c.name) + '</b>：廠商聲明 ' +
        '<span class="v">' + escapeHtml(c.vendor_version) + '</span>，映像裡是 ' +
        '<span class="v">' + escapeHtml(c.our_version) + '</span></div>';
    }).join('');
    const notObserved = doc.not_observed.length
      ? '<p class="not-observed"><b>廠商聲明但映像中未觀察到（' +
        doc.not_observed.length + '）：</b>' +
        doc.not_observed.map(function (c) {
          return escapeHtml(c.name) + (c.version ? ' ' + escapeHtml(c.version) : '');
        }).join('、') +
        '<br>這不代表它們不存在 —— 讀不到與不存在是兩件事，兩者都已寫進 SBOM。</p>'
      : '';
    return '<div class="vendor-doc">' +
      '<h3>' + escapeHtml(doc.file) +
        ' <span class="tag">' + escapeHtml(doc.format) + '</span></h3>' +
      '<p class="counts">聲明 ' + doc.declared + ' 項 · 獲映像佐證 ' + doc.corroborated +
        ' · 版本衝突 ' + doc.conflicts.length +
        ' · 未觀察到 ' + doc.not_observed.length +
        (doc.subject ? ' · 對象 ' + escapeHtml(doc.subject) : '') + '</p>' +
      conflicts + notObserved +
      '</div>';
  }).join('');
}

document.getElementById('vendor-pick').addEventListener('click', () => vendorInput.click());
vendorInput.addEventListener('change', (e) => addVendorFiles(e.target.files));

['dragenter', 'dragover'].forEach(evt =>
  vendorZone.addEventListener(evt, (e) => {
    e.preventDefault(); e.stopPropagation(); vendorZone.classList.add('drag');
  }));
['dragleave', 'drop'].forEach(evt =>
  vendorZone.addEventListener(evt, (e) => {
    e.preventDefault(); e.stopPropagation(); vendorZone.classList.remove('drag');
  }));
vendorZone.addEventListener('drop', (e) => {
  if (e.dataTransfer.files && e.dataTransfer.files.length) {
    addVendorFiles(e.dataTransfer.files);
  }
});

drop.addEventListener('click', () => input.click());
input.addEventListener('change', (e) => handleFile(e.target.files[0]));

['dragenter', 'dragover'].forEach(evt =>
  drop.addEventListener(evt, (e) => { e.preventDefault(); drop.classList.add('drag'); }));
['dragleave', 'drop'].forEach(evt =>
  drop.addEventListener(evt, (e) => { e.preventDefault(); drop.classList.remove('drag'); }));
drop.addEventListener('drop', (e) => {
  const f = e.dataTransfer.files && e.dataTransfer.files[0];
  handleFile(f);
});
</script>
</body>
</html>
"""

PAGE = (PAGE_TEMPLATE
        .replace("__LOGO_DATA_URI__", LOGO_DATA_URI)
        .replace("__ICON_DATA_URI__", ICON_DATA_URI)
        .replace("__TOOL_VERSION__", core.TOOL_VERSION))


def parse_multipart(body, boundary):
    """Minimal multipart/form-data parser (stdlib only, no cgi module).

    Returns {field_name: [value, ...]} - a list because a field can legitimately
    repeat: a customer may hold SBOMs from several suppliers for one product,
    and dropping them one at a time would compare each against nothing. Text
    fields give str values, file fields (filename, bytes) tuples.
    """
    delimiter = b"--" + boundary
    fields = {}
    for raw in body.split(delimiter):
        if raw in (b"", b"--", b"--\r\n", b"\r\n"):
            continue
        if not raw.startswith(b"\r\n"):
            continue
        raw = raw[2:]
        sep = raw.find(b"\r\n\r\n")
        if sep == -1:
            continue
        header_blob = raw[:sep].decode("utf-8", errors="replace")
        content = raw[sep + 4:]
        if content.endswith(b"\r\n"):
            content = content[:-2]

        m = re.search(r'Content-Disposition:\s*form-data;\s*(.*)', header_blob, re.IGNORECASE)
        if not m:
            continue
        params = {}
        for kv in m.group(1).split(";"):
            kv = kv.strip()
            if "=" in kv:
                k, v = kv.split("=", 1)
                params[k.strip()] = v.strip().strip('"')
        name = params.get("name")
        if not name:
            continue
        if "filename" in params:
            fields.setdefault(name, []).append((params["filename"], content))
        else:
            fields.setdefault(name, []).append(
                content.decode("utf-8", errors="replace"))
    return fields


def summarise(bom):
    """The component list the browser shows, read out of the document itself.

    It used to be assembled separately, from the signature hits, the embedded
    standards and the package database - which meant every later source of
    components (a vendor SBOM, an os-release file, an Espressif app descriptor)
    was silently missing from the screen while being present in the download.
    The list a customer reads first must not be shorter than the document they
    hand to an auditor, and the only way to guarantee that is to derive one
    from the other.

    The one deliberate difference: a document also records the regions we could
    not read, as components carrying `fw2sbom:opaque`. Those belong in an SBOM -
    "we could not enumerate this" is a finding - but listing them on screen
    beside the things we did identify would read as if we had identified them.
    """
    rows = []
    for component in bom.get("components", []):
        properties = {p["name"]: p["value"]
                      for p in component.get("properties", [])}
        if properties.get("fw2sbom:opaque") == "true":
            continue
        confidence = properties.get("fw2sbom:confidence")
        rows.append({
            "name": component["name"],
            "version": component.get("version"),
            "confidence": float(confidence) if confidence else None,
            "confidence_level": properties.get("fw2sbom:confidence_level"),
            "evidence_class": properties.get("fw2sbom:evidence_class",
                                             "signature"),
        })
    return rows


def read_vendor_sboms(uploads):
    """Parse uploaded vendor SBOMs. Returns (documents, errors).

    An unreadable vendor file must not cost the customer the firmware analysis
    they actually came for: it is reported beside the result, not raised. What
    it must never do is pass silently, because "no conflicts found" and "we
    could not read your supplier's document" look identical on screen.
    """
    documents, errors = [], []
    for name, blob in uploads or []:
        try:
            documents.append(vendor_sbom.loads(blob, name or "vendor SBOM"))
        except vendor_sbom.VendorSBOMError as e:
            errors.append(str(e))
    return documents, errors


def vendor_findings(report):
    """Flatten the reconciliation for the browser.

    Conflicts come first in every list this produces. A vendor declaring a
    different version from the one compiled into the image is the most useful
    thing the comparison can say, and burying it under a count of agreements
    would waste it.
    """
    findings = []
    for entry in report:
        identity = entry["document"]
        findings.append({
            "file": identity["file"],
            "format": identity["format"],
            "subject": identity["subject"],
            "declared": len(entry["components"]),
            "corroborated": len(entry["agreements"]),
            "conflicts": [{
                "name": c["vendor"]["name"],
                "vendor_version": c["vendor_version"],
                "our_version": c["our_version"],
            } for c in entry["conflicts"]],
            "not_observed": [{
                "name": c["name"], "version": c.get("version"),
            } for c in entry["vendor_only"]],
        })
    return findings


def analyze_bytes(filename, data, vendor_uploads=None):
    """Run the fw2sbom pipeline in-process on in-memory bytes."""
    delivered = data
    try:
        source = image_input.detect_and_load(data)
    except image_input.InputFormatError as e:
        raise ValueError(f"cannot read this file: {e}")
    data = source["data"]

    container = core.detect_packet_container(data)
    payload = core.deframe(data, container) if container else data
    arm_info = core.analyze_architecture(payload)
    opacity = core.analyze_opacity(payload, arm_info["label"])
    standards = core.detect_embedded_standards(payload)
    segments, rootfs, _warnings = core.analyze_segments(
        payload, 6, False, arm_info["label"])
    strings = [pair for segment in segments
               for pair in segment.get("strings", [])]
    hits = core.merge_segment_hits(segments)
    packages = core.packages_to_components(rootfs)
    opacity = core.summarise_opacity(segments, opacity)
    opacity = core.reconcile_opacity(opacity, hits + packages, standards)

    vendor_documents, vendor_errors = read_vendor_sboms(vendor_uploads)
    vendor = core.reconcile_vendor_sboms(
        vendor_documents, hits, standards, packages, False,
        core.espressif_components(segments))

    name = filename or "firmware.bin"
    stem = os.path.splitext(os.path.basename(name))[0]
    bom = core.build_sbom(name, delivered, None, arm_info, hits, 6,
                          len(strings), container=container, opacity=opacity,
                          payload=payload, standards=standards,
                          segments=segments, rootfs=rootfs, packages=packages,
                          vendor=vendor, source=source)

    spdx = spdx_report.build_spdx(bom, name, core.TOOL_NAME, core.TOOL_VERSION)
    sbom_filename = stem + "_SBOM.cdx.json"
    context = core.build_evidence_context(
        os.path.basename(name), data, payload, arm_info, container, opacity,
        hits, standards, sbom_filename)
    evidence = io.BytesIO()
    evidence_report.build_workbook(context, bom).save(evidence)
    summary = summarise(bom)
    return {
        "sbom_json": json.dumps(bom, indent=2),
        "sbom_filename": sbom_filename,
        "spdx_json": json.dumps(spdx, indent=2),
        "spdx_filename": stem + "_SBOM.spdx.json",
        "evidence_xlsx": evidence.getvalue(),
        "evidence_filename": stem + "_Evidence.xlsx",
        "components": summary,
        "n_strings": len(strings),
        "cortex_m": arm_info["looks_like_cortex_m"],
        "architecture": arm_info["label"],
        "file_size_bytes": len(delivered),
        "input_format": source["format"],
        "reassembled": source["converted"],
        "container": container,
        "opacity": opacity,
        "vendor": vendor_findings(vendor),
        "vendor_errors": vendor_errors,
    }


class Handler(BaseHTTPRequestHandler):
    server_version = f"fw2sbom-service/{core.TOOL_VERSION}"
    # http.server defaults to HTTP/1.0, which tears down the TCP connection
    # after every single response. Real browsers (Chrome in particular) keep
    # reusing a pooled keep-alive connection regardless, so a later request
    # sent on that already-closed socket gets reset - this is what breaks
    # SBOM downloads intermittently after the page has made a few earlier
    # requests. HTTP/1.1 lets BaseHTTPRequestHandler negotiate persistent
    # connections correctly using Content-Length, which we always send.
    protocol_version = "HTTP/1.1"

    def do_GET(self):
        self._handle_get(write_body=True)

    def do_HEAD(self):
        self._handle_get(write_body=False)

    def _handle_get(self, write_body):
        if self.path == "/":
            self._send_html(PAGE, write_body=write_body)
        elif self.path.startswith("/download/"):
            self._send_attachment(self.path[len("/download/"):], "json",
                                  "application/json", write_body)
        elif self.path.startswith("/spdx/"):
            self._send_attachment(self.path[len("/spdx/"):], "spdx",
                                  "application/json", write_body)
        elif self.path.startswith("/evidence/"):
            self._send_attachment(
                self.path[len("/evidence/"):], "xlsx",
                "application/vnd.openxmlformats-officedocument."
                "spreadsheetml.sheet", write_body)
        else:
            self.send_error(404, "not found")

    def _send_attachment(self, sbom_id, key, content_type, write_body):
        entry = _store_get(sbom_id)
        if not entry or key not in entry:
            self.send_error(404, "unknown or expired SBOM id")
            return
        body = entry[key]
        if isinstance(body, str):
            body = body.encode("utf-8")
        self.send_response(200)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Disposition",
                         f'attachment; filename="{entry[key + "_name"]}"')
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        if write_body:
            self.wfile.write(body)

    def do_POST(self):
        if self.path != "/analyze":
            self.send_error(404, "not found")
            return

        ctype = self.headers.get("Content-Type", "")
        if "multipart/form-data" not in ctype or "boundary=" not in ctype:
            self._send_json({"error": "expected multipart/form-data upload"}, 400)
            return
        boundary = ctype.split("boundary=", 1)[1].strip().strip('"').encode()

        try:
            length = int(self.headers.get("Content-Length", 0))
        except ValueError:
            length = 0
        max_upload = core.MAX_FILE_SIZE + (1 * 1024 * 1024)  # headroom for multipart overhead
        if length <= 0 or length > max_upload:
            self._send_json({"error": "missing file or upload too large"}, 400)
            return
        body = self.rfile.read(length)

        try:
            fields = parse_multipart(body, boundary)
        except Exception as e:
            self._send_json({"error": f"malformed upload: {e}"}, 400)
            return

        uploaded = fields.get("file") or []
        if not uploaded or not isinstance(uploaded[0], tuple):
            self._send_json({"error": "no file field in upload"}, 400)
            return
        filename, data = uploaded[0]
        vendor_uploads = [item for item in fields.get("vendor") or []
                          if isinstance(item, tuple)]
        if not data:
            self._send_json({"error": "empty file"}, 400)
            return
        if len(data) > core.MAX_FILE_SIZE:
            self._send_json({"error": "input file too large"}, 400)
            return

        try:
            result = analyze_bytes(filename, data, vendor_uploads)
        except Exception as e:
            self._send_json({"error": f"analysis failed: {e}"}, 500)
            return

        sbom_id = uuid.uuid4().hex
        out_filename = result["sbom_filename"]
        _store_put(sbom_id, {
            "json": result["sbom_json"], "json_name": out_filename,
            "spdx": result["spdx_json"], "spdx_name": result["spdx_filename"],
            "xlsx": result["evidence_xlsx"],
            "xlsx_name": result["evidence_filename"],
        })

        self._send_json({
            "components": result["components"],
            "n_strings": result["n_strings"],
            "cortex_m": result["cortex_m"],
            "architecture": result["architecture"],
            "file_size_bytes": result["file_size_bytes"],
            "container": result["container"],
            "opacity": result["opacity"],
            "vendor": result["vendor"],
            "vendor_errors": result["vendor_errors"],
            "download_url": f"/download/{sbom_id}",
            "download_filename": out_filename,
            "spdx_url": f"/spdx/{sbom_id}",
            "spdx_filename": result["spdx_filename"],
            "evidence_url": f"/evidence/{sbom_id}",
            "evidence_filename": result["evidence_filename"],
        })

    def log_message(self, fmt, *args):
        sys.stderr.write("[fw2sbom-service] " + (fmt % args) + "\n")

    def _send_html(self, text, write_body=True):
        body = text.encode("utf-8")
        self.send_response(200)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        if write_body:
            self.wfile.write(body)

    def _send_json(self, obj, status=200):
        body = json.dumps(obj).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)


class Server(ThreadingHTTPServer):
    """HTTP server that refuses to start on an already-occupied port.

    Two things have to be switched off for that. ThreadingHTTPServer sets
    allow_reuse_address (SO_REUSEADDR), and Windows additionally allows a
    second process to bind a port another server already holds unless
    SO_EXCLUSIVEADDRUSE is set. Without both, starting a second instance -
    or starting alongside some other tool on 8765 - silently "succeeds"
    while a different program answers the browser. For something a customer
    launches by double-clicking, that is the worst possible failure mode.
    """

    allow_reuse_address = False

    def server_bind(self):
        exclusive = getattr(socket, "SO_EXCLUSIVEADDRUSE", None)
        if exclusive is not None:
            try:
                self.socket.setsockopt(socket.SOL_SOCKET, exclusive, 1)
            except OSError:
                pass  # not fatal: we still get SO_REUSEADDR being off
        super().server_bind()


def main():
    # Load the component database before binding the port. A service that
    # starts happily and then reports "0 components" for every upload because
    # its signatures did not ship is the worst possible failure for this tool.
    try:
        signatures = core.load_signatures()
    except ValueError as e:
        print(f"[fw2sbom-service] {e}", file=sys.stderr)
        return 1
    print(f"[fw2sbom-service] {len(signatures)} signatures loaded from "
          f"pack(s) {', '.join(core.SIGNATURE_PACKS)}")

    url = f"http://{HOST}:{PORT}/"
    try:
        server = Server((HOST, PORT), Handler)
    except OSError as e:
        print(f"[fw2sbom-service] cannot listen on {HOST}:{PORT}: {e}",
              file=sys.stderr)
        print("[fw2sbom-service] another program is already using that port. "
              "Close it, or choose another with FW2SBOM_PORT=<port>.",
              file=sys.stderr)
        return 1
    print(f"[fw2sbom-service] listening on {url} (Ctrl+C to stop)")
    try:
        webbrowser.open(url)
    except Exception:
        pass
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("\n[fw2sbom-service] stopped")
    return 0


if __name__ == "__main__":
    sys.exit(main())
