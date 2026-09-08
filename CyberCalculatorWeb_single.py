from __future__ import annotations

import base64
import hashlib
import ipaddress
import json
import math
import re
import secrets
import string
import uuid
from datetime import datetime, timezone
from pathlib import Path
from urllib.parse import parse_qs, unquote, urlencode, urlparse, quote
import socket
import threading
import time
import webbrowser

from flask import Flask, jsonify, render_template_string, request, Response

app = Flask(__name__)

PORTS = [
    (20, "TCP", "FTP Data"), (21, "TCP", "FTP Control"), (22, "TCP", "SSH"),
    (23, "TCP", "Telnet"), (25, "TCP", "SMTP"), (53, "TCP/UDP", "DNS"),
    (67, "UDP", "DHCP Server"), (68, "UDP", "DHCP Client"), (80, "TCP", "HTTP"),
    (110, "TCP", "POP3"), (123, "UDP", "NTP"), (143, "TCP", "IMAP"),
    (161, "UDP", "SNMP"), (389, "TCP/UDP", "LDAP"), (443, "TCP", "HTTPS"),
    (445, "TCP", "SMB"), (465, "TCP", "SMTPS"), (587, "TCP", "SMTP Submission"),
    (636, "TCP", "LDAPS"), (993, "TCP", "IMAPS"), (995, "TCP", "POP3S"),
    (3306, "TCP", "MySQL"), (3389, "TCP", "RDP"), (5432, "TCP", "PostgreSQL"),
    (6379, "TCP", "Redis"), (8080, "TCP", "HTTP Alternate"),
]

HTTP_CODES = [
    (100, "Continue"), (101, "Switching Protocols"), (200, "OK"), (201, "Created"),
    (204, "No Content"), (301, "Moved Permanently"), (302, "Found"), (304, "Not Modified"),
    (307, "Temporary Redirect"), (308, "Permanent Redirect"), (400, "Bad Request"),
    (401, "Unauthorized"), (403, "Forbidden"), (404, "Not Found"), (405, "Method Not Allowed"),
    (408, "Request Timeout"), (409, "Conflict"), (413, "Content Too Large"),
    (415, "Unsupported Media Type"), (422, "Unprocessable Content"), (429, "Too Many Requests"),
    (500, "Internal Server Error"), (501, "Not Implemented"), (502, "Bad Gateway"),
    (503, "Service Unavailable"), (504, "Gateway Timeout"),
]


def error(message: str, status: int = 400):
    return jsonify({"ok": False, "error": message}), status


def vlsm_allocate(base: ipaddress.IPv4Network, requirements: list[int]):
    requirements = sorted(requirements, reverse=True)
    current = int(base.network_address)
    base_end = int(base.broadcast_address)
    results = []

    for req in requirements:
        needed = max(req + 2, 4)
        prefix = 32
        while prefix > base.prefixlen and (2 ** (32 - prefix)) < needed:
            prefix -= 1
        if (2 ** (32 - prefix)) < needed or prefix < base.prefixlen:
            raise ValueError("Requirements do not fit inside the base network")
        block = 2 ** (32 - prefix)
        if current % block:
            current += block - (current % block)
        end = current + block - 1
        if end > base_end:
            raise ValueError("Requirements exceed the available address space")
        net = ipaddress.ip_network(f"{ipaddress.IPv4Address(current)}/{prefix}")
        if prefix <= 30:
            first = str(net.network_address + 1)
            last = str(net.broadcast_address - 1)
            usable = net.num_addresses - 2
        else:
            first = str(net.network_address)
            last = str(net.broadcast_address)
            usable = net.num_addresses
        results.append({
            "requested": req, "network": str(net.network_address), "prefix": prefix,
            "mask": str(net.netmask), "broadcast": str(net.broadcast_address),
            "first": first, "last": last, "total": net.num_addresses, "usable": usable,
        })
        current = end + 1
    return results



# Embedded frontend assets for single-file distribution
INDEX_HTML = '<!doctype html>\n<html lang="en" dir="ltr">\n<head>\n  <meta charset="utf-8">\n  <meta name="viewport" content="width=device-width, initial-scale=1">\n  <meta name="theme-color" content="#070a0f">\n  <title>Cyber Calculator Web</title>\n  <link rel="stylesheet" href="/static/style.css">\n</head>\n<body>\n  <canvas id="matrix"></canvas>\n  <div class="noise"></div>\n  <div id="drawerBackdrop" class="drawer-backdrop"></div>\n  <div class="app-shell">\n    <header class="topbar glass">\n      <div class="brand">\n        <button class="mobile-menu" id="mobileMenu">☰</button>\n        <div class="brand-mark">◈</div>\n        <div><div class="brand-title">CYBER CALCULATOR</div><div class="brand-subtitle">Network & Security Computation Suite</div></div>\n      </div>\n      <div class="top-actions">\n        <div class="status"><span class="pulse"></span><span>SYSTEM ONLINE</span></div>\n        <div class="search-wrap"><span>⌕</span><input id="globalSearch" placeholder="Search tools..."></div>\n        <button class="icon-btn" id="themeBtn" title="Change theme">◐</button>\n      </div>\n    </header>\n\n    <div class="layout">\n      <aside id="sidebar" class="sidebar glass">\n        <div class="side-section-title">CONTROL PANEL</div>\n        <button class="nav-item active" data-tool="dashboard"><span>⌂</span><span>Dashboard</span></button>\n        <button class="nav-item" data-tool="calculator"><span>∑</span><span>Calculator</span></button>\n        <button class="nav-item" data-tool="network"><span>◎</span><span>Network</span></button>\n        <button class="nav-item" data-tool="security"><span>⌘</span><span>Security</span></button>\n        <button class="nav-item" data-tool="utilities"><span>⚒</span><span>Utilities</span></button>\n        <div class="side-divider"></div>\n        <button class="nav-item" data-tool="settings"><span>⚙</span><span>Settings</span></button>\n        <div class="sidebar-footer"><span>v10.0 Web</span><span class="tiny-dot"></span></div>\n      </aside>\n\n      <main id="main" class="main glass">\n        <div id="view"></div>\n      </main>\n    </div>\n  </div>\n  <div id="toast"></div>\n  <script src="/static/app.js"></script>\n</body>\n</html>\n'
STYLE_CSS = ':root{--bg:#05080d;--panel:rgba(10,16,23,.84);--card:rgba(15,24,34,.86);--card2:#162432;--text:#e8eef4;--muted:#71808f;--green:#00ff88;--blue:#00c8ff;--purple:#a970ff;--yellow:#ffd166;--red:#ff4d6d;--border:rgba(63,94,116,.26);--shadow:0 20px 70px rgba(0,0,0,.35)}\n*{box-sizing:border-box}html,body{margin:0;min-height:100%;background:radial-gradient(circle at 20% 10%,rgba(0,255,136,.05),transparent 24%),radial-gradient(circle at 80% 90%,rgba(0,200,255,.05),transparent 30%),var(--bg);color:var(--text);font-family:"Segoe UI",Arial,sans-serif}body{overflow-x:hidden}.noise{position:fixed;inset:0;pointer-events:none;opacity:.04;background-image:repeating-linear-gradient(0deg,transparent,transparent 2px,#fff 3px);mix-blend-mode:overlay}#matrix{position:fixed;inset:0;width:100%;height:100%;opacity:.13;pointer-events:none}.app-shell{position:relative;z-index:2;max-width:1500px;margin:auto;padding:18px}.glass{background:var(--panel);backdrop-filter:blur(18px);-webkit-backdrop-filter:blur(18px);border:1px solid var(--border);box-shadow:var(--shadow)}.topbar{min-height:76px;border-radius:18px;padding:12px 16px;display:flex;align-items:center;justify-content:space-between;gap:16px}.brand{display:flex;align-items:center;gap:12px}.brand-mark{width:46px;height:46px;border:1px solid rgba(0,255,136,.35);border-radius:13px;display:grid;place-items:center;color:var(--green);font-size:24px;box-shadow:0 0 25px rgba(0,255,136,.12)}.brand-title{font:700 20px Consolas,monospace;letter-spacing:.06em;color:var(--green)}.brand-subtitle{font-size:12px;color:var(--muted);margin-top:2px}.top-actions{display:flex;align-items:center;gap:10px}.status{display:flex;align-items:center;gap:8px;font:600 11px Consolas,monospace;color:var(--green);white-space:nowrap}.pulse{width:8px;height:8px;background:var(--green);border-radius:50%;box-shadow:0 0 8px var(--green);animation:pulse 1.5s infinite}.search-wrap{display:flex;align-items:center;gap:8px;background:#070c11;border:1px solid var(--border);border-radius:10px;padding:0 10px;width:min(280px,31vw)}.search-wrap input{width:100%;padding:10px 4px;background:transparent;border:0;outline:0;color:var(--text)}.icon-btn,.mobile-menu{background:#0a1118;border:1px solid var(--border);color:var(--text);border-radius:10px;padding:10px 12px;cursor:pointer}.mobile-menu{display:none}.layout{display:grid;grid-template-columns:250px minmax(0,1fr);gap:16px;margin-top:16px}.sidebar{border-radius:18px;padding:16px;display:flex;flex-direction:column;min-height:calc(100vh - 126px)}.side-section-title{font:700 10px Consolas,monospace;color:var(--blue);padding:8px 10px 12px;letter-spacing:.12em}.nav-item{display:flex;align-items:center;gap:12px;background:transparent;border:0;color:var(--text);padding:13px 12px;border-radius:10px;text-align:left;cursor:pointer;font-weight:600;transition:.25s}.nav-item span:first-child{width:22px;color:var(--muted)}.nav-item:hover{background:rgba(22,36,50,.75);transform:translateX(3px)}.nav-item.active{background:linear-gradient(90deg,rgba(0,255,136,.16),rgba(0,255,136,.02));color:var(--green);box-shadow:inset 3px 0 var(--green)}.nav-item.active span:first-child{color:var(--green)}.side-divider{height:1px;background:var(--border);margin:12px 0}.sidebar-footer{margin-top:auto;display:flex;align-items:center;justify-content:space-between;color:#526170;font:11px Consolas,monospace;padding:10px}.tiny-dot{width:7px;height:7px;background:var(--green);border-radius:50%}.main{border-radius:18px;min-height:calc(100vh - 126px);padding:18px;overflow:hidden}.view{animation:pageIn .42s ease}.hero{display:flex;align-items:center;justify-content:space-between;gap:20px;padding:18px 10px 22px}.hero h1{margin:0;font:700 clamp(24px,3vw,36px) Consolas,monospace}.hero p{margin:7px 0 0;color:var(--muted)}.hero-badge{border:1px solid rgba(0,255,136,.2);padding:8px 12px;border-radius:999px;color:var(--green);font:600 11px Consolas,monospace}.stats,.grid{display:grid;grid-template-columns:repeat(4,minmax(0,1fr));gap:12px}.grid-3{grid-template-columns:repeat(3,minmax(0,1fr))}.grid-2{grid-template-columns:repeat(2,minmax(0,1fr))}.stat,.tool-card,.panel-card{background:linear-gradient(180deg,rgba(18,28,38,.95),rgba(10,16,23,.95));border:1px solid var(--border);border-radius:16px;padding:16px;position:relative;overflow:hidden}.stat:before,.tool-card:before{content:"";position:absolute;inset:0;background:linear-gradient(135deg,rgba(0,255,136,.08),transparent 40%);opacity:.7;pointer-events:none}.stat-label{font:11px Consolas,monospace;color:var(--muted)}.stat-value{font:700 28px Consolas,monospace;margin-top:6px}.tool-card{min-height:145px;transition:.25s;cursor:pointer}.tool-card:hover{transform:translateY(-4px);border-color:rgba(0,255,136,.35);box-shadow:0 10px 40px rgba(0,255,136,.07)}.tool-icon{font-size:22px;color:var(--green)}.tool-title{font:700 15px Consolas,monospace;margin-top:12px}.tool-desc{font-size:12px;color:var(--muted);margin:7px 0 15px;min-height:32px}.btn{border:0;border-radius:9px;padding:10px 13px;background:var(--green);color:#04110a;font-weight:800;cursor:pointer;transition:.2s}.btn:hover{transform:translateY(-1px);filter:brightness(1.05)}.btn.secondary{background:#14202b;color:var(--text);border:1px solid var(--border)}.btn.blue{background:var(--blue);color:#041016}.btn.purple{background:var(--purple);color:#10051d}.toolbar{display:flex;flex-wrap:wrap;gap:9px;align-items:center;margin:10px 0 14px}.form-grid{display:grid;grid-template-columns:repeat(2,minmax(0,1fr));gap:12px}.field label{display:block;color:var(--muted);font:11px Consolas,monospace;margin-bottom:7px}.input,.select,.textarea{width:100%;background:#070c11;border:1px solid var(--border);color:var(--text);border-radius:10px;padding:11px 12px;outline:none}.textarea{min-height:140px;resize:vertical}.input:focus,.select:focus,.textarea:focus{border-color:rgba(0,255,136,.55);box-shadow:0 0 0 3px rgba(0,255,136,.06)}.result{margin-top:12px;background:#060a0f;border:1px solid var(--border);border-radius:12px;padding:14px;overflow:auto;white-space:pre-wrap;min-height:100px;font:12px/1.7 Consolas,monospace}.table-wrap{overflow:auto;border:1px solid var(--border);border-radius:12px}.data-table{width:100%;border-collapse:collapse;font-size:12px}.data-table th,.data-table td{padding:10px;border-bottom:1px solid var(--border);text-align:left}.data-table th{color:var(--green);font:700 11px Consolas,monospace;background:#0b1219}.notice{padding:11px 12px;border-left:3px solid var(--blue);background:rgba(0,200,255,.06);border-radius:8px;color:#aac6d5;font-size:12px}.tool-layout{display:grid;grid-template-columns:230px minmax(0,1fr);gap:14px}.tool-list{display:flex;flex-direction:column;gap:7px}.tool-chip{padding:10px 11px;border:1px solid var(--border);background:#0a1118;border-radius:9px;color:var(--text);cursor:pointer;text-align:left}.tool-chip.active{border-color:rgba(0,255,136,.3);color:var(--green);background:rgba(0,255,136,.06)}.footer-note{margin-top:16px;color:#506170;font:10px Consolas,monospace}.mini{font-size:11px;color:var(--muted)}.progress{height:5px;background:#101923;border-radius:999px;overflow:hidden}.progress span{display:block;height:100%;background:linear-gradient(90deg,var(--green),var(--blue));width:0;transition:1s}.modal-backdrop{position:fixed;inset:0;background:rgba(2,5,8,.78);display:none;place-items:center;z-index:50}.modal{width:min(760px,92vw);background:#0d141c;border:1px solid var(--border);border-radius:18px;padding:18px;box-shadow:var(--shadow)}#toast{position:fixed;right:20px;bottom:20px;z-index:60;padding:11px 14px;background:#101923;border:1px solid var(--border);border-radius:10px;opacity:0;transform:translateY(12px);transition:.25s;pointer-events:none;font-size:12px}#toast.show{opacity:1;transform:none}@keyframes pulse{0%,100%{transform:scale(1);opacity:1}50%{transform:scale(1.5);opacity:.55}}@keyframes pageIn{from{opacity:0;transform:translateY(10px)}to{opacity:1;transform:none}}@media(max-width:1100px){.stats{grid-template-columns:repeat(2,minmax(0,1fr))}.search-wrap{width:220px}}@media(max-width:860px){.layout{grid-template-columns:1fr}.sidebar{position:fixed;left:12px;top:100px;bottom:12px;width:250px;z-index:20;transform:translateX(-115%);transition:.3s}.sidebar.open{transform:none}.mobile-menu{display:inline-block}.topbar{align-items:flex-start}.top-actions{flex-wrap:wrap;justify-content:flex-end}.search-wrap{order:4;width:100%}.main{min-height:calc(100vh - 160px)}.tool-layout{grid-template-columns:1fr}.grid-3,.grid-2{grid-template-columns:1fr 1fr}}@media(max-width:600px){.app-shell{padding:9px}.topbar{border-radius:14px;padding:10px}.brand-title{font-size:16px}.brand-subtitle{font-size:10px}.status{display:none}.stats{grid-template-columns:1fr 1fr}.form-grid{grid-template-columns:1fr}.grid{grid-template-columns:1fr}.main{padding:12px}.hero{padding:8px 4px 16px;align-items:flex-start}.hero-badge{font-size:9px}.tool-card{min-height:auto}}\n\n:root{--ease:cubic-bezier(.22,.61,.36,1)}\nhtml{scroll-behavior:smooth}\nbody{min-width:0}\nbutton,input,select,textarea{font:inherit}\nbutton{appearance:none;-webkit-tap-highlight-color:transparent}\n.topbar{position:relative;overflow:visible}\n.brand{min-width:0;flex:1 1 auto}\n.brand > div:last-child{min-width:0}\n.brand-title,.brand-subtitle{overflow:hidden;text-overflow:ellipsis;white-space:nowrap}\n.top-actions{flex:0 1 auto;min-width:0}\n.search-wrap{flex:0 1 280px;min-width:150px}\n.main{position:relative}\n.view{animation:pageIn .42s var(--ease);will-change:opacity,transform}\n.panel-card,.tool-card,.stat{animation:cardIn .48s var(--ease) both}\n.tool-card:nth-child(1),.stat:nth-child(1){animation-delay:.03s}\n.tool-card:nth-child(2),.stat:nth-child(2){animation-delay:.07s}\n.tool-card:nth-child(3),.stat:nth-child(3){animation-delay:.11s}\n.tool-card:nth-child(4),.stat:nth-child(4){animation-delay:.15s}\n.tool-card:nth-child(5){animation-delay:.19s}\n.tool-card:nth-child(6){animation-delay:.23s}\n.tool-card:nth-child(7){animation-delay:.27s}\n.tool-card:nth-child(8){animation-delay:.31s}\n.tool-card:nth-child(9){animation-delay:.35s}\n.tool-card{transform-origin:center bottom}\n.tool-card:hover{transform:translateY(-5px) scale(1.01)}\n.tool-chip{transition:background .22s var(--ease),border-color .22s var(--ease),transform .22s var(--ease),color .22s var(--ease)}\n.tool-chip:hover{transform:translateX(3px);border-color:rgba(0,255,136,.25)}\n.nav-item{position:relative;overflow:hidden}\n.nav-item::after{content:"";position:absolute;inset:0;background:linear-gradient(90deg,transparent,rgba(0,255,136,.08),transparent);transform:translateX(-110%);transition:transform .5s var(--ease);pointer-events:none}\n.nav-item:hover::after{transform:translateX(110%)}\n.btn{position:relative;overflow:hidden}\n.btn::after{content:"";position:absolute;top:-120%;left:-30%;width:30%;height:340%;background:rgba(255,255,255,.18);transform:rotate(18deg) translateX(-260%);transition:transform .7s var(--ease);pointer-events:none}\n.btn:hover::after{transform:rotate(18deg) translateX(720%)}\n.input:focus,.select:focus,.textarea:focus{transform:translateY(-1px);transition:transform .2s var(--ease)}\n#toast{direction:auto}\n\n/* Robust RTL layout: keep the app grid logical, move only the sidebar visually. */\n\n/* Mobile drawer */\n.drawer-backdrop{position:fixed;inset:0;background:rgba(1,5,8,.58);backdrop-filter:blur(3px);z-index:18;opacity:0;pointer-events:none;transition:opacity .25s var(--ease)}\n.drawer-backdrop.show{opacity:1;pointer-events:auto}\n@media(max-width:860px){\n  .app-shell{padding:10px}\n  .topbar{gap:10px;min-height:70px}\n  .brand{gap:9px}\n  .brand-mark{width:40px;height:40px;font-size:20px}\n  .top-actions{gap:7px}\n  .search-wrap{flex-basis:100%;min-width:0;order:5}\n  .mobile-menu{display:inline-grid;place-items:center;flex:0 0 auto}\n  .layout{display:block;margin-top:12px}\n  .sidebar{position:fixed;top:86px;bottom:10px;left:10px;right:auto;width:min(290px,82vw);min-height:0;height:auto;z-index:30;transform:translateX(-115%);transition:transform .35s var(--ease);overflow:auto}\n  .sidebar.open{transform:translateX(0)}\n  .main{min-height:calc(100vh - 95px);padding:14px}\n  .hero{flex-direction:column;gap:10px}\n  .hero-badge{align-self:flex-start}\n}\n@media(max-width:600px){\n  .app-shell{padding:7px}\n  .topbar{border-radius:14px;padding:9px}\n  .brand-title{font-size:15px}\n  .brand-subtitle{font-size:9px;max-width:45vw}\n  .icon-btn,.mobile-menu{padding:9px 10px}\n  .search-wrap{width:100%}\n  .stats,.grid,.grid-2,.grid-3,.form-grid{grid-template-columns:1fr}\n  .tool-layout{grid-template-columns:1fr}\n  .tool-list{display:grid;grid-template-columns:repeat(2,minmax(0,1fr))}\n  .tool-chip{text-align:center}\n  .main{border-radius:14px;padding:11px}\n  .panel-card{padding:13px}\n  .btn{min-height:42px}\n}\n@media(prefers-reduced-motion:reduce){*,*::before,*::after{animation-duration:.001ms!important;animation-iteration-count:1!important;transition-duration:.001ms!important;scroll-behavior:auto!important}}\n@keyframes cardIn{from{opacity:0;transform:translateY(14px) scale(.985)}to{opacity:1;transform:translateY(0) scale(1)}}\n\n\n.layout{display:grid;grid-template-columns:280px minmax(0,1fr);gap:14px;align-items:stretch;direction:ltr}\n.sidebar{grid-column:1;grid-row:1;min-width:0}\n.main{grid-column:2;grid-row:1;min-width:0}\n\n@media(max-width:860px){\n  .layout{display:block;direction:ltr}\n  .main{display:block;width:auto}\n  .sidebar{\n    display:block;\n    position:fixed !important;\n    top:86px !important;\n    bottom:10px !important;\n    left:10px !important;\n    right:auto !important;\n    width:min(290px,82vw) !important;\n    max-width:calc(100vw - 20px);\n    height:auto !important;\n    z-index:100 !important;\n    transform:translate3d(-120%,0,0) !important;\n    visibility:hidden;\n    opacity:0;\n    transition:transform .35s var(--ease),opacity .25s var(--ease),visibility 0s linear .35s;\n  }\n  .sidebar.open{\n    transform:translate3d(0,0,0) !important;\n    visibility:visible;\n    opacity:1;\n    transition:transform .35s var(--ease),opacity .25s var(--ease),visibility 0s linear 0s;\n  }\n    left:auto !important;\n    right:10px !important;\n    transform:translate3d(120%,0,0) !important;\n  }\n  .drawer-backdrop{z-index:90 !important}\n  .mobile-menu{display:inline-grid !important;place-items:center;z-index:110}\n  .topbar{position:relative;z-index:120}\n}\n\n@media(max-width:600px){\n  .sidebar{width:min(310px,86vw) !important}\n  .topbar{min-width:0;overflow:visible}\n  .brand{min-width:0}\n  .brand-title,.brand-subtitle{max-width:52vw}\n}'
APP_JS = 'const state={theme:localStorage.theme||\'matrix\',current:\'dashboard\'};\nconst $=s=>document.querySelector(s); const view=$(\'#view\');\nfunction toast(m){const t=$(\'#toast\');t.textContent=m;t.classList.add(\'show\');setTimeout(()=>t.classList.remove(\'show\'),2200)}\nfunction applyTheme(){document.body.dataset.theme=state.theme; localStorage.theme=state.theme}\nasync function api(payload){const r=await fetch(\'/api/execute\',{method:\'POST\',headers:{\'Content-Type\':\'application/json\'},body:JSON.stringify(payload)});const d=await r.json();if(!d.ok)throw new Error(d.error||\'Error\');return d.result}\nfunction closeDrawer(){const sb=$(\'#sidebar\'),bd=$(\'#drawerBackdrop\');sb.classList.remove(\'open\');bd&&bd.classList.remove(\'show\')}\nfunction openDrawer(){const sb=$(\'#sidebar\'),bd=$(\'#drawerBackdrop\');sb.classList.add(\'open\');bd&&bd.classList.add(\'show\')}\nfunction setNav(tool){state.current=tool;document.querySelectorAll(\'.nav-item\').forEach(x=>x.classList.toggle(\'active\',x.dataset.tool===tool));render();if(innerWidth<860)closeDrawer()}\nfunction field(label,id,value=\'\',type=\'text\'){return `<div class="field"><label>${label}</label><input id="${id}" class="input" type="${type}" value="${value}"></div>`}\nfunction btn(label,id,cls=\'\'){return `<button id="${id}" class="btn ${cls}">${label}</button>`}\nfunction resultBox(id=\'result\'){return `<div id="${id}" class="result">READY.</div>`}\nfunction escapeHtml(x){return String(x).replace(/[&<>\\"]/g,s=>({\'&\':\'&amp;\',\'<\':\'&lt;\',\'>\':\'&gt;\',\'\\"\':\'&quot;\',\'\\\\\':\'&#39;\'}[s]))}\nfunction resultText(obj){if(typeof obj===\'string\')return obj;if(Array.isArray(obj))return JSON.stringify(obj,null,2);return Object.entries(obj).map(([k,v])=>`${k}: ${typeof v===\'object\'?JSON.stringify(v):v}`).join(\'\\n\')}\nfunction shell(title,sub,body){view.innerHTML=`<div class="view"><div class="hero"><div><h1>${title}</h1><p>${sub}</p></div><div class="hero-badge">● LIVE MODULE</div></div>${body}</div>`}\nfunction renderDashboard(){shell(\'SYSTEM DASHBOARD\',\'Cyber tools for calculation, networking, encoding and defensive analysis.\',`<div class="stats"><div class="stat"><div class="stat-label">TOOLS</div><div class="stat-value">24+</div></div><div class="stat"><div class="stat-label">NETWORK</div><div class="stat-value">9</div></div><div class="stat"><div class="stat-label">SECURITY</div><div class="stat-value">8</div></div><div class="stat"><div class="stat-label">STATUS</div><div class="stat-value" style="color:var(--green)">ONLINE</div></div></div><div style="height:16px"></div><div class="grid grid-3">${cards()}</div>`);document.querySelectorAll(\'.tool-card[data-open]\').forEach(c=>c.onclick=()=>setNav(c.dataset.open))}\nfunction cards(){const arr=[[\'◎\',\'IPv4 / CIDR\',\'Network analysis\',\'network\'],[\'▦\',\'Subnet\',\'Split networks\',\'network\'],[\'◫\',\'VLSM\',\'Variable subnetting\',\'network\'],[\'◎\',\'IPv6\',\'IPv6 analysis\',\'network\'],[\'01\',\'Bitwise\',\'AND / OR / XOR / shifts\',\'network\'],[\'#\',\'Hash\',\'Text and file integrity hashes\',\'security\'],[\'↔\',\'Encoding\',\'Base64 / Hex / URL\',\'security\'],[\'◈\',\'Entropy\',\'Password entropy estimate\',\'security\'],[\'{}\',\'JSON\',\'Validate and format JSON\',\'utilities\']];return arr.map(a=>`<div class="tool-card" data-open="${a[3]}"><div class="tool-icon">${a[0]}</div><div class="tool-title">${a[1]}</div><div class="tool-desc">${a[2]}</div><button class="btn secondary">OPEN MODULE</button></div>`).join(\'\')}\nfunction renderCalculator(){shell(\'CALCULATOR\',\'Scientific calculator with keyboard-friendly controls.\',`<div class="panel-card"><input id="calcDisplay" class="input" style="font:700 24px Consolas,monospace;text-align:right;margin-bottom:12px" value=""><div class="grid grid-3">${[\'sin\',\'cos\',\'tan\',\'sqrt\',\'log\',\'ln\',\'7\',\'8\',\'9\',\'4\',\'5\',\'6\',\'1\',\'2\',\'3\',\'0\',\'.\',\'+\',\'-\',\'*\',\'/\',\'(\',\')\',\'AC\',\'⌫\',\'=\'].map(x=>`<button class="btn ${x===\'=\'?\'\':\'secondary\'}" data-k="${x}">${x}</button>`).join(\'\')}</div></div>`);const d=$(\'#calcDisplay\');const press=k=>{if(k===\'AC\')d.value=\'\';else if(k===\'⌫\')d.value=d.value.slice(0,-1);else if(k===\'=\'){try{d.value=Function(\'return \'+d.value.replace(\'sin\',\'Math.sin\').replace(\'cos\',\'Math.cos\').replace(\'tan\',\'Math.tan\').replace(\'sqrt\',\'Math.sqrt\').replace(\'log\',\'Math.log10\').replace(\'ln\',\'Math.log\'))()}catch{d.value=\'Error\'}}else d.value+=k};document.querySelectorAll(\'[data-k]\').forEach(b=>b.onclick=()=>press(b.dataset.k));d.addEventListener(\'keydown\',e=>{if(e.key===\'Enter\')press(\'=\')})}\nfunction renderNetwork(){shell(\'NETWORK TOOLKIT\',\'IPv4, IPv6, subnetting, VLSM, bitwise and MAC tools.\',`<div class="tool-layout"><div class="tool-list">${[[\'ipv4\',\'IPv4 / CIDR\'],[\'subnet\',\'Subnet\'],[\'vlsm\',\'VLSM\'],[\'ipv6\',\'IPv6\'],[\'range\',\'IP Range\'],[\'wildcard\',\'Wildcard\'],[\'bitwise\',\'Bitwise\'],[\'mac\',\'MAC Formatter\'],[\'convert\',\'Number Converter\']].map((x,i)=>`<button class="tool-chip ${i===0?\'active\':\'\'}" data-net="${x[0]}">${x[1]}</button>`).join(\'\')}</div><div id="netPanel"></div></div>`);document.querySelectorAll(\'[data-net]\').forEach(b=>b.onclick=()=>{document.querySelectorAll(\'[data-net]\').forEach(x=>x.classList.remove(\'active\'));b.classList.add(\'active\');renderNetTool(b.dataset.net)});renderNetTool(\'ipv4\')}\nfunction renderNetTool(t){const p=$(\'#netPanel\');const map={ipv4:[\'IPv4 / CIDR\',\'Analyze IPv4 interface\',`<div class="form-grid">${field(\'IPv4/CIDR\',\'v\',\'192.168.1.25/24\')}</div>${btn(\'CALCULATE\',\'go\')}${resultBox()}`],ipv6:[\'IPv6\',\'Analyze IPv6 interface\',`<div class="form-grid">${field(\'IPv6/CIDR\',\'v\',\'2001:db8::10/64\')}</div>${btn(\'CALCULATE\',\'go\')}${resultBox()}`],subnet:[\'Subnet\',\'Split a network into equal subnets\',`<div class="form-grid">${field(\'Network\',\'n\',\'192.168.1.0/24\')}${field(\'New Prefix\',\'p\',\'26\',\'number\')}</div>${btn(\'SPLIT\',\'go\')}${resultBox()}`],vlsm:[\'VLSM\',\'Allocate variable-size IPv4 subnets\',`<div class="form-grid">${field(\'Base Network\',\'n\',\'192.168.10.0/24\')}${field(\'Host Requirements\',\'h\',\'100,50,20,10\')}</div>${btn(\'CALCULATE VLSM\',\'go\')}${resultBox()}`],range:[\'IP Range\',\'Check if an IP belongs to a CIDR network\',`<div class="form-grid">${field(\'IP\',\'ip\',\'192.168.1.25\')}${field(\'Network\',\'n\',\'192.168.1.0/24\')}</div>${btn(\'CHECK\',\'go\')}${resultBox()}`],wildcard:[\'Wildcard\',\'CIDR to subnet and wildcard mask\',`<div class="form-grid">${field(\'Prefix\',\'p\',\'24\',\'number\')}</div>${btn(\'CALCULATE\',\'go\')}${resultBox()}`],bitwise:[\'Bitwise\',\'Bitwise operations for network calculations\',`<div class="form-grid">${field(\'A\',\'a\',\'12\',\'number\')}${field(\'B\',\'b\',\'10\',\'number\')}</div>${btn(\'CALCULATE\',\'go\')}${resultBox()}`],mac:[\'MAC Formatter\',\'Normalize and inspect a MAC address\',`<div class="form-grid">${field(\'MAC\',\'v\',\'AA:BB:CC:DD:EE:FF\')}</div>${btn(\'FORMAT\',\'go\')}${resultBox()}`],convert:[\'Number Converter\',\'Decimal / Binary / Hex\',`<div class="form-grid">${field(\'Value\',\'v\',\'192\')}<div class="field"><label>BASE</label><select id="b" class="select"><option>decimal</option><option>binary</option><option>hex</option></select></div></div>${btn(\'CONVERT\',\'go\')}${resultBox()}`]};const m=map[t];p.innerHTML=`<div class="panel-card"><h2 style="font:700 17px Consolas,monospace;margin-top:0">${m[0]}</h2><div class="mini">${m[1]}</div><div style="height:14px"></div>${m[2]}</div>`;$(\'#go\').onclick=async()=>{try{let payload={};if(t===\'ipv4\'||t===\'ipv6\'||t===\'mac\')payload={tool:t,value:$(\'#v\').value};if(t===\'subnet\')payload={tool:t,network:$(\'#n\').value,prefix:$(\'#p\').value};if(t===\'vlsm\')payload={tool:t,network:$(\'#n\').value,hosts:$(\'#h\').value};if(t===\'range\')payload={tool:t,ip:$(\'#ip\').value,network:$(\'#n\').value};if(t===\'wildcard\')payload={tool:t,prefix:$(\'#p\').value};if(t===\'bitwise\')payload={tool:t,a:$(\'#a\').value,b:$(\'#b\').value};if(t===\'convert_number\'){payload={tool:t,value:$(\'#v\').value,base:$(\'#b\').value}}const r=await api(payload);$(\'#result\').textContent=resultText(r)}catch(e){$(\'#result\').textContent=\'ERROR: \'+e.message}}}\nfunction renderSecurity(){shell(\'SECURITY TOOLKIT\',\'Defensive and educational security utilities.\',`<div class="tool-layout"><div class="tool-list">${[[\'hash\',\'Hash\'],[\'encoding\',\'Encoding\'],[\'entropy\',\'Entropy\'],[\'uuid\',\'UUID\'],[\'checksum\',\'Checksum\'],[\'jwt\',\'JWT Decoder\']].map((x,i)=>`<button class="tool-chip ${i===0?\'active\':\'\'}" data-sec="${x[0]}">${x[1]}</button>`).join(\'\')}</div><div id="secPanel"></div></div>`);document.querySelectorAll(\'[data-sec]\').forEach(b=>b.onclick=()=>{document.querySelectorAll(\'[data-sec]\').forEach(x=>x.classList.remove(\'active\'));b.classList.add(\'active\');renderSecTool(b.dataset.sec)});renderSecTool(\'hash\')}\nfunction renderSecTool(t){const p=$(\'#secPanel\');let html=\'\';if(t===\'hash\')html=`<div class="panel-card"><h2>Hash Calculator</h2><div class="form-grid">${field(\'Text\',\'v\',\'hello\')}<div class="field"><label>ALGORITHM</label><select id="a" class="select"><option>SHA-256</option><option>SHA-512</option><option>SHA-1</option><option>MD5</option><option>SHA3-256</option><option>SHA3-512</option></select></div></div>${btn(\'CALCULATE HASH\',\'go\')}${resultBox()}</div>`;if(t===\'encoding\')html=`<div class="panel-card"><h2>Encoding</h2>${field(\'Input\',\'v\',\'hello\')}<div class="toolbar"><select id="m" class="select"><option value="base64">Base64</option><option value="hex">Hex</option><option value="url">URL</option></select>${btn(\'ENCODE\',\'enc\')}${btn(\'DECODE\',\'dec\',\'secondary\')}</div>${resultBox()}</div>`;if(t===\'entropy\')html=`<div class="panel-card"><h2>Password Entropy</h2>${field(\'Text\',\'v\',\'Example123!\')}${btn(\'ANALYZE\',\'go\')}${resultBox()}</div>`;if(t===\'uuid\')html=`<div class="panel-card"><h2>UUID Generator</h2>${field(\'Count\',\'c\',\'5\',\'number\')}${btn(\'GENERATE\',\'go\')}${resultBox()}</div>`;if(t===\'checksum\')html=`<div class="panel-card"><h2>Checksum</h2>${field(\'Text\',\'v\',\'hello\')}${btn(\'CALCULATE\',\'go\')}${resultBox()}</div>`;if(t===\'jwt\')html=`<div class="panel-card"><h2>JWT Structure Decoder</h2><div class="notice">Decodes header and payload only. It does not verify or break signatures.</div><div style="height:12px"></div><div class="field"><label>TOKEN</label><textarea id="v" class="textarea">eyJhbGciOiJub25lIn0.eyJzdWIiOiIxMjM0In0.</textarea></div>${btn(\'DECODE\',\'go\')}${resultBox()}</div>`;p.innerHTML=html;$(\'#go\')&&($(\'#go\').onclick=async()=>{try{let payload={tool:t};if(t===\'hash\')payload={tool:t,value:$(\'#v\').value,algorithm:$(\'#a\').value};else if(t===\'entropy\'||t===\'checksum\'||t===\'jwt\')payload={tool:t,value:$(\'#v\').value};else if(t===\'uuid\')payload={tool:t,count:$(\'#c\').value};const r=await api(payload);$(\'#result\').textContent=resultText(r)}catch(e){$(\'#result\').textContent=\'ERROR: \'+e.message}});if(t===\'encoding\'){for(const id of [\'enc\',\'dec\'])$(\'#\'+id).onclick=async()=>{try{$(\'#result\').textContent=resultText(await api({tool:t,mode:$(\'#m\').value,action:id===\'enc\'?\'encode\':\'decode\',value:$(\'#v\').value}))}catch(e){$(\'#result\').textContent=\'ERROR: \'+e.message}}}}\nfunction renderUtilities(){shell(\'UTILITIES\',\'Developer and analysis helpers.\',`<div class="grid grid-2"><div class="panel-card"><h2>Timestamp</h2><div class="toolbar">${btn(\'NOW\',\'tsnow\')}${btn(\'FROM UNIX\',\'tsunix\',\'secondary\')}</div>${field(\'Value\',\'tsv\',\'0\')} ${resultBox(\'tsres\')}</div><div class="panel-card"><h2>ASCII</h2>${field(\'Text or Code\',\'asv\',\'A\')}${btn(\'TEXT → CODES\',\'asc\')}${resultBox(\'asres\')}</div><div class="panel-card"><h2>Regex Tester</h2>${field(\'Pattern\',\'rp\',\'^[A-Z]\')}<div class="field"><label>TEXT</label><textarea id="rt" class="textarea">ABC abc XYZ</textarea></div>${btn(\'TEST\',\'rg\')}${resultBox(\'rgres\')}</div><div class="panel-card"><h2>JSON Formatter</h2><textarea id="jv" class="textarea">{"name":"cyber","ready":true}</textarea>${btn(\'FORMAT\',\'jf\')}${resultBox(\'jres\')}</div><div class="panel-card"><h2>URL Parser</h2>${field(\'URL\',\'uv\',\'https://example.com/a?x=1&y=2\')}${btn(\'PARSE\',\'up\')}${resultBox(\'ures\')}</div><div class="panel-card"><h2>Unit Converter</h2><div class="form-grid">${field(\'Value\',\'cv\',\'10\',\'number\')}<div class="field"><label>TYPE</label><select id="ck" class="select"><option value="length">Length</option><option value="data">Data</option><option value="time">Time</option></select></div>${field(\'From\',\'cf\',\'km\')} ${field(\'To\',\'ct\',\'m\')}</div>${btn(\'CONVERT\',\'cu\')}${resultBox(\'cres\')}</div></div>`);$(\'#tsnow\').onclick=async()=>$(\'#tsres\').textContent=resultText(await api({tool:\'timestamp\',mode:\'now\'}));$(\'#tsunix\').onclick=async()=>$(\'#tsres\').textContent=resultText(await api({tool:\'timestamp\',mode:\'from_timestamp\',value:$(\'#tsv\').value}));$(\'#asc\').onclick=async()=>$(\'#asres\').textContent=resultText(await api({tool:\'ascii\',value:$(\'#asv\').value}));$(\'#rg\').onclick=async()=>{$(\'#rgres\').textContent=resultText(await api({tool:\'regex\',pattern:$(\'#rp\').value,value:$(\'#rt\').value}))};$(\'#jf\').onclick=async()=>{$(\'#jres\').textContent=resultText(await api({tool:\'json\',value:$(\'#jv\').value}))};$(\'#up\').onclick=async()=>{$(\'#ures\').textContent=resultText(await api({tool:\'url\',value:$(\'#uv\').value}))};$(\'#cu\').onclick=async()=>{$(\'#cres\').textContent=resultText(await api({tool:\'unit\',kind:$(\'#ck\').value,value:$(\'#cv\').value,from:$(\'#cf\').value,to:$(\'#ct\').value}))}}\nfunction renderSettings(){shell(\'SETTINGS\',\'Appearance and interface preferences.\',`<div class="panel-card"><div class="form-grid"><div><div class="field"><label>THEME</label><select id="themeSel" class="select"><option value="matrix">Matrix</option><option value="blue">Cyber Blue</option><option value="purple">Purple Core</option><option value="minimal">Dark Minimal</option></select></div></div></div><div style="height:14px"></div><div class="notice">English-only web edition. The desktop Python application remains untouched.</div></div>`);$(\'#themeSel\').value=state.theme;$(\'#themeSel\').onchange=e=>{state.theme=e.target.value;applyTheme();toast(\'Theme updated\')}}\nfunction render(){if(state.current===\'dashboard\')renderDashboard();else if(state.current===\'calculator\')renderCalculator();else if(state.current===\'network\')renderNetwork();else if(state.current===\'security\')renderSecurity();else if(state.current===\'utilities\')renderUtilities();else renderSettings();applyTheme()}\ndocument.querySelectorAll(\'.nav-item\').forEach(b=>b.onclick=()=>setNav(b.dataset.tool));$(\'#themeBtn\').onclick=()=>{const a=[\'matrix\',\'blue\',\'purple\',\'minimal\'];state.theme=a[(a.indexOf(state.theme)+1)%a.length];applyTheme();toast(\'Theme: \'+state.theme)};$(\'#mobileMenu\').onclick=()=>$(\'#sidebar\').classList.contains(\'open\')?closeDrawer():openDrawer();$(\'#drawerBackdrop\').onclick=closeDrawer;window.addEventListener(\'resize\',()=>{if(innerWidth>860)closeDrawer()});$(\'#globalSearch\').addEventListener(\'input\',e=>{const q=e.target.value.toLowerCase().trim();if(!q)return;const map={ipv4:\'network\',cidr:\'network\',subnet:\'network\',vlsm:\'network\',ipv6:\'network\',bitwise:\'network\',mac:\'network\',hash:\'security\',sha:\'security\',base64:\'security\',hex:\'security\',entropy:\'security\',uuid:\'security\',jwt:\'security\',json:\'utilities\',regex:\'utilities\',timestamp:\'utilities\',ascii:\'utilities\',url:\'utilities\'};for(const k in map)if(k.includes(q)){setNav(map[k]);break}});document.addEventListener(\'keydown\',e=>{if(e.ctrlKey&&e.key.toLowerCase()===\'b\'){e.preventDefault();const sb=$(\'#sidebar\');sb.classList.contains(\'open\')?closeDrawer():openDrawer()}});\n// Matrix background\nconst canvas=$(\'#matrix\'),ctx=canvas.getContext(\'2d\');let W,H,cols,streams;function matrixInit(){W=canvas.width=innerWidth*devicePixelRatio;H=canvas.height=innerHeight*devicePixelRatio;canvas.style.width=innerWidth+\'px\';canvas.style.height=innerHeight+\'px\';ctx.scale(devicePixelRatio,devicePixelRatio);cols=Math.floor(innerWidth/16);streams=Array.from({length:cols},()=>Math.random()*innerHeight/16)}function matrixDraw(){ctx.fillStyle=\'rgba(5,8,13,.09)\';ctx.fillRect(0,0,innerWidth,innerHeight);ctx.fillStyle=\'#00ff88\';ctx.font=\'12px monospace\';for(let i=0;i<cols;i++){const x=i*16,y=streams[i]*16;ctx.fillText(Math.random()>.5?\'1\':\'0\',x,y);streams[i]=(streams[i]+.55)% (innerHeight/16)}requestAnimationFrame(matrixDraw)}addEventListener(\'resize\',matrixInit);matrixInit();matrixDraw();render();'

@app.get("/static/style.css")
def static_css():
    return Response(STYLE_CSS, mimetype="text/css")

@app.get("/static/app.js")
def static_js():
    return Response(APP_JS, mimetype="application/javascript")

def main():
    return render_template_string(INDEX_HTML)


@app.get("/")
def index():
    return main()


@app.post("/api/execute")
def execute():
    data = request.get_json(silent=True) or {}
    tool = data.get("tool", "")
    op = data.get("op", "")

    try:
        if tool == "ipv4":
            iface = ipaddress.ip_interface(data["value"].strip())
            net = iface.network
            total = net.num_addresses
            if net.version != 4:
                raise ValueError("IPv4 only")
            if net.prefixlen <= 30:
                hosts = list(net.hosts())
                first, last, usable = str(hosts[0]), str(hosts[-1]), total - 2
            else:
                first = last = str(net.network_address)
                usable = total
            wildcard = ipaddress.IPv4Address(int(ipaddress.IPv4Address("255.255.255.255")) ^ int(net.netmask))
            return jsonify(ok=True, result={
                "IP Address": str(iface.ip), "Network": str(net.network_address),
                "Broadcast": str(net.broadcast_address), "Subnet Mask": str(net.netmask),
                "Wildcard Mask": str(wildcard), "CIDR": f"/{net.prefixlen}",
                "Total Addresses": total, "Usable Hosts": usable,
                "First Host": first, "Last Host": last,
                "Address Type": "Private" if iface.ip.is_private else "Public / Global" if iface.ip.is_global else "Special",
                "IP Version": iface.version,
            })

        if tool == "ipv6":
            iface = ipaddress.ip_interface(data["value"].strip())
            net = iface.network
            return jsonify(ok=True, result={
                "IP Address": str(iface.ip), "Network": str(net.network_address),
                "Prefix": f"/{net.prefixlen}", "First Address": str(net.network_address),
                "Last Address": str(net.broadcast_address), "Total Addresses": net.num_addresses,
                "Compressed": iface.ip.compressed, "Expanded": iface.ip.exploded,
            })

        if tool == "subnet":
            net = ipaddress.ip_network(data["network"].strip(), strict=False)
            new_prefix = int(data["prefix"])
            if net.version != 4:
                raise ValueError("IPv4 only")
            if new_prefix <= net.prefixlen or new_prefix > 32:
                raise ValueError("New prefix must be greater than the original prefix and <= 32")
            subs = list(net.subnets(new_prefix=new_prefix))
            result = []
            for s in subs:
                if s.prefixlen <= 30:
                    first, last, usable = str(s.network_address + 1), str(s.broadcast_address - 1), s.num_addresses - 2
                else:
                    first = last = str(s.network_address)
                    usable = s.num_addresses
                result.append({"network": str(s.network_address), "cidr": str(s), "mask": str(s.netmask),
                               "broadcast": str(s.broadcast_address), "first": first, "last": last,
                               "total": s.num_addresses, "usable": usable})
            return jsonify(ok=True, result=result)

        if tool == "vlsm":
            base = ipaddress.ip_network(data["network"].strip(), strict=False)
            if base.version != 4:
                raise ValueError("VLSM supports IPv4 only")
            reqs = [int(x) for x in re.split(r"[,\s]+", data["hosts"].strip()) if x]
            if not reqs or any(x < 1 for x in reqs):
                raise ValueError("Enter positive host requirements")
            return jsonify(ok=True, result=vlsm_allocate(base, reqs))

        if tool == "range":
            ip = ipaddress.ip_address(data["ip"].strip())
            net = ipaddress.ip_network(data["network"].strip(), strict=False)
            return jsonify(ok=True, result={"inside": ip in net, "ip": str(ip), "network": str(net)})

        if tool == "wildcard":
            prefix = int(str(data["prefix"]).replace("/", ""))
            net = ipaddress.ip_network(f"0.0.0.0/{prefix}")
            wildcard = ipaddress.IPv4Address(int(ipaddress.IPv4Address("255.255.255.255")) ^ int(net.netmask))
            return jsonify(ok=True, result={"cidr": f"/{prefix}", "mask": str(net.netmask), "wildcard": str(wildcard)})

        if tool == "bitwise":
            a, b = int(data["a"]), int(data["b"])
            if a < 0 or b < 0:
                raise ValueError("Use non-negative integers")
            bits = max(a.bit_length(), b.bit_length(), 1)
            return jsonify(ok=True, result={
                "A": a, "B": b, "A Binary": format(a, f"0{bits}b"), "B Binary": format(b, f"0{bits}b"),
                "AND": a & b, "OR": a | b, "XOR": a ^ b, "NOT A": ~a, "NOT B": ~b,
                "A << 1": a << 1, "A >> 1": a >> 1, "B << 1": b << 1, "B >> 1": b >> 1,
            })

        if tool == "mac":
            raw = re.sub(r"[^0-9A-Fa-f]", "", data["value"])
            if len(raw) != 12:
                raise ValueError("Enter 12 hexadecimal digits")
            upper = raw.upper()
            return jsonify(ok=True, result={
                "Colon": ":".join(upper[i:i+2] for i in range(0, 12, 2)),
                "Hyphen": "-".join(upper[i:i+2] for i in range(0, 12, 2)),
                "Cisco": ".".join(upper[i:i+4] for i in range(0, 12, 4)),
                "Raw": upper,
                "Unicast": not bool(int(upper[0], 16) & 1),
                "Locally Administered": bool(int(upper[0], 16) & 2),
            })

        if tool == "convert_number":
            base = data["base"]
            value = data["value"].strip().lower().replace("0x", "")
            if base == "decimal": num = int(value, 10)
            elif base == "binary": num = int(value, 2)
            elif base == "hex": num = int(value, 16)
            else: raise ValueError("Unknown base")
            if num < 0: raise ValueError("Positive values only")
            return jsonify(ok=True, result={"Decimal": str(num), "Binary": bin(num)[2:], "Hex": "0x" + hex(num)[2:].upper()})

        if tool == "hash":
            algo = data.get("algorithm", "sha256").lower().replace("-", "")
            if algo not in {"md5", "sha1", "sha256", "sha512", "sha3_256", "sha3_512"}:
                raise ValueError("Unsupported algorithm")
            value = data.get("value", "").encode("utf-8")
            return jsonify(ok=True, result={"algorithm": algo, "bytes": len(value), "hash": hashlib.new(algo, value).hexdigest()})

        if tool == "encoding":
            mode = data.get("mode", "base64").lower()
            action = data.get("action", "encode").lower()
            value = data.get("value", "")
            if action == "encode":
                if mode == "base64": out = base64.b64encode(value.encode()).decode()
                elif mode == "hex": out = value.encode().hex().upper()
                elif mode == "url": out = quote(value, safe="")
                else: raise ValueError("Unsupported mode")
            else:
                if mode == "base64": out = base64.b64decode(value, validate=True).decode()
                elif mode == "hex": out = bytes.fromhex(value).decode()
                elif mode == "url": out = unquote(value)
                else: raise ValueError("Unsupported mode")
            return jsonify(ok=True, result=out)

        if tool == "entropy":
            value = data.get("value", "")
            pool = 0
            categories = {
                "lower": bool(re.search(r"[a-z]", value)), "upper": bool(re.search(r"[A-Z]", value)),
                "digits": bool(re.search(r"\d", value)), "symbols": bool(re.search(r"[^A-Za-z0-9]", value)),
            }
            pool = 26 * categories["lower"] + 26 * categories["upper"] + 10 * categories["digits"] + 33 * categories["symbols"]
            bits = len(value) * math.log2(pool) if value and pool else 0
            return jsonify(ok=True, result={"length": len(value), "pool": pool, "entropy_bits": round(bits, 2), "categories": categories})

        if tool == "uuid":
            count = min(max(int(data.get("count", 1)), 1), 50)
            return jsonify(ok=True, result=[str(uuid.uuid4()) for _ in range(count)])

        if tool == "checksum":
            value = data.get("value", "").encode()
            return jsonify(ok=True, result={"MD5": hashlib.md5(value).hexdigest(), "SHA1": hashlib.sha1(value).hexdigest(),
                                             "SHA256": hashlib.sha256(value).hexdigest(), "SHA512": hashlib.sha512(value).hexdigest()})

        if tool == "timestamp":
            mode = data.get("mode", "now")
            if mode == "now":
                dt = datetime.now(timezone.utc)
                ts = int(dt.timestamp())
            elif mode == "from_timestamp":
                ts = int(data["value"]); dt = datetime.fromtimestamp(ts, tz=timezone.utc)
            elif mode == "from_iso":
                raw = data["value"].strip().replace("Z", "+00:00")
                dt = datetime.fromisoformat(raw)
                if dt.tzinfo is None: dt = dt.replace(tzinfo=timezone.utc)
                ts = int(dt.timestamp())
            else: raise ValueError("Unknown timestamp mode")
            return jsonify(ok=True, result={"Unix": ts, "UTC": dt.astimezone(timezone.utc).isoformat()})

        if tool == "ascii":
            if op == "code_to_char":
                n = int(data["value"]); return jsonify(ok=True, result={"character": chr(n), "code": n})
            text = data.get("value", "")
            return jsonify(ok=True, result={"codes": [ord(c) for c in text]})

        if tool == "regex":
            pattern = data.get("pattern", "")
            text = data.get("value", "")
            matches = [m.group(0) for m in re.finditer(pattern, text)]
            return jsonify(ok=True, result={"count": len(matches), "matches": matches})

        if tool == "json":
            obj = json.loads(data.get("value", ""))
            pretty = json.dumps(obj, indent=2, ensure_ascii=False)
            compact = json.dumps(obj, separators=(",", ":"), ensure_ascii=False)
            return jsonify(ok=True, result={"pretty": pretty, "compact": compact})

        if tool == "url":
            parsed = urlparse(data.get("value", ""))
            return jsonify(ok=True, result={
                "scheme": parsed.scheme, "netloc": parsed.netloc, "hostname": parsed.hostname,
                "port": parsed.port, "path": parsed.path, "query": parsed.query, "fragment": parsed.fragment,
                "params": {k: v for k, v in parse_qs(parsed.query).items()},
            })

        if tool == "unit":
            kind = data["kind"]; value = float(data["value"]); from_u = data["from"]; to_u = data["to"]
            factors = {
                "length": {"m": 1, "km": 1000, "cm": 0.01, "mm": 0.001, "ft": 0.3048, "in": 0.0254},
                "data": {"bit": 1, "byte": 8, "kb": 8_000, "kib": 8_192, "mb": 8_000_000, "mib": 8_388_608},
                "time": {"s": 1, "ms": 0.001, "min": 60, "h": 3600, "day": 86400},
            }
            if kind not in factors or from_u not in factors[kind] or to_u not in factors[kind]:
                raise ValueError("Unsupported unit")
            result = value * factors[kind][from_u] / factors[kind][to_u]
            return jsonify(ok=True, result=result)

        if tool == "port_search":
            q = str(data.get("query", "")).lower()
            items = [{"port": p, "proto": proto, "service": svc} for p, proto, svc in PORTS if q in str(p) or q in svc.lower() or q in proto.lower()]
            return jsonify(ok=True, result=items)

        if tool == "http_search":
            q = str(data.get("query", "")).lower()
            items = [{"code": c, "reason": reason} for c, reason in HTTP_CODES if q in str(c) or q in reason.lower()]
            return jsonify(ok=True, result=items)

        if tool == "jwt":
            token = data.get("value", "").strip()
            parts = token.split(".")
            if len(parts) != 3: raise ValueError("JWT must contain three segments")
            def b64json(seg):
                pad = "=" * (-len(seg) % 4)
                return json.loads(base64.urlsafe_b64decode(seg + pad).decode())
            return jsonify(ok=True, result={"header": b64json(parts[0]), "payload": b64json(parts[1]), "signature": parts[2]})

        return error("Unknown tool")
    except Exception as exc:
        return error(str(exc))


@app.post("/api/file-hash")
def file_hash():
    file = request.files.get("file")
    algo = request.form.get("algorithm", "sha256").lower().replace("-", "")
    if not file or not file.filename:
        return error("No file uploaded")
    if algo not in {"md5", "sha1", "sha256", "sha512"}:
        return error("Unsupported algorithm")
    hasher = hashlib.new(algo)
    size = 0
    while True:
        chunk = file.stream.read(1024 * 1024)
        if not chunk:
            break
        size += len(chunk)
        hasher.update(chunk)
    return jsonify(ok=True, result={"filename": file.filename, "bytes": size, "algorithm": algo, "hash": hasher.hexdigest()})


HOST = "0.0.0.0"
PORT = 5000
LOCAL_URL = f"http://127.0.0.1:{PORT}/"


def get_lan_ip() -> str:
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        sock.connect(("8.8.8.8", 80))
        ip = sock.getsockname()[0]
        if ip and not ip.startswith("127."):
            return ip
    except OSError:
        pass
    finally:
        sock.close()
    try:
        ip = socket.gethostbyname(socket.gethostname())
        if ip and not ip.startswith("127."):
            return ip
    except OSError:
        pass
    return "127.0.0.1"


def open_browser_when_ready() -> None:
    deadline = time.time() + 15
    while time.time() < deadline:
        try:
            with socket.create_connection(("127.0.0.1", PORT), timeout=0.4):
                break
        except OSError:
            time.sleep(0.2)
    try:
        webbrowser.open_new(LOCAL_URL)
    except Exception:
        pass


if __name__ == "__main__":
    lan_ip = get_lan_ip()
    print("=" * 60)
    print("              CYBER CALCULATOR WEB")
    print("=" * 60)
    print(f"PC browser : {LOCAL_URL}")
    print(f"PHONE URL  : http://{lan_ip}:{PORT}/")
    print("SERVER     : 0.0.0.0:5000")
    print("=" * 60)
    print("Keep this window open while using the app on your phone.")
    print()
    threading.Thread(target=open_browser_when_ready, daemon=True, name="auto-browser").start()
    app.run(host=HOST, port=PORT, debug=False, use_reloader=False, threaded=True)
