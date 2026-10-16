"""
Interface Web pour dns_crawl (FastAPI)
Optionnel - lance avec: python -m dns_crawl.web.app
Ou: uvicorn dns_crawl.web.app:app --host 0.0.0.0 --port 8000
"""
from __future__ import annotations

import asyncio
from pathlib import Path
from typing import Optional

try:
    from fastapi import FastAPI, Query, BackgroundTasks
    from fastapi.responses import HTMLResponse, JSONResponse
    from fastapi.staticfiles import StaticFiles
    FASTAPI_AVAILABLE = True
except ImportError:
    FASTAPI_AVAILABLE = False
    FastAPI = None  # type: ignore

if FASTAPI_AVAILABLE:
    from dns_crawl.crawler import DnsCrawler, CrawlConfig
    from dns_crawl.utils import detect_target_type, normalize_target

    app = FastAPI(
        title="DNS Crawl",
        description="Crawler DNS - Trouve tous les sites webs référencés sur un DNS / domaine / NS / IP",
        version="1.0.0",
    )

    # Stockage simple en mémoire des résultats
    jobs: dict[str, dict] = {}

    HTML_PAGE = Path(__file__).parent / "templates" / "index.html"
    # Fallback inline si pas de template
    INLINE_HTML = r"""
<!DOCTYPE html>
<html lang="fr">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>DNS Crawl - Trouve tous les sites sur un DNS</title>
<style>
 *{box-sizing:border-box} body{font-family:system-ui,-apple-system,Segoe UI,sans-serif;background:#0f172a;color:#e2e8f0;margin:0;padding:0}
 .container{max-width:900px;margin:0 auto;padding:32px 20px}
 h1{font-size:28px;text-align:center;margin:0}
 .sub{text-align:center;color:#94a3b8;margin:8px 0 24px}
 .card{background:#1e293b;border-radius:12px;padding:20px;box-shadow:0 4px 12px rgba(0,0,0,.3)}
 input[type=text]{width:100%;padding:14px 16px;border-radius:8px;border:1px solid #334155;background:#0f172a;color:#fff;font-size:16px;outline:none}
 input[type=text]:focus{border-color:#38bdf8}
 .row{display:flex;gap:12px;margin-top:16px;flex-wrap:wrap}
 .row label{flex:1;min-width:140px;display:flex;align-items:center;gap:6px;font-size:14px;color:#cbd5e1}
 .row label input{width:auto}
 button{margin-top:16px;width:100%;padding:14px;background:#38bdf8;color:#0f172a;font-weight:700;border:none;border-radius:8px;font-size:16px;cursor:pointer}
 button:hover{background:#0ea5e9}
 button:disabled{opacity:.6;cursor:not-allowed}
 #results{margin-top:24px}
 .badge{display:inline-block;padding:2px 8px;border-radius:999px;background:#334155;color:#94a3b8;font-size:12px;margin-right:6px}
 .domain-list{margin-top:12px;display:grid;gap:6px}
 .domain-item{background:#0f172a;border:1px solid #334155;border-radius:8px;padding:10px 12px;display:flex;justify-content:space-between;align-items:center;flex-wrap:wrap;gap:8px}
 .domain-item a{color:#38bdf8;text-decoration:none}
 .domain-item a:hover{text-decoration:underline}
 .stats{display:flex;gap:16px;flex-wrap:wrap;margin:12px 0}
 .stat{background:#0f172a;border:1px solid #334155;border-radius:8px;padding:12px 16px;flex:1;min-width:120px;text-align:center}
 .stat b{font-size:20px;color:#38bdf8}
 .help{margin-top:24px;background:#1e293b;border-radius:12px;padding:16px;color:#94a3b8;font-size:13px;line-height:1.5}
 .help code{background:#0f172a;padding:2px 6px;border-radius:4px;color:#e2e8f0}
 .spinner{border:3px solid #334155;border-top-color:#38bdf8;border-radius:50%;width:24px;height:24px;animation:spin 1s linear infinite;display:inline-block;vertical-align:middle}
 @keyframes spin{to{transform:rotate(360deg)}}
</style>
</head>
<body>
<div class="container">
  <h1>🔍 DNS Crawl</h1>
  <p class="sub">Trouve tous les sites webs référencés sur un DNS — domaine, NS, IP ou plage CIDR</p>

  <div class="card">
    <input id="target" type="text" placeholder="ex: example.com  |  ns1.ovh.net  |  8.8.8.8  |  1.1.1.0/24" autocomplete="off" />

    <div class="row">
      <label><input type="checkbox" id="ct" checked> CT logs (crt.sh)</label>
      <label><input type="checkbox" id="bf" checked> Bruteforce</label>
      <label><input type="checkbox" id="axfr" checked> AXFR</label>
      <label><input type="checkbox" id="reverse"> Reverse IP/NS</label>
      <label><input type="checkbox" id="webcheck"> Vérif. HTTP</label>
    </div>
    <div class="row">
      <label>Wordlist:
        <select id="wl" style="background:#0f172a;color:#e2e8f0;border:1px solid #334155;border-radius:6px;padding:6px;">
          <option value="">défaut (~200)</option>
          <option value="top100">top100</option>
          <option value="common">common</option>
          <option value="large">large (~500+)</option>
        </select>
      </label>
    </div>

    <button id="go" onclick="crawl()">🚀 Crawler</button>
  </div>

  <div id="results"></div>

  <div class="help">
    <b>💡 Comment ça marche ?</b><br>
    • <b>Domaine</b> (<code>example.com</code>): DNS records + CT logs + bruteforce + AXFR → tous ses sous-domaines / sites<br>
    • <b>NS</b> (<code>ns1.ovh.net</code>): avec <code>Reverse IP/NS</code> → tous les domaines hébergés sur ce serveur DNS<br>
    • <b>IP</b> (<code>8.8.8.8</code>): reverse PTR + reverse IP → tous les sites sur cette IP<br>
    • <b>CIDR</b> (<code>1.1.1.0/24</code>): PTR sur la plage → tous les PTR de la plage<br>
    <br>
    <b>CLI équivalent:</b> <code>dns-crawl example.com -o resultats.json</code> &nbsp;|&nbsp; <code>dns-crawl ns1.ovh.net --reverse</code>
  </div>
</div>

<script>
async function crawl(){
  const target = document.getElementById('target').value.trim();
  if(!target){ alert('Entre une cible : domaine, NS, IP ou CIDR'); return; }
  const btn = document.getElementById('go');
  const resEl = document.getElementById('results');
  btn.disabled = true;
  btn.innerHTML = '<span class="spinner"></span> Crawl en cours...';
  resEl.innerHTML = '<p style="text-align:center;color:#94a3b8;margin-top:16px;"><span class="spinner"></span> Recherche en cours (10-30s)...</p>';

  const params = new URLSearchParams({
    target,
    ct: document.getElementById('ct').checked,
    bf: document.getElementById('bf').checked,
    axfr: document.getElementById('axfr').checked,
    reverse: document.getElementById('reverse').checked,
    webcheck: document.getElementById('webcheck').checked,
    wordlist: document.getElementById('wl').value,
  });

  try{
    const r = await fetch('/api/crawl?' + params.toString());
    const data = await r.json();
    if(data.error){ resEl.innerHTML = '<p style="color:#f87171">'+data.error+'</p>'; btn.disabled=false; btn.innerHTML='🚀 Crawler'; return; }
    render(data);
  }catch(e){
    resEl.innerHTML = '<p style="color:#f87171">Erreur réseau: '+e+'</p>';
  }
  btn.disabled=false;
  btn.innerHTML='🚀 Crawler';
}

function render(data){
  const el = document.getElementById('results');
  const count = data.all_domains ? data.all_domains.length : 0;
  let html = '';

  html += '<div class="stats">';
  html += `<div class="stat"><b>${count}</b><br><span style="color:#94a3b8;font-size:13px">domaines</span></div>`;
  html += `<div class="stat"><b>${data.duration ? data.duration.toFixed(1)+'s' : '-'}</b><br><span style="color:#94a3b8;font-size:13px">durée</span></div>`;
  html += `<div class="stat"><b>${data.target_type || ''}</b><br><span style="color:#94a3b8;font-size:13px">type cible</span></div>`;
  html += '</div>';

  if(data.sources_used) html += '<p>'+ data.sources_used.map(s=>'<span class="badge">'+s+'</span>').join('') +'</p>';

  if(data.dns_records && Object.keys(data.dns_records).length){
    html += '<div class="card" style="margin-top:12px"><b>DNS Records</b><br>';
    for(const [k,v] of Object.entries(data.dns_records)){
      html += `<div><span class="badge">${k}</span> ${Array.isArray(v)? v.slice(0,3).join(', '): v}</div>`;
    }
    html += '</div>';
  }

  html += '<div class="card" style="margin-top:12px"><b>🌐 Tous les sites / domaines trouvés ('+count+')</b>';
  html += ' <button onclick="copyAll()" style="width:auto;padding:6px 12px;font-size:13px;margin-left:8px">📋 Copier</button> ';
  html += ' <button onclick="downloadTxt()" style="width:auto;padding:6px 12px;font-size:13px;">⬇️ TXT</button> ';
  html += ' <button onclick="downloadJson()" style="width:auto;padding:6px 12px;font-size:13px;">⬇️ JSON</button>';
  html += '<div class="domain-list" id="dlist">';
  if(data.all_domains && data.all_domains.length){
    for(const d of data.all_domains){
      html += `<div class="domain-item"><span>🌐 <a href="https://${d}" target="_blank">${d}</a></span> <span><a href="https://${d}" target="_blank" style="color:#94a3b8;font-size:13px">https://${d}</a></span></div>`;
    }
  } else {
    html += '<p style="color:#f87171">Aucun domaine trouvé. Essaie avec <code>Reverse IP/NS</code> ou une autre wordlist.</p>';
  }
  html += '</div></div>';

  if(data.errors && data.errors.length) html += '<div class="card" style="margin-top:12px;border-color:#f87171"><b style="color:#f87171">Erreurs</b><br>'+ data.errors.join('<br>') +'</div>';
  if(data.warnings && data.warnings.length) html += '<div class="card" style="margin-top:12px;border-color:#fbbf24"><b style="color:#fbbf24">Warnings</b><br>'+ data.warnings.join('<br>') +'</div>';

  // Raw JSON toggle
  html += '<details style="margin-top:12px"><summary style="cursor:pointer;color:#94a3b8">Voir JSON brut</summary><pre style="background:#0f172a;border:1px solid #334155;border-radius:8px;padding:12px;overflow:auto;max-height:400px;font-size:12px">'+ JSON.stringify(data, null, 2) +'</pre></details>';

  el.innerHTML = html;
  window._lastData = data;
}

function copyAll(){
  if(!window._lastData) return;
  const txt = window._lastData.all_domains.join("\\n");
  navigator.clipboard.writeText(txt).then(()=> alert('Copié ! ('+window._lastData.all_domains.length+' domaines)'));
}
function downloadTxt(){
  if(!window._lastData) return;
  const blob = new Blob([window._lastData.all_domains.join("\\n")], {type:'text/plain'});
  const a = document.createElement('a'); a.href=URL.createObjectURL(blob); a.download = (window._lastData.normalized || 'domains') + '.txt'; a.click();
}
function downloadJson(){
  if(!window._lastData) return;
  const blob = new Blob([JSON.stringify(window._lastData, null, 2)], {type:'application/json'});
  const a = document.createElement('a'); a.href=URL.createObjectURL(blob); a.download = (window._lastData.normalized || 'result') + '.json'; a.click();
}

// Enter key
document.getElementById('target').addEventListener('keydown', e=>{
  if(e.key==='Enter') crawl();
});
</script>
</body>
</html>
    """

    @app.get("/", response_class=HTMLResponse)
    async def index():
        if HTML_PAGE.exists():
            return HTMLResponse(HTML_PAGE.read_text(encoding="utf-8"))
        return HTMLResponse(INLINE_HTML)

    @app.get("/api/crawl")
    async def api_crawl(
        target: str = Query(..., description="Domaine, NS, IP ou CIDR"),
        ct: bool = Query(True),
        bf: bool = Query(True),
        axfr: bool = Query(True),
        reverse: bool = Query(False),
        webcheck: bool = Query(False),
        wordlist: Optional[str] = Query(None),
        workers: int = Query(30),
        timeout: float = Query(3.0),
    ):
        if not target.strip():
            return JSONResponse({"error": "Cible vide"}, status_code=400)

        # Détection type pour info
        norm = normalize_target(target)
        ttype = detect_target_type(norm)

        config = CrawlConfig(
            do_resolve_all=True,
            do_zone_transfer=axfr,
            do_ct_logs=ct,
            do_bruteforce=bf,
            do_reverse_ip=reverse,
            do_web_check=webcheck,
            wordlist=wordlist or None,
            bruteforce_workers=workers,
            dns_timeout=timeout,
        )
        crawler = DnsCrawler(config=config)

        # Exécuter en thread pour ne pas bloquer l'event loop
        loop = asyncio.get_event_loop()
        result = await loop.run_in_executor(None, lambda: crawler.crawl(target))

        return result.to_dict()

    @app.get("/api/health")
    async def health():
        return {"status": "ok", "version": "1.0.0"}

else:
    app = None  # type: ignore
    def _missing():
        raise ImportError("FastAPI non installé. Installe avec: pip install fastapi uvicorn")

    # Pour éviter erreurs import
