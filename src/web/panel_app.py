"""
CENTINELA Web Panel
-------------------
Simple (but functional) dashboard for:
  - reading logs (tail) securely
  - browsing incidents and updating status
  - editing persisted config overrides (applies on restart)

Security model:
  - All sensitive endpoints require `CENTINELA_PANEL_TOKEN`
  - Client sends it as `Authorization: Bearer <token>`
"""

from __future__ import annotations

import asyncio
import hmac
import logging
import os
import re
from dataclasses import asdict
from pathlib import Path
from typing import Any, Dict, List, Optional

import docker
import docker.errors
import yaml
from fastapi import Body, Depends, FastAPI, Request
from fastapi.responses import HTMLResponse, JSONResponse
import uvicorn

from config.loader import load_config
from database.repository import IncidentRepository

logger = logging.getLogger("centinela.web.panel")

_DEFAULT_OVERRIDES_PATH = "/app/data/config_overrides.yml"
_DEFAULT_LOG_FILES = ("centinela.log", "centinela-alerts.log")
_ANSI_RE = re.compile(r"\x1B\[[0-?]*[ -/]*[@-~]")


def _get_env_token() -> str:
    return os.environ.get("CENTINELA_PANEL_TOKEN", "").strip()


def _is_authorized(token_from_header: Optional[str]) -> bool:
    expected = _get_env_token()
    if not expected:
        return False
    if not token_from_header:
        return False
    return hmac.compare_digest(expected, token_from_header)


async def _require_auth(request: Request) -> None:
    # Accept either:
    #   Authorization: Bearer <token>
    #   X-Panel-Token: <token>
    authz = request.headers.get("Authorization", "")
    token = None
    if authz.lower().startswith("bearer "):
        token = authz.split(" ", 1)[1].strip()
    if not token:
        token = request.headers.get("X-Panel-Token")
    if not _is_authorized(token):
        from fastapi import HTTPException

        raise HTTPException(status_code=401, detail="No autorizado")


def _read_last_lines(path: Path, max_lines: int) -> List[str]:
    """
    Efficient tail for potentially large logs.
    Reads from the end backwards in chunks until we collect max_lines.
    """
    if not path.exists() or not path.is_file():
        return []

    max_lines = max(1, min(int(max_lines), 5000))
    chunk_size = 8192

    with open(path, "rb") as f:
        f.seek(0, os.SEEK_END)
        end = f.tell()
        if end <= 0:
            return []

        pos = end
        data = b""
        lines: List[bytes] = []

        while pos > 0 and len(lines) < max_lines:
            read_size = min(chunk_size, pos)
            pos -= read_size
            f.seek(pos)
            data = f.read(read_size) + data
            lines = data.splitlines()
            # If we already have enough, we can stop.
            if len(lines) >= max_lines:
                break

    tail_lines = lines[-max_lines:]
    # Decode defensively
    out: List[str] = []
    for b in tail_lines:
        out.append(b.decode("utf-8", errors="replace"))
    return out


def _atomic_write_text(path: Path, content: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_suffix(path.suffix + ".tmp")
    with open(tmp, "w", encoding="utf-8") as f:
        f.write(content)
    os.replace(tmp, path)


def _strip_ansi(s: str) -> str:
    return _ANSI_RE.sub("", s)


def _render_index_html() -> str:
    return """
<!doctype html>
<html>
  <head>
    <meta charset="utf-8"/>
    <meta name="viewport" content="width=device-width, initial-scale=1"/>
    <title>Centinela Panel</title>
    <style>
      :root {
        --bg: #090b10;
        --panel: #101521;
        --panel-2: #0d1320;
        --line: #1f2b40;
        --text: #e7ebf5;
        --muted: #9fb0cd;
        --ok: #4ade80;
        --warn: #f59e0b;
        --danger: #ef4444;
        --info: #38bdf8;
        --accent: #7c3aed;
      }
      * { box-sizing: border-box; }
      body {
        margin: 0;
        font-family: Inter, Segoe UI, Roboto, Arial, sans-serif;
        background: radial-gradient(circle at top right, #10182b 0%, var(--bg) 55%);
        color: var(--text);
      }
      .container { max-width: 1400px; margin: 0 auto; padding: 16px; }
      .top {
        display: flex; align-items: center; justify-content: space-between; gap: 12px;
        margin-bottom: 14px;
      }
      .title { font-size: 22px; font-weight: 700; letter-spacing: .3px; }
      .subtitle { color: var(--muted); font-size: 13px; }
      .card {
        background: linear-gradient(180deg, var(--panel) 0%, var(--panel-2) 100%);
        border: 1px solid var(--line);
        border-radius: 14px;
        padding: 14px;
        box-shadow: 0 8px 30px rgba(0,0,0,.25);
      }
      .grid4 {
        display: grid;
        grid-template-columns: repeat(4, minmax(200px, 1fr));
        gap: 12px;
      }
      .stat .label { color: var(--muted); font-size: 12px; margin-bottom: 6px; }
      .stat .value { font-size: 24px; font-weight: 700; }
      .row { display: flex; flex-wrap: wrap; gap: 10px; align-items: center; }
      .tabs { display:flex; gap: 8px; margin: 12px 0; }
      .tab {
        padding: 8px 12px; border-radius: 10px; border:1px solid var(--line);
        background:#0e1422; color:var(--text); cursor:pointer; user-select:none;
      }
      .tab.active { background: #1b2540; border-color:#2c3d66; }
      .muted { color: var(--muted); font-size: 12px; }
      .ok { color: var(--ok); }
      .danger { color: var(--danger); }
      input, select, textarea, button {
        background:#0c1220; border:1px solid var(--line); color:var(--text);
        border-radius: 10px; padding: 8px 10px;
      }
      button { cursor:pointer; }
      button.primary { background: #1f2f54; border-color:#304572; }
      .split {
        display:grid;
        grid-template-columns: 1.2fr 1fr;
        gap: 12px;
      }
      pre {
        margin:0; white-space: pre-wrap; word-break: break-word;
        background:#0a101c; border:1px solid var(--line); border-radius: 10px;
        padding: 10px; max-height: 520px; overflow: auto; font-family: ui-monospace, SFMono-Regular, Menlo, Consolas, monospace;
      }
      .logbox { height: 520px; overflow: auto; }
      table { width:100%; border-collapse: collapse; }
      th, td { border-bottom:1px solid var(--line); padding: 8px; text-align:left; vertical-align: top; }
      th { color: var(--muted); font-weight:600; font-size: 12px; }
      .pill {
        display:inline-block; padding:2px 8px; border:1px solid var(--line); border-radius:999px; font-size:11px;
      }
      .small { font-size: 11px; color: var(--muted); }
      @media (max-width: 1024px) {
        .grid4 { grid-template-columns: repeat(2, minmax(160px, 1fr)); }
        .split { grid-template-columns: 1fr; }
      }
    </style>
  </head>
  <body>
    <div class="container">
      <div class="top">
        <div>
          <div class="title">Centinela Panel</div>
          <div class="subtitle">Dashboard operativo, logs en vivo, incidencias y configuración segura</div>
        </div>
        <button id="btnLogout" style="display:none;">Cerrar sesión</button>
      </div>

      <div id="loginCard" class="card">
        <div style="font-size:16px;font-weight:700;margin-bottom:8px;">Acceso protegido</div>
        <div class="muted">Introduce el token configurado en `CENTINELA_PANEL_TOKEN`.</div>
        <div class="row" style="margin-top:10px;">
          <input id="tokenInput" placeholder="Token del panel" style="min-width:320px;flex:1;" />
          <button id="btnLogin" class="primary">Entrar</button>
        </div>
        <div id="loginError" class="danger" style="margin-top:10px;"></div>
      </div>

      <div id="appCard" style="display:none;">
        <div class="tabs">
          <div class="tab active" id="tabDashboard" onclick="setTab('dashboard')">Dashboard</div>
          <div class="tab" id="tabLogs" onclick="setTab('logs')">Logs</div>
          <div class="tab" id="tabIncidents" onclick="setTab('incidents')">Incidencias</div>
          <div class="tab" id="tabConfig" onclick="setTab('config')">Configuración</div>
        </div>

        <div id="viewDashboard">
          <div class="grid4">
            <div class="card stat"><div class="label">Incidencias (24h)</div><div class="value" id="kpiInc24">-</div></div>
            <div class="card stat"><div class="label">CPU total host</div><div class="value" id="kpiCpu">-</div></div>
            <div class="card stat"><div class="label">RAM host</div><div class="value" id="kpiRam">-</div></div>
            <div class="card stat"><div class="label">Contenedores activos</div><div class="value" id="kpiContainers">-</div></div>
          </div>
          <div class="split" style="margin-top:12px;">
            <div class="card">
              <div class="row" style="justify-content:space-between;">
                <div style="font-weight:700;">Uso de red y tráfico (24h)</div>
                <button onclick="refreshDashboard()">Actualizar</button>
              </div>
              <div class="small" style="margin:8px 0 10px;">Datos agregados desde `network_samples` + Docker stats en tiempo real.</div>
              <div class="grid4">
                <div class="stat"><div class="label">RX (24h)</div><div class="value" id="netRx">-</div></div>
                <div class="stat"><div class="label">TX (24h)</div><div class="value" id="netTx">-</div></div>
                <div class="stat"><div class="label">Packets RX</div><div class="value" id="pktRx">-</div></div>
                <div class="stat"><div class="label">Packets TX</div><div class="value" id="pktTx">-</div></div>
              </div>
              <div style="margin-top:10px;">
                <div class="muted" style="margin-bottom:6px;">Top contenedores por tráfico</div>
                <pre id="topTraffic"></pre>
              </div>
            </div>
            <div class="card">
              <div style="font-weight:700;">Salud y severidad</div>
              <div class="small" style="margin:8px 0 10px;">Distribución rápida de severidades y estado operativo.</div>
              <pre id="severityBreakdown"></pre>
              <div class="small" style="margin-top:10px;">Refresco automático cada 10s.</div>
            </div>
          </div>
        </div>

        <div id="viewLogs" style="display:none;">
          <div class="card">
            <div class="row">
              <label class="muted">Archivo</label>
              <select id="logFile">
                <option value="centinela.log">centinela.log</option>
                <option value="centinela-alerts.log">centinela-alerts.log</option>
              </select>
              <label class="muted">Tail</label>
              <input id="tailLines" type="number" min="10" max="5000" value="300" style="width:100px;" />
              <label class="muted">Nivel</label>
              <select id="logLevel">
                <option value="">Todos</option>
                <option value="DEBUG">DEBUG</option>
                <option value="INFO">INFO</option>
                <option value="WARNING">WARNING</option>
                <option value="ALERT">ALERT</option>
                <option value="CRITICAL">CRITICAL</option>
                <option value="ERROR">ERROR</option>
              </select>
              <label class="muted">Autorefresh</label>
              <select id="logRefreshEvery">
                <option value="1000">1s</option>
                <option value="2000">2s</option>
                <option value="5000" selected>5s</option>
                <option value="10000">10s</option>
              </select>
              <button onclick="refreshLogs()" class="primary">Actualizar</button>
            </div>
            <div class="small" style="margin:8px 0;">
              Autoscroll inteligente: si estás al final, sigue en vivo; si subes manualmente, respeta tu posición.
            </div>
            <pre id="logOut" class="logbox"></pre>
          </div>
        </div>

        <div id="viewIncidents" style="display:none;">
          <div class="card">
            <div class="row">
              <label class="muted">Estado</label>
              <select id="filterStatus">
                <option value="">Todos</option><option value="new">new</option><option value="reviewed">reviewed</option><option value="closed">closed</option>
              </select>
              <label class="muted">Severidad</label>
              <select id="filterSeverity">
                <option value="">Todas</option><option value="low">low</option><option value="medium">medium</option><option value="high">high</option><option value="critical">critical</option>
              </select>
              <button onclick="refreshIncidents()" class="primary">Buscar</button>
              <button onclick="purgeIncidentsHistory()" style="margin-left:auto;border-color:#5b1f2f;color:#ffb4c4;">Borrar histórico</button>
            </div>
            <div id="incidentsMeta" class="muted" style="margin-top:8px;"></div>
            <table style="margin-top:8px;">
              <thead><tr><th>ID</th><th>Fecha</th><th>Proyecto</th><th>Container</th><th>Tipo</th><th>Severidad</th><th>Estado</th><th>Acción</th></tr></thead>
              <tbody id="incidentsBody"></tbody>
            </table>
            <div class="row" style="margin-top:10px;">
              <button onclick="prevPage()">Anterior</button>
              <div id="pageInfo" class="muted"></div>
              <button onclick="nextPage()">Siguiente</button>
            </div>
          </div>
        </div>

        <div id="viewConfig" style="display:none;">
          <div class="card">
            <div class="muted">Los cambios se guardan en overrides persistentes y se aplican al reiniciar.</div>
            <div class="row" style="margin:10px 0;">
              <button onclick="refreshConfig()">Refrescar</button>
              <div id="configSaveMsg" class="muted"></div>
            </div>
            <div style="font-weight:700;margin-bottom:6px;">Overrides editables (YAML)</div>
            <textarea id="overridesYaml" style="width:100%;min-height:220px;"></textarea>
            <div class="row" style="justify-content:flex-end;margin-top:8px;">
              <button onclick="saveOverrides()" class="primary">Guardar overrides</button>
            </div>
          </div>
          <div class="card" style="margin-top:12px;">
            <div style="font-weight:700;margin-bottom:6px;">Config efectiva (solo lectura)</div>
            <pre id="effectiveYaml"></pre>
          </div>
        </div>
      </div>
    </div>
    <script>
      let panelToken = localStorage.getItem('panel_token') || '';
      let page = 1;
      const pageSize = 25;
      let lastFilters = {status:'', severity:''};
      let logTimer = null;
      let metricsTimer = null;

      const $ = (id) => document.getElementById(id);

      async function api(path, method='GET', body=null) {
        const headers = {};
        if (panelToken) headers['Authorization'] = 'Bearer ' + panelToken;
        if (method !== 'GET' && body !== null) headers['Content-Type'] = 'application/json';
        const resp = await fetch(path, {method, headers, body: body ? JSON.stringify(body) : undefined});
        if (!resp.ok) throw new Error('HTTP ' + resp.status + ': ' + (await resp.text()).slice(0, 240));
        return await resp.json();
      }

      function setTab(name) {
        ['Dashboard','Logs','Incidents','Config'].forEach(t => $('tab'+t).classList.remove('active'));
        $('tab'+name.charAt(0).toUpperCase()+name.slice(1)).classList.add('active');
        $('viewDashboard').style.display = name === 'dashboard' ? 'block':'none';
        $('viewLogs').style.display = name === 'logs' ? 'block':'none';
        $('viewIncidents').style.display = name === 'incidents' ? 'block':'none';
        $('viewConfig').style.display = name === 'config' ? 'block':'none';
      }

      function showLogin(msg='') {
        $('loginCard').style.display = 'block';
        $('appCard').style.display = 'none';
        $('btnLogout').style.display = 'none';
        $('loginError').innerText = msg;
      }
      function showApp() {
        $('loginCard').style.display = 'none';
        $('appCard').style.display = 'block';
        $('btnLogout').style.display = 'inline-block';
      }

      function formatBytes(n) {
        const v = Number(n || 0);
        if (v < 1024) return v + ' B';
        const units = ['KB','MB','GB','TB'];
        let x = v / 1024, i = 0;
        while (x >= 1024 && i < units.length-1) { x /= 1024; i++; }
        return x.toFixed(1) + ' ' + units[i];
      }

      function atBottom(el) {
        return el.scrollHeight - el.scrollTop - el.clientHeight < 20;
      }

      async function refreshLogs() {
        const logEl = $('logOut');
        const wasBottom = atBottom(logEl);
        const file = $('logFile').value;
        const tail = $('tailLines').value || 300;
        const level = $('logLevel').value || '';
        try {
          const data = await api(`/api/logs?file=${encodeURIComponent(file)}&tail=${encodeURIComponent(tail)}&level=${encodeURIComponent(level)}`);
          logEl.innerText = (data.lines || []).join('\\n');
          if (wasBottom) logEl.scrollTop = logEl.scrollHeight;
        } catch (e) {
          logEl.innerText = String(e);
        }
      }

      function startLogAutoRefresh() {
        if (logTimer) clearInterval(logTimer);
        const every = Number($('logRefreshEvery').value || 5000);
        logTimer = setInterval(refreshLogs, every);
      }

      async function refreshDashboard() {
        try {
          const m = await api('/api/dashboard/metrics');
          $('kpiInc24').innerText = String(m.incidents.total_last_window || 0);
          $('kpiCpu').innerText = (m.system.cpu_percent_total || 0).toFixed(1) + '%';
          $('kpiRam').innerText = (m.system.memory_percent_total || 0).toFixed(1) + '%';
          $('kpiContainers').innerText = String((m.system.containers || []).length);

          $('netRx').innerText = formatBytes(m.network.bytes_rx || 0);
          $('netTx').innerText = formatBytes(m.network.bytes_tx || 0);
          $('pktRx').innerText = (m.network.packets_rx || 0).toLocaleString();
          $('pktTx').innerText = (m.network.packets_tx || 0).toLocaleString();

          $('topTraffic').innerText = (m.network.top_containers || []).map(
            x => `${x.container}\\n  RX: ${formatBytes(x.bytes_rx)} | TX: ${formatBytes(x.bytes_tx)}`
          ).join('\\n\\n') || 'Sin datos recientes';

          const sev = m.incidents.by_severity || {};
          const st = m.incidents.by_status || {};
          $('severityBreakdown').innerText =
            `Severidad (24h)\\n` +
            `- critical: ${sev.critical || 0}\\n` +
            `- high: ${sev.high || 0}\\n` +
            `- medium: ${sev.medium || 0}\\n` +
            `- low: ${sev.low || 0}\\n\\n` +
            `Estado actual\\n` +
            `- new: ${st.new || 0}\\n` +
            `- reviewed: ${st.reviewed || 0}\\n` +
            `- closed: ${st.closed || 0}\\n`;
        } catch (e) {
          $('severityBreakdown').innerText = String(e);
        }
      }

      function startMetricsAutoRefresh() {
        if (metricsTimer) clearInterval(metricsTimer);
        metricsTimer = setInterval(refreshDashboard, 10000);
      }

      async function refreshIncidents() {
        lastFilters = {status: $('filterStatus').value || '', severity: $('filterSeverity').value || ''};
        page = 1;
        await loadIncidents();
      }
      async function loadIncidents() {
        const offset = (page - 1) * pageSize;
        $('incidentsMeta').innerText = 'Cargando...';
        $('incidentsBody').innerHTML = '';
        try {
          const data = await api(`/api/incidents?status=${encodeURIComponent(lastFilters.status)}&severity=${encodeURIComponent(lastFilters.severity)}&limit=${pageSize}&offset=${offset}`);
          const incidents = data.items || [];
          $('incidentsMeta').innerText = `Mostrando ${incidents.length} / ${data.total || 0} (página ${page})`;
          $('incidentsBody').innerHTML = incidents.map(i => `
            <tr>
              <td>${i.id}</td>
              <td>${i.timestamp || ''}</td>
              <td>${i.project || ''}</td>
              <td>${i.container_name || ''}</td>
              <td>${i.alert_type || ''}<div class="small">${i.rule || ''}</div></td>
              <td><span class="pill">${i.severity || ''}</span></td>
              <td>
                <select id="status_${i.id}">
                  <option value="new" ${i.status==='new'?'selected':''}>new</option>
                  <option value="reviewed" ${i.status==='reviewed'?'selected':''}>reviewed</option>
                  <option value="closed" ${i.status==='closed'?'selected':''}>closed</option>
                </select>
              </td>
              <td><button onclick="showEvidence(${i.id})">Ver</button><button style="margin-left:6px;" onclick="updateStatus(${i.id})">Guardar</button></td>
            </tr>
          `).join('');
          $('pageInfo').innerText = `Página ${page}`;
        } catch (e) {
          $('incidentsMeta').innerText = String(e);
        }
      }
      async function prevPage() { if (page <= 1) return; page--; await loadIncidents(); }
      async function nextPage() { page++; await loadIncidents(); }
      async function updateStatus(id) {
        const status = $('status_' + id).value;
        try { await api('/api/incidents/' + id + '/status', 'POST', {status}); await loadIncidents(); } catch (e) { alert(String(e)); }
      }
      async function purgeIncidentsHistory() {
        const ok1 = confirm('Esto borrará TODO el histórico de incidencias. Esta acción no se puede deshacer. ¿Continuar?');
        if (!ok1) return;
        const phrase = prompt('Escribe BORRAR HISTORICO para confirmar');
        if ((phrase || '').trim() !== 'BORRAR HISTORICO') {
          alert('Confirmación incorrecta. Operación cancelada.');
          return;
        }
        try {
          const resp = await api('/api/incidents/purge', 'POST', {confirm_text: phrase});
          alert('Histórico borrado. Registros eliminados: ' + (resp.deleted || 0));
          page = 1;
          await Promise.all([loadIncidents(), refreshDashboard()]);
        } catch (e) {
          alert(String(e));
        }
      }
      async function showEvidence(id) {
        try { const data = await api('/api/incidents/' + id); alert('Evidencia ID ' + id + '\\n\\n' + (data.evidence || '')); } catch (e) { alert(String(e)); }
      }

      async function refreshConfig() {
        $('configSaveMsg').innerText = '';
        const ov = await api('/api/config/overrides');
        $('overridesYaml').value = ov.yaml || '';
        const ef = await api('/api/config/effective');
        $('effectiveYaml').innerText = ef.yaml || '';
      }
      async function saveOverrides() {
        try {
          $('configSaveMsg').innerText = 'Guardando...';
          await api('/api/config/overrides', 'POST', {yaml: $('overridesYaml').value || ''});
          $('configSaveMsg').innerText = 'Guardado. Reinicia Centinela para aplicar.';
        } catch (e) {
          $('configSaveMsg').innerText = 'Error: ' + String(e);
        }
      }

      $('btnLogin').onclick = async () => {
        panelToken = $('tokenInput').value.trim();
        localStorage.setItem('panel_token', panelToken);
        try {
          await api('/api/health-protected');
          showApp();
          setTab('dashboard');
          await Promise.all([refreshDashboard(), refreshLogs(), refreshIncidents(), refreshConfig()]);
          startLogAutoRefresh();
          startMetricsAutoRefresh();
        } catch (e) {
          showLogin('Token inválido o panel no autorizado.');
        }
      };

      $('btnLogout').onclick = () => {
        localStorage.removeItem('panel_token');
        panelToken = '';
        location.reload();
      };
      $('logRefreshEvery').addEventListener('change', startLogAutoRefresh);
      ['logFile','tailLines','logLevel'].forEach(id => $(id).addEventListener('change', refreshLogs));

      if (panelToken) {
        showApp();
        setTab('dashboard');
        Promise.all([refreshDashboard(), refreshLogs(), refreshIncidents(), refreshConfig()]);
        startLogAutoRefresh();
        startMetricsAutoRefresh();
      } else {
        showLogin('');
      }
    </script>
  </body>
</html>
"""


def create_panel_app(
    *,
    repository: IncidentRepository,
    config_path: str,
    log_dir: str,
    overrides_path: str = _DEFAULT_OVERRIDES_PATH,
) -> FastAPI:
    app = FastAPI(title="Centinela Panel")

    log_dir_path = Path(log_dir)
    overrides_path_obj = Path(overrides_path)

    async def require_auth_dep(request: Request) -> None:
        # If token is missing in env, we return 503.
        if not _get_env_token():
            from fastapi import HTTPException

            raise HTTPException(
                status_code=503,
                detail="Panel deshabilitado: configura CENTINELA_PANEL_TOKEN.",
            )
        await _require_auth(request)

    @app.get("/api/health")
    async def health() -> Dict[str, Any]:
        return {"ok": True}

    @app.get("/api/health-protected")
    async def health_protected(_: None = Depends(require_auth_dep)) -> Dict[str, Any]:
        return {"ok": True}

    @app.get("/", response_class=HTMLResponse)
    async def index() -> HTMLResponse:
        return HTMLResponse(_render_index_html())

    @app.get("/api/logs")
    async def api_logs(
        file: str = "centinela.log",
        tail: int = 200,
        level: str = "",
        _: None = Depends(require_auth_dep),
    ) -> JSONResponse:
        allowed = set(_DEFAULT_LOG_FILES)
        if file not in allowed:
            return JSONResponse({"lines": [], "error": "Archivo no permitido"}, status_code=400)

        max_tail = max(10, min(int(tail), 5000))
        level_norm = (level or "").strip().upper()

        def _read() -> List[str]:
            path = log_dir_path / file
            lines = _read_last_lines(path, max_lines=max_tail)
            if not level_norm:
                return lines
            # Parse robustly after stripping ANSI colors:
            # "... | LEVEL | ... | ..."
            out: List[str] = []
            for ln in lines:
                clean = _strip_ansi(ln)
                marker = f"| {level_norm} "
                if marker in clean:
                    out.append(ln)
            return out

        lines = await asyncio.get_running_loop().run_in_executor(None, _read)
        return JSONResponse({"lines": lines})

    @app.get("/api/dashboard/metrics")
    async def api_dashboard_metrics(
        _: None = Depends(require_auth_dep),
    ) -> JSONResponse:
        loop = asyncio.get_running_loop()

        incidents_task = loop.run_in_executor(None, repository.get_incident_stats, 24)
        network_task = loop.run_in_executor(None, repository.get_network_usage_stats, 24)

        def _docker_metrics() -> Dict[str, Any]:
            out: Dict[str, Any] = {
                "cpu_percent_total": 0.0,
                "memory_percent_total": 0.0,
                "containers": [],
            }
            client = None
            try:
                client = docker.from_env()
                containers = client.containers.list()
                cpu_total = 0.0
                mem_total = 0.0
                for c in containers[:20]:
                    try:
                        stats = c.stats(stream=False)
                        cpu_stats = stats.get("cpu_stats", {}) or {}
                        precpu_stats = stats.get("precpu_stats", {}) or {}
                        cpu_delta = (
                            cpu_stats.get("cpu_usage", {}).get("total_usage", 0)
                            - precpu_stats.get("cpu_usage", {}).get("total_usage", 0)
                        )
                        system_delta = (
                            cpu_stats.get("system_cpu_usage", 0)
                            - precpu_stats.get("system_cpu_usage", 0)
                        )
                        cpus = len(cpu_stats.get("cpu_usage", {}).get("percpu_usage") or [1])
                        cpu_pct = 0.0
                        if system_delta > 0 and cpu_delta > 0:
                            cpu_pct = (cpu_delta / system_delta) * cpus * 100.0

                        mem_usage = float((stats.get("memory_stats", {}) or {}).get("usage", 0) or 0)
                        mem_limit = float((stats.get("memory_stats", {}) or {}).get("limit", 0) or 0)
                        mem_pct = (mem_usage / mem_limit * 100.0) if mem_limit > 0 else 0.0

                        cpu_total += cpu_pct
                        mem_total += mem_pct
                        out["containers"].append(
                            {
                                "name": c.name,
                                "cpu_percent": round(cpu_pct, 2),
                                "memory_percent": round(mem_pct, 2),
                                "memory_usage_bytes": int(mem_usage),
                            }
                        )
                    except Exception:
                        continue

                out["containers"].sort(key=lambda x: x["cpu_percent"], reverse=True)
                out["cpu_percent_total"] = round(cpu_total, 2)
                out["memory_percent_total"] = round(mem_total, 2)
                return out
            except docker.errors.DockerException as exc:
                return {"error": str(exc), **out}
            finally:
                try:
                    if client is not None:
                        client.close()
                except Exception:
                    pass

        system_task = loop.run_in_executor(None, _docker_metrics)
        incidents, network, system = await asyncio.gather(
            incidents_task, network_task, system_task
        )
        return JSONResponse(
            {
                "incidents": incidents,
                "network": network,
                "system": system,
            }
        )

    @app.get("/api/incidents")
    async def api_incidents(
        status: str = "",
        severity: str = "",
        limit: int = 25,
        offset: int = 0,
        _: None = Depends(require_auth_dep),
    ) -> JSONResponse:
        limit = max(1, min(int(limit), 100))
        offset = max(0, int(offset))
        status = (status or "").strip() or None
        severity = (severity or "").strip() or None

        def _page() -> List[Dict[str, Any]]:
            items = repository.get_incidents_paginated(
                status=status,
                severity=severity,
                limit=limit,
                offset=offset,
            )
            return [
                {
                    "id": i.id,
                    "timestamp": i.timestamp.isoformat() if i.timestamp else None,
                    "project": i.project,
                    "container_name": i.container_name,
                    "alert_type": i.alert_type,
                    "severity": i.severity,
                    "rule": i.rule,
                    "status": i.status,
                }
                for i in items
            ]

        def _count() -> int:
            return repository.count_incidents(status=status, severity=severity)

        loop = asyncio.get_running_loop()
        items, total = await asyncio.gather(
            loop.run_in_executor(None, _page),
            loop.run_in_executor(None, _count),
        )
        return JSONResponse({"items": items, "total": total})

    @app.get("/api/incidents/{incident_id}")
    async def api_incident_detail(
        incident_id: int,
        _: None = Depends(require_auth_dep),
    ) -> JSONResponse:
        def _fetch() -> Optional[Dict[str, Any]]:
            i = repository.get_incident_by_id(incident_id)
            if not i:
                return None
            return {"evidence": i.evidence}

        loop = asyncio.get_running_loop()
        incident = await loop.run_in_executor(None, _fetch)
        if not incident:
            return JSONResponse({"error": "No existe"}, status_code=404)
        return JSONResponse(
            {
                "id": incident_id,
                "evidence": incident["evidence"],
            }
        )

    @app.post("/api/incidents/{incident_id}/status")
    async def api_set_incident_status(
        incident_id: int,
        payload: Dict[str, Any] = Body(...),
        _: None = Depends(require_auth_dep),
    ) -> JSONResponse:
        status = str(payload.get("status", "new")).strip()
        if status not in ("new", "reviewed", "closed"):
            return JSONResponse({"error": "status inválido"}, status_code=400)

        def _update() -> None:
            repository.update_incident_status(incident_id, status)

        await asyncio.get_running_loop().run_in_executor(None, _update)
        return JSONResponse({"ok": True})

    @app.post("/api/incidents/purge")
    async def api_purge_incidents(
        payload: Dict[str, Any] = Body(...),
        _: None = Depends(require_auth_dep),
    ) -> JSONResponse:
        confirm_text = str(payload.get("confirm_text", "")).strip()
        if confirm_text != "BORRAR HISTORICO":
            return JSONResponse(
                {"error": "Confirmación inválida. Debe ser exactamente 'BORRAR HISTORICO'."},
                status_code=400,
            )

        deleted = await asyncio.get_running_loop().run_in_executor(
            None, repository.delete_all_incidents
        )
        return JSONResponse({"ok": True, "deleted": int(deleted)})

    @app.get("/api/config/overrides")
    async def api_get_overrides(_: None = Depends(require_auth_dep)) -> JSONResponse:
        def _read() -> str:
            if not overrides_path_obj.exists():
                # Default empty schema
                return "global: {}\nprojects: []\n"
            return overrides_path_obj.read_text(encoding="utf-8", errors="replace")

        text = await asyncio.get_running_loop().run_in_executor(None, _read)
        return JSONResponse({"yaml": text})

    @app.post("/api/config/overrides")
    async def api_set_overrides(
        payload: Dict[str, Any] = Body(...),
        _: None = Depends(require_auth_dep),
    ) -> JSONResponse:
        raw_yaml = payload.get("yaml", "")
        if not isinstance(raw_yaml, str):
            return JSONResponse({"error": "Se requiere `yaml` como string"}, status_code=400)

        # Validate YAML parses and is a dict
        try:
            parsed = yaml.safe_load(raw_yaml) or {}
        except Exception as exc:
            return JSONResponse({"error": f"YAML inválido: {exc}"}, status_code=400)

        if not isinstance(parsed, dict):
            return JSONResponse({"error": "El YAML debe ser un diccionario (map)"}, status_code=400)

        def _write() -> None:
            _atomic_write_text(overrides_path_obj, raw_yaml if raw_yaml.endswith("\n") else raw_yaml + "\n")

        await asyncio.get_running_loop().run_in_executor(None, _write)
        return JSONResponse({"ok": True})

    @app.get("/api/config/effective")
    async def api_effective_config(_: None = Depends(require_auth_dep)) -> JSONResponse:
        def _effective() -> Dict[str, Any]:
            cfg = load_config(config_path)
            return asdict(cfg)

        effective = await asyncio.get_running_loop().run_in_executor(None, _effective)
        effective_yaml = yaml.safe_dump(effective, sort_keys=False, allow_unicode=True)
        return JSONResponse({"yaml": effective_yaml})

    return app


async def run_panel_server(app: FastAPI) -> None:
    host = os.environ.get("CENTINELA_PANEL_HOST", "0.0.0.0")
    port = int(os.environ.get("CENTINELA_PANEL_PORT", "8000"))
    log_level = os.environ.get("CENTINELA_PANEL_LOG_LEVEL", "warning")

    config = uvicorn.Config(
        app,
        host=host,
        port=port,
        log_level=log_level,
    )
    server = uvicorn.Server(config)
    try:
        await server.serve()
    except asyncio.CancelledError:
        server.should_exit = True
        raise

