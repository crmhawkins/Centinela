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
import html
import hmac
import json
import logging
import os
from dataclasses import asdict
from pathlib import Path
from typing import Any, Dict, List, Optional

import yaml
from fastapi import Body, Depends, FastAPI, Request
from fastapi.responses import HTMLResponse, JSONResponse
import uvicorn

from config.loader import load_config
from database.repository import IncidentRepository

logger = logging.getLogger("centinela.web.panel")

_DEFAULT_OVERRIDES_PATH = "/app/data/config_overrides.yml"
_DEFAULT_LOG_FILES = ("centinela.log", "centinela-alerts.log")


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


def _render_index_html() -> str:
    # Token-based UI: user stores token in localStorage and sends it to APIs.
    return """
<!doctype html>
<html>
  <head>
    <meta charset="utf-8"/>
    <meta name="viewport" content="width=device-width, initial-scale=1"/>
    <title>Centinela Panel</title>
    <style>
      body { font-family: Arial, sans-serif; margin: 0; padding: 16px; background: #0b0b0f; color: #eaeaf0; }
      .top { display: flex; gap: 12px; align-items: center; justify-content: space-between; }
      .card { background: #11111a; border: 1px solid #222236; border-radius: 10px; padding: 12px; margin-top: 12px; }
      .row { display: flex; gap: 12px; flex-wrap: wrap; align-items: center; }
      input, textarea, select, button { background: #0f0f15; border: 1px solid #2a2a43; color: #eaeaf0; border-radius: 8px; padding: 8px; }
      textarea { width: 100%; min-height: 240px; font-family: monospace; font-size: 12px; }
      button { cursor: pointer; }
      .tabs { display: flex; gap: 8px; margin-top: 12px; }
      .tab { padding: 8px 10px; background: #0f0f15; border: 1px solid #2a2a43; border-radius: 8px; }
      .tab.active { background: #1a1a2b; }
      table { width: 100%; border-collapse: collapse; }
      th, td { border-bottom: 1px solid #222236; padding: 8px; text-align: left; vertical-align: top; }
      th { color: #bdbddd; font-weight: 600; }
      .muted { color: #9a9ab8; font-size: 12px; }
      .danger { color: #ff6b6b; }
      .ok { color: #6bffb0; }
      .mono { font-family: monospace; }
      pre { white-space: pre-wrap; word-break: break-word; background:#0f0f15; border:1px solid #2a2a43; border-radius:10px; padding:10px; max-height: 420px; overflow:auto; }
      .pill { display:inline-block; padding:2px 8px; border:1px solid #2a2a43; border-radius:999px; font-size:12px; background:#0f0f15; }
    </style>
  </head>
  <body>
    <div class="top">
      <div>
        <div style="font-size: 18px; font-weight: 700;">Centinela Panel</div>
        <div class="muted">Logs, incidencias y configuración segura (overrides) + token</div>
      </div>
      <button id="btnLogout" style="display:none;">Cerrar sesión</button>
    </div>

    <div id="loginCard" class="card">
      <div style="font-size: 14px; font-weight: 700; margin-bottom: 8px;">Token de acceso</div>
      <div class="muted">Este token se configura en `CENTINELA_PANEL_TOKEN`.</div>
      <div class="row" style="margin-top: 12px;">
        <input id="tokenInput" placeholder="Pega aquí el token" style="flex: 1;" />
        <button id="btnLogin">Entrar</button>
      </div>
      <div id="loginError" class="danger" style="margin-top: 10px;"></div>
    </div>

    <div id="appCard" class="card" style="display:none;">
      <div class="tabs">
        <div class="tab active" id="tabLogs" onclick="setTab('logs')">Logs</div>
        <div class="tab" id="tabIncidents" onclick="setTab('incidents')">Incidencias</div>
        <div class="tab" id="tabConfig" onclick="setTab('config')">Configuración</div>
      </div>

      <div id="viewLogs" style="margin-top: 12px;">
        <div class="row">
          <label class="muted">Archivo:</label>
          <select id="logFile">
            <option value="centinela.log" selected>centinela.log</option>
            <option value="centinela-alerts.log">centinela-alerts.log</option>
          </select>
          <label class="muted">Tail (líneas):</label>
          <input id="tailLines" type="number" min="10" max="5000" value="200" style="width: 120px;"/>
          <label class="muted">Nivel:</label>
          <select id="logLevel">
            <option value="">Todos</option>
            <option value="DEBUG">DEBUG</option>
            <option value="INFO">INFO</option>
            <option value="WARNING">WARNING</option>
            <option value="ALERT">ALERT</option>
            <option value="CRITICAL">CRITICAL</option>
          </select>
          <button onclick="refreshLogs()">Actualizar</button>
        </div>
        <div style="margin-top: 12px;">
          <pre id="logOut" class="mono"></pre>
        </div>
      </div>

      <div id="viewIncidents" style="display:none; margin-top: 12px;">
        <div class="row">
          <label class="muted">Estado:</label>
          <select id="filterStatus">
            <option value="">Todos</option>
            <option value="new">new</option>
            <option value="reviewed">reviewed</option>
            <option value="closed">closed</option>
          </select>
          <label class="muted">Severidad:</label>
          <select id="filterSeverity">
            <option value="">Todas</option>
            <option value="low">low</option>
            <option value="medium">medium</option>
            <option value="high">high</option>
            <option value="critical">critical</option>
          </select>
          <button onclick="refreshIncidents()">Buscar</button>
        </div>
        <div style="margin-top: 12px;">
          <div id="incidentsMeta" class="muted"></div>
          <table>
            <thead>
              <tr>
                <th>ID</th>
                <th>Fecha</th>
                <th>Proyecto</th>
                <th>Container</th>
                <th>Tipo</th>
                <th>Severidad</th>
                <th>Estado</th>
                <th>Acción</th>
              </tr>
            </thead>
            <tbody id="incidentsBody"></tbody>
          </table>
          <div class="row" style="margin-top: 10px;">
            <button onclick="prevPage()">Anterior</button>
            <div id="pageInfo" class="muted"></div>
            <button onclick="nextPage()">Siguiente</button>
          </div>
        </div>
      </div>

      <div id="viewConfig" style="display:none; margin-top: 12px;">
        <div class="muted">
          Los cambios se guardan en overrides persistentes y <span class="danger">se aplican al reiniciar</span> Centinela.
        </div>
        <div class="row" style="margin-top: 10px;">
          <button onclick="refreshConfig()">Refrescar</button>
        </div>
        <div class="card" style="margin-top: 12px;">
          <div style="font-weight: 700; margin-bottom: 8px;">Overwrites (editables)</div>
          <textarea id="overridesYaml"></textarea>
          <div class="row" style="margin-top: 10px; justify-content: space-between;">
            <div id="configSaveMsg" class="muted"></div>
            <button onclick="saveOverrides()">Guardar overrides</button>
          </div>
        </div>
        <div class="card" style="margin-top: 12px;">
          <div style="font-weight: 700; margin-bottom: 8px;">Config efectiva (solo lectura)</div>
          <pre id="effectiveYaml" class="mono"></pre>
        </div>
      </div>
    </div>

    <script>
      let panelToken = localStorage.getItem('panel_token') || '';
      let page = 1;
      let pageSize = 25;
      let lastFilters = {status:'', severity:''};

      function setTab(name) {
        document.querySelectorAll('.tab').forEach(t => t.classList.remove('active'));
        document.getElementById('tabLogs').classList.toggle('active', name==='logs');
        document.getElementById('tabIncidents').classList.toggle('active', name==='incidents');
        document.getElementById('tabConfig').classList.toggle('active', name==='config');
        document.getElementById('viewLogs').style.display = name==='logs' ? 'block' : 'none';
        document.getElementById('viewIncidents').style.display = name==='incidents' ? 'block' : 'none';
        document.getElementById('viewConfig').style.display = name==='config' ? 'block' : 'none';
      }

      function setAuthFromInput() {
        panelToken = document.getElementById('tokenInput').value.trim();
        localStorage.setItem('panel_token', panelToken);
      }

      async function api(path, method='GET', body=null) {
        const headers = {};
        if (panelToken) headers['Authorization'] = 'Bearer ' + panelToken;
        if (method !== 'GET' && body !== null) headers['Content-Type'] = 'application/json';
        const resp = await fetch(path, {method, headers, body: body ? JSON.stringify(body) : undefined});
        if (!resp.ok) {
          const txt = await resp.text();
          throw new Error('HTTP ' + resp.status + ': ' + txt.slice(0, 300));
        }
        return await resp.json();
      }

      function escapeHtml(s) {
        const d = document.createElement('div');
        d.innerText = s;
        return d.innerHTML;
      }

      function showLogin(showErr, msg='') {
        document.getElementById('loginCard').style.display = 'block';
        document.getElementById('appCard').style.display = 'none';
        document.getElementById('btnLogout').style.display = 'none';
        if (showErr) document.getElementById('loginError').innerText = msg;
      }

      function showApp() {
        document.getElementById('loginCard').style.display = 'none';
        document.getElementById('appCard').style.display = 'block';
        document.getElementById('btnLogout').style.display = 'inline-block';
      }

      document.getElementById('btnLogin').onclick = async () => {
        document.getElementById('loginError').innerText = '';
        setAuthFromInput();
        try {
          // Probe
          await api('/api/health-protected');
          showApp();
          refreshLogs();
          refreshIncidents();
          refreshConfig();
        } catch (e) {
          showLogin(true, 'Token inválido o panel no autorizado.');
        }
      };

      document.getElementById('btnLogout').onclick = () => {
        localStorage.removeItem('panel_token');
        panelToken = '';
        location.reload();
      };

      async function refreshLogs() {
        const file = document.getElementById('logFile').value;
        const tail = document.getElementById('tailLines').value || 200;
        const level = document.getElementById('logLevel').value || '';
        const url = `/api/logs?file=` + encodeURIComponent(file) + `&tail=` + encodeURIComponent(tail) + `&level=` + encodeURIComponent(level);
        document.getElementById('logOut').innerText = 'Cargando...';
        try {
          const data = await api(url);
          document.getElementById('logOut').innerText = (data.lines || []).join('\\n');
        } catch (e) {
          document.getElementById('logOut').innerText = String(e);
        }
      }

      async function refreshIncidents() {
        const status = document.getElementById('filterStatus').value || '';
        const severity = document.getElementById('filterSeverity').value || '';
        lastFilters = {status, severity};
        page = 1;
        await loadIncidents();
      }

      async function loadIncidents() {
        const status = lastFilters.status;
        const severity = lastFilters.severity;
        const offset = (page - 1) * pageSize;
        const url = `/api/incidents?status=` + encodeURIComponent(status) + `&severity=` + encodeURIComponent(severity) + `&limit=${pageSize}&offset=${offset}`;
        document.getElementById('incidentsMeta').innerText = 'Cargando...';
        const body = document.getElementById('incidentsBody');
        body.innerHTML = '';
        try {
          const data = await api(url);
          const incidents = data.items || [];
          const total = data.total || 0;
          document.getElementById('incidentsMeta').innerText = `Mostrando ${incidents.length} / ${total} (página ${page})`;
          body.innerHTML = incidents.map(i => {
            const ts = i.timestamp ? String(i.timestamp) : '';
            const evidenceBtn = `<button onclick="showEvidence(${i.id})">Ver</button>`;
            return `
              <tr>
                <td class="mono">${i.id}</td>
                <td>${escapeHtml(ts)}</td>
                <td>${escapeHtml(i.project)}</td>
                <td>${escapeHtml(i.container_name)}</td>
                <td>${escapeHtml(i.alert_type)}<div class="muted">${escapeHtml(i.rule||'')}</div></td>
                <td><span class="pill">${escapeHtml(i.severity)}</span></td>
                <td>
                  <select id="status_${i.id}">
                    <option value="new" ${i.status==='new'?'selected':''}>new</option>
                    <option value="reviewed" ${i.status==='reviewed'?'selected':''}>reviewed</option>
                    <option value="closed" ${i.status==='closed'?'selected':''}>closed</option>
                  </select>
                </td>
                <td>${evidenceBtn}<button style="margin-left:8px;" onclick="updateStatus(${i.id})">Guardar</button></td>
              </tr>
            `;
          }).join('');
          document.getElementById('pageInfo').innerText = `Página ${page}`;
        } catch (e) {
          document.getElementById('incidentsMeta').innerText = String(e);
        }
      }

      async function prevPage() {
        if (page <= 1) return;
        page -= 1;
        await loadIncidents();
      }
      async function nextPage() {
        page += 1;
        await loadIncidents();
      }

      async function updateStatus(id) {
        const sel = document.getElementById('status_' + id);
        const status = sel ? sel.value : 'new';
        try {
          await api('/api/incidents/' + id + '/status', 'POST', {status});
          await loadIncidents();
        } catch (e) {
          alert(String(e));
        }
      }

      async function showEvidence(id) {
        try {
          const data = await api('/api/incidents/' + id);
          const ev = data.evidence || '';
          alert('Evidencia (ID ' + id + ')\\n\\n' + ev);
        } catch (e) {
          alert(String(e));
        }
      }

      async function refreshConfig() {
        document.getElementById('configSaveMsg').innerText = '';
        const overrides = await api('/api/config/overrides');
        document.getElementById('overridesYaml').value = overrides.yaml || '';
        const eff = await api('/api/config/effective');
        document.getElementById('effectiveYaml').innerText = eff.yaml || '';
      }

      async function saveOverrides() {
        const text = document.getElementById('overridesYaml').value || '';
        try {
          document.getElementById('configSaveMsg').className = 'muted';
          document.getElementById('configSaveMsg').innerText = 'Guardando...';
          await api('/api/config/overrides', 'POST', {yaml: text});
          document.getElementById('configSaveMsg').innerText = 'Guardado. Reinicia Centinela para aplicar.';
        } catch (e) {
          document.getElementById('configSaveMsg').className = 'danger';
          document.getElementById('configSaveMsg').innerText = 'Error: ' + String(e);
        }
      }

      // Init
      if (panelToken) {
        showApp();
        refreshLogs();
        refreshIncidents();
        refreshConfig();
      } else {
        showLogin(false);
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
            # Parse: "... | LEVEL | ... | ..."
            out: List[str] = []
            for ln in lines:
                parts = [p.strip() for p in ln.split(" | ")]
                if len(parts) >= 2:
                    ln_level = parts[1].upper()
                    if ln_level == level_norm:
                        out.append(ln)
                else:
                    # If format differs, keep line only if no filtering.
                    continue
            return out

        lines = await asyncio.get_running_loop().run_in_executor(None, _read)
        return JSONResponse({"lines": lines})

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

