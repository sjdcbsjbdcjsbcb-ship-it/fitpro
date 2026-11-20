"""Run once via SSH as root on the FIT PRO application server."""
import ast
import getpass
import hashlib
import os
from pathlib import Path
import secrets
import shutil
import subprocess
import tempfile
import time

APP = Path("/var/www/fitpro")
API = APP / "main.py"
JS = APP / "admin.js"

ENDPOINT = '''
# FIT PRO: authenticated client list
from fastapi import Depends as _Depends, HTTPException as _HTTPException
from fastapi.responses import JSONResponse as _JSONResponse
from fastapi.security import HTTPBasic as _HTTPBasic, HTTPBasicCredentials as _Credentials
import hashlib as _hashlib
import secrets as _secrets

@app.get("/api/admin/clients", include_in_schema=False)
def fitpro_clients(credentials: _Credentials = _Depends(_HTTPBasic())):
    candidate = _hashlib.scrypt(credentials.password.encode(), salt=bytes.fromhex("SALT"), n=16384, r=8, p=1)
    if not _secrets.compare_digest(candidate, bytes.fromhex("DIGEST")) or credentials.username != "admin":
        raise _HTTPException(status_code=401, detail="Login required", headers={"WWW-Authenticate": 'Basic realm="FIT PRO"'})
    rows = []
    while True:
        batch = sb.table("clients").select("*").order("created_at", desc=True).range(len(rows), len(rows) + 499).execute().data
        if not isinstance(batch, list):
            raise RuntimeError("Invalid clients response")
        rows.extend(batch)
        if not batch:
            break
    fields = ("name", "username", "tg_id", "ref_code", "ref", "created_at")
    return _JSONResponse({"clients": [{k: row.get(k) for k in fields} for row in rows]}, headers={"Cache-Control": "private, no-store", "Vary": "Authorization"})
'''

def replace_once(source, old, new):
    if source.count(old) != 1:
        raise SystemExit("Unexpected file version. No changes installed.")
    return source.replace(old, new, 1)

def prepare_api(source):
    tree = ast.parse(source)
    func = next(n for n in tree.body if getattr(n, "name", "") == "get_init_data")
    target = next(n for n in func.body if isinstance(n, ast.Assign) and any(getattr(t, "id", "") == "clients" for t in n.targets))
    query = ast.get_source_segment(source, target)
    if 'clients' not in query or '.execute()' not in query or 'fitpro_clients' in source:
        raise SystemExit("Unexpected API version. No changes installed.")
    return replace_once(source, query, 'clients = []  # Client records require administrator login.')

def prepare_js(source):
    anchor = '    const renderTab = async function(tabId) {'
    source = replace_once(source, anchor, '    let tabGeneration = 0;\n' + anchor + '\n      const generation = ++tabGeneration;')
    anchor = '      const res = await fetch("/api/crm-summary?t="'
    start = source.index(anchor)
    end = source.index('\n', start)
    original = source[start:end].strip().removeprefix('const res = ').rstrip(';')
    block = """
      let res;
      if (tabId === "clients") {
        const badge = document.getElementById("crm-count-badge");
        try {
          if (location.protocol !== "https:") throw new Error("Откройте админку по HTTPS для входа.");
          const response = await fetch("/api/admin/clients", {credentials:"same-origin", cache:"no-store"});
          if (!response.ok) throw new Error(response.status === 401 ? "Для просмотра базы войдите как администратор." : "Не удалось загрузить клиентов.");
          res = await response.json();
          if (!Array.isArray(res.clients)) throw new Error("Неверный ответ сервера.");
          if (generation !== tabGeneration) return;
          if (badge) badge.textContent = res.clients.length;
        } catch (err) {
          if (generation !== tabGeneration) return;
          if (badge) badge.textContent = "—";
          panel.textContent = err.message;
          return;
        }
      } else {
        res = ORIGINAL;
      }
      if (generation !== tabGeneration) return;
""".replace("ORIGINAL", original)
    source = source[:start] + block + source[end:]
    start = source.index('        const rowsHtml = clients.map')
    end = source.index('        panel.innerHTML =', start)
    source = source[:start] + source[end:]
    original = """'<tbody>' + rowsHtml + '</tbody>'"""
    source = replace_once(source, original, """'<tbody></tbody>'""")
    anchor = '      } else if (tabId === "analytics") {'
    return replace_once(source, anchor, """
        const body = panel.querySelector("tbody");
        for (const c of clients) {
          const row = body.insertRow();
          for (const value of [c.name, c.username, c.tg_id, c.ref_code || c.ref, String(c.created_at || "").slice(0, 16).replace("T", " ")]) {
            const cell = row.insertCell();
            cell.className = "py-2";
            cell.textContent = value == null || value === "" ? "—" : String(value);
          }
        }
""" + anchor)

def install(path, data):
    with tempfile.NamedTemporaryFile(dir=path.parent, delete=False) as tmp:
        stage = Path(tmp.name)
    try:
        shutil.copy2(path, stage)
        stage.write_bytes(data)
        os.chown(stage, path.stat().st_uid, path.stat().st_gid)
        os.replace(stage, path)
    finally:
        stage.unlink(missing_ok=True)

def main():
    old = {p: p.read_bytes() for p in (API, JS)}
    if 'def fitpro_clients(' in old[API].decode() and '/api/admin/clients' in old[JS].decode():
        print("CRM_ALREADY_INSTALLED")
        return
    api = prepare_api(old[API].decode())
    js = prepare_js(old[JS].decode())
    password = getpass.getpass("New admin password (12+ ASCII characters): ")
    if not password.isascii() or len(password) < 12 or password != getpass.getpass("Repeat password: "):
        raise SystemExit("Password mismatch or too short. No changes installed.")
    salt = secrets.token_bytes(16)
    digest = hashlib.scrypt(password.encode(), salt=salt, n=16384, r=8, p=1)
    api += '\n' + ENDPOINT.replace('SALT', salt.hex()).replace('DIGEST', digest.hex())
    compile(api, str(API), 'exec')
    backup = Path(tempfile.mkdtemp(prefix='fitpro-crm-backup-', dir='/root'))
    for path in old:
        shutil.copy2(path, backup / path.name)
    print("Backup:", backup, flush=True)
    try:
        install(API, api.encode())
        install(JS, js.encode())
        subprocess.run(['systemctl','restart','fitpro'], check=True)
        time.sleep(2)
        subprocess.run(['systemctl','is-active','--quiet','fitpro'], check=True)
    except BaseException:
        for path, data in old.items():
            install(path, data)
        subprocess.run(['systemctl','restart','fitpro'], check=False)
        raise
    print("CRM_READY")

if __name__ == "__main__":
    main()
