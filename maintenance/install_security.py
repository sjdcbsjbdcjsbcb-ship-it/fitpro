"""Install the reviewed FIT PRO API guards on the matching application version."""
import ast
import os
from pathlib import Path
import shutil
import subprocess
import tempfile
import time
import urllib.request
from urllib.error import HTTPError, URLError

BASE = Path('/var/www/fitpro')
API, JS = BASE/'main.py', BASE/'admin.js'
RUNTIME = r'''
import base64
import os
import hashlib
import hmac
import json
import time
from decimal import Decimal, InvalidOperation
from pathlib import Path
from urllib.parse import parse_qsl, urlsplit
from fastapi import HTTPException
from fastapi.responses import JSONResponse
from PIL import Image, ImageOps, UnidentifiedImageError

def signed_user(raw):
    if not raw or len(raw) > 8192:
        return None
    try:
        pairs = parse_qsl(raw, strict_parsing=True, keep_blank_values=True, max_num_fields=32)
        data = dict(pairs)
        if len(data) != len(pairs):
            return None
        signature = data.pop('hash')
        message = '\n'.join(k + '=' + data[k] for k in sorted(data)).encode()
        key = hmac.digest(b'WebAppData', bot.token.encode(), 'sha256')
        if not hmac.compare_digest(hmac.digest(key, message, 'sha256').hex(), signature):
            return None
        if not -30 <= time.time() - int(data['auth_date']) <= 3600:
            return None
        user = json.loads(data['user'])
        return user if isinstance(user, dict) and type(user.get('id')) is int else None
    except (KeyError, TypeError, ValueError, UnicodeError):
        return None

# Bound costly password checks under concurrent requests.
from threading import BoundedSemaphore
_password_slots = BoundedSemaphore(4)
_password_cache_key = os.urandom(32)
_password_cache = None

def check_admin(req: Request):
    global _password_cache
    user = signed_user(req.headers.get('x-fitpro-telegram'))
    if user and user['id'] == ADMIN_ID:
        return
    try:
        scheme, value = req.headers.get('authorization', '').split(' ', 1)
        if scheme.lower() != 'basic' or len(value) > 1024:
            raise ValueError()
        name, password = base64.b64decode(value, validate=True).decode().split(':', 1)
        fingerprint = hmac.digest(_password_cache_key, value.encode(), 'sha256')
        cached = _password_cache
        if cached and cached[1] > time.monotonic() and hmac.compare_digest(cached[0], fingerprint):
            return
        if not _password_slots.acquire(blocking=False):
            raise RuntimeError('busy')
        try:
            verify_existing_admin(_Credentials(username=name, password=password))
            _password_cache = (fingerprint, time.monotonic()+30)
        finally:
            _password_slots.release()
    except RuntimeError:
        raise HTTPException(429, 'Повторите вход через несколько секунд', headers={'Retry-After':'3'})
    except (ValueError, UnicodeError, HTTPException):
        raise HTTPException(401, 'Требуется вход администратора',
                            headers={'WWW-Authenticate': 'Basic realm="FIT PRO"', 'Cache-Control':'no-store'})

@app.middleware('http')
async def secure_requests(req: Request, call_next):
    path = req.url.path
    if req.method not in ('GET', 'HEAD', 'OPTIONS'):
        origin = req.headers.get('origin')
        if (req.headers.get('x-fitpro-request') != '1' or req.headers.get('sec-fetch-site') == 'cross-site'
                or (origin and urlsplit(origin).netloc != req.headers.get('host'))):
            return JSONResponse({'detail':'Отклонён запрос'}, status_code=403)
        limit = 9*1024*1024 if path in ('/api/import-price','/api/upload-photo') else 512*1024
        size = req.headers.get('content-length', '')
        if not size.isdecimal() or int(size) > limit:
            return JSONResponse({'detail':'Размер запроса недопустим'}, status_code=413)
    if path.startswith('/uploads/') and Path(path).suffix.lower() not in ('.jpg','.jpeg','.png','.webp','.gif','.avif'):
        return JSONResponse({'detail':'Нет файла'}, status_code=404)
    resp = await call_next(req)
    resp.headers['X-Content-Type-Options'] = 'nosniff'
    if path.startswith('/api/'):
        resp.headers['Cache-Control'] = 'private, no-store'
    if path.startswith('/uploads/'):
        resp.headers['Content-Security-Policy'] = "default-src 'none'; sandbox"
    return resp

def visible_product(row):
    variants = row.get('flavors') or []
    return not (variants and (variants[0].get('fitpro') or {}).get('hidden') is True)

def public_product(row):
    fields = ('id','sku','title','brand','category','price','description','image_url','stock','in_stock')
    result = {k:row[k] for k in fields if k in row}
    result['flavors'] = []
    for f in row.get('flavors') or []:
        variant = {k:f[k] for k in ('name','stock') if k in f}
        info = f.get('fitpro') or {}
        variant['fitpro'] = {k:info[k] for k in ('amount','unit','servings','taste','eta','expected','compositionPhoto') if k in info}
        result['flavors'].append(variant)
    return result

def checked_items(items, rows):
    catalog = {str(p['id']):p for p in rows if visible_product(p)}
    result, counts, total = [], {}, Decimal(0)
    for line in items:
        p = catalog.get(str(line.get('id')))
        qty, flavor = line.get('qty'), line.get('flavor')
        if not p or type(qty) is not int or not 1 <= qty <= 10000 or not isinstance(flavor,str):
            raise HTTPException(409,'Проверьте состав корзины')
        variant = next((f for f in p.get('flavors') or [] if (f.get('name') or 'Стандарт') == flavor),None)
        key = (str(p['id']), flavor)
        counts[key] = counts.get(key,0) + qty
        try:
            stock = Decimal(str(variant.get('stock',0))) if variant else Decimal(0)
            price = Decimal(str(p['price']))
            if not stock.is_finite() or stock < counts[key] or not price.is_finite() or price < 0 or price != Decimal(str(line.get('price'))):
                raise ValueError()
        except (InvalidOperation, KeyError, ValueError):
            raise HTTPException(409,'Цена или остаток изменились')
        result.append(dict(id=p['id'],title=p['title'],flavor=flavor,qty=qty,price=float(price)))
        total += price * qty
    return result,float(total)

async def secure_order(req):
    try:
        data = await req.json()
    except ValueError:
        raise HTTPException(422,'Некорректный заказ')
    if not isinstance(data,dict):
        raise HTTPException(422,'Некорректный заказ')
    items = data.get('items')
    if not isinstance(items,list) or not 1 <= len(items) <= 100 or not all(isinstance(x,dict) and type(x.get('id')) in (int,str) and str(x['id']).isdecimal() and len(str(x['id']))<=18 for x in items):
        raise HTTPException(422,'Проверьте корзину')
    raw = req.headers.get('x-fitpro-telegram')
    user = signed_user(raw)
    if raw and not user:
        raise HTTPException(401,'Откройте магазин в Telegram повторно')
    def contact(key):
        value = data.get(key)
        if not isinstance(value,str) or not 1 <= len(value.strip()) <= 128 or not value.strip().isprintable():
            raise HTTPException(422,'Проверьте контактные данные')
        return value.strip()
    name, tg = contact('name'),contact('tg')
    if user:
        name = ' '.join(user[k] for k in ('first_name','last_name') if user.get(k)) or str(user['id'])
        tg = '@'+user['username'] if user.get('username') else str(user['id'])
    ids = list({int(x['id']) for x in items})
    rows = sb.table('products').select('id,title,price,flavors').in_('id',ids).execute().data
    lines,total = checked_items(items, rows)
    return dict(items=lines,total=total,name=name,tg=tg,source='Telegram Mini App' if user else 'Сайт (контакт указан покупателем)')

async def safe_photo(file):
    mount = next(r for r in app.routes if getattr(r,'path',None)=='/uploads')
    root = Path(mount.app.directory)
    try:
        with Image.open(file.file, formats=('JPEG','PNG','WEBP')) as original:
            if original.width * original.height > 16000000:
                raise ValueError()
            image = ImageOps.exif_transpose(original).convert('RGBA')
            image.thumbnail((2400,2400))
            name = uuid.uuid4().hex + '.webp'
            image.save(root/name,'WEBP',quality=90)
    except (UnidentifiedImageError, Image.DecompressionBombError, OSError, ValueError):
        raise HTTPException(422,'Нужно изображение JPEG, PNG или WebP до 16 мегапикселей')
    return {'ok':True,'url':'/uploads/'+name}
'''
CLIENT = r'''
// FIT PRO protected API transport
(() => {
  const nativeFetch = window.fetch.bind(window);
  const panel = () => document.getElementById('view-admin');
  const inAdmin = () => panel() && !panel().classList.contains('hidden');
  window.fetch = function(resource, options) {
    const request = new Request(resource, options);
    const url = new URL(request.url);
    if (url.origin !== location.origin || !url.pathname.startsWith('/api/')) return nativeFetch(request);
    const headers = new Headers(request.headers);
    headers.set('X-Fitpro-Request', '1');
    const raw = window.Telegram?.WebApp?.initData;
    if (raw && (inAdmin() || url.pathname === '/api/order')) headers.set('X-Fitpro-Telegram', raw);
    if (url.pathname === '/api/init' && request.method === 'GET' && inAdmin()) {
      url.pathname = '/api/admin/catalog';
      return nativeFetch(url, {headers, cache:'no-store', credentials:'same-origin',signal:request.signal});
    }
    return nativeFetch(request,{headers});
  };
  if (panel()) {
    let active = inAdmin();
    new MutationObserver(() => {
      const next = inAdmin();
      if (next && !active && typeof loadAllAdminData === 'function') loadAllAdminData();
      active = next;
    }).observe(panel(), {attributes:true,attributeFilter:['class']});
  }
})();
'''

def transform(source):
    tree = ast.parse(source)
    functions = {n.name:n for n in tree.body if isinstance(n,(ast.FunctionDef,ast.AsyncFunctionDef))}
    auth = functions['fitpro_clients']
    first, second = auth.body[:2]
    if not isinstance(first,ast.Assign) or 'scrypt' not in ast.unparse(first) or not isinstance(second,ast.If) or 'compare_digest' not in ast.unparse(second) or not isinstance(second.body[0],ast.Raise):
        raise ValueError('Unsupported existing login verifier')
    lines = source.splitlines(keepends=True)
    edits = []
    def replace(start,end,value):
        edits.append((start-1,end,value.rstrip()+'\n'))
    def body(n,value):
        replace(n.body[0].lineno,n.end_lineno,value)
    def full(n,value):
        replace(n.decorator_list[0].lineno,n.end_lineno,value)
    def segment(n):
        return ''.join(lines[n.lineno-1:n.end_lineno])
    verifier = 'def verify_existing_admin(credentials):\n'+segment(first)+segment(second)
    init = functions['get_init_data']
    if 'products' not in segment(init.body[0]) or not isinstance(init.body[-1],ast.Return):
        raise ValueError('Unsupported catalog')
    private = '@app.get("/api/admin/catalog", dependencies=[_Depends(check_admin)])\nasync def secure_admin_catalog():\n'+''.join(lines[init.body[0].lineno-1:init.end_lineno])
    public = '''    rows = sb.table('products').select('id,sku,title,brand,category,price,description,image_url,flavors').order('id', desc=True).execute().data
    return {'products':[public_product(row) for row in rows if visible_product(row)]}'''
    body(init,public)
    full(auth,'@app.get("/api/admin/clients", dependencies=[_Depends(check_admin)], include_in_schema=False)\ndef fitpro_clients():\n'+''.join(lines[auth.body[2].lineno-1:auth.end_lineno]))
    admin_names = {'add_product','del_product','import_price','rename_meta','upload_photo','update_product','save_all_categories','rename_cat','delete_cat'}
    for key in admin_names:
        node = functions[key]
        dec = node.decorator_list[0]
        if not isinstance(dec,ast.Call) or ast.unparse(dec.func) not in ('app.post','app.put','app.delete') or dec.keywords:
            raise ValueError('Unsupported route '+key)
        replace(dec.lineno,dec.end_lineno,'@'+ast.unparse(dec)[:-1]+', dependencies=[_Depends(check_admin)])')
    order = functions['create_order']
    if ast.unparse(order.body[0]) != 'd = await req.json()':
        raise ValueError('Unsupported checkout')
    replace(order.body[0].lineno,order.body[0].end_lineno,'    d = await secure_order(req)')
    body(functions['upload_photo'],'    return await safe_photo(file)')
    anchor = next(n for n in tree.body if isinstance(n,ast.Assign) and ast.unparse(n.targets[0])=='app')
    edits.append((anchor.end_lineno,anchor.end_lineno,'\nfrom fastapi import Depends as _Depends\n'+RUNTIME+'\n'+verifier+'\n'+private+'\n'))
    for a,b,replacement in sorted(edits,reverse=True):
        lines[a:b]=[replacement]
    result=''.join(lines)
    compile(result,'main.py','exec')
    return result

def write(path,data):
    with tempfile.NamedTemporaryFile(dir=path.parent,delete=False) as f:
        tmp = Path(f.name)
    try:
        shutil.copy2(path,tmp)
        tmp.write_bytes(data)
        st=path.stat()
        os.chown(tmp,st.st_uid,st.st_gid)
        os.replace(tmp,path)
    finally:
        tmp.unlink(missing_ok=True)

def ports():
    pid=subprocess.check_output(['systemctl','show','-p','MainPID','--value','fitpro'],text=True).strip()
    base=Path('/proc')/pid
    sockets={os.readlink(f) for f in (base/'fd').iterdir() if f.is_symlink()}
    result=set()
    for name in ('tcp','tcp6'):
        for line in (base/'net'/name).read_text().splitlines()[1:]:
            cols=line.split()
            if cols[3]=='0A' and 'socket:['+cols[9]+']' in sockets:
                result.add(int(cols[1].split(':')[1],16))
    return result

def protect_entry(source):
    if "def fitpro_admin_session(" in source:
        return source
    tree = ast.parse(source)
    index = next(n for n in tree.body if isinstance(n, ast.AsyncFunctionDef) and n.name == "index")
    decorator, = index.decorator_list
    if ast.unparse(decorator) != "app.get('/')":
        raise ValueError("Unexpected storefront route")
    replacement = """def require_admin_entry(req: Request):
    if 'admin' in req.query_params or 'admin_tab' in req.query_params:
        check_admin(req)

@app.get('/api/admin/session', dependencies=[_Depends(check_admin)], include_in_schema=False)
def fitpro_admin_session():
    return {'authenticated': True}

@app.get('/', dependencies=[_Depends(require_admin_entry)])"""
    lines = source.splitlines(keepends=True)
    lines[decorator.lineno-1:decorator.end_lineno] = [replacement+'\n']
    result = ''.join(lines)
    compile(result, 'main.py', 'exec')
    return result


def challenges(port, path):
    try:
        with urllib.request.urlopen(f'http://127.0.0.1:{port}'+path, timeout=1):
            return False
    except HTTPError as error:
        return error.code == 401 and 'FIT PRO' in error.headers.get('WWW-Authenticate','')


def check():
    for _ in range(20):
        try:
            for port in ports():
                if all(challenges(port, path) for path in ('/?admin=1','/api/admin/session','/api/admin/catalog')):
                    return
        except (OSError,URLError,ValueError,IndexError):
            pass
        time.sleep(0.5)
    raise RuntimeError('API login check failed')

def main():
    old={p:p.read_bytes() for p in (API,JS)}
    if b'def fitpro_admin_session(' in old[API]:
        check()
        print('FITPRO_ADMIN_LOGIN_READY')
        return
    previous = old[API].decode()
    updated = protect_entry(previous if 'def secure_admin_catalog(' in previous else transform(previous))
    js=old[JS].decode()
    if 'loadAllAdminData' not in js:
        raise ValueError('Unsupported admin client')
    # Find the interpreter used by the service, keeping its virtual environment.
    pid=subprocess.check_output(['systemctl','show','-p','MainPID','--value','fitpro'],text=True).strip()
    args=(Path('/proc')/pid/'cmdline').read_bytes().split(b'\0')
    candidates=[Path(os.fsdecode(a)) for a in args[:2] if a and os.path.basename(a).startswith(b'python')]
    candidates += [BASE/'venv/bin/python',BASE/'.venv/bin/python']
    interpreter=next(p for p in candidates if p.is_absolute() and p.is_file())
    if subprocess.run([interpreter,'-c','from PIL import Image, ImageOps'],capture_output=True).returncode:
        subprocess.run([interpreter,'-m','pip','install','Pillow>=11.3'],check=True)
    backup=Path(tempfile.mkdtemp(prefix='fitpro-security-backup-',dir='/root'))
    for path in old:
        shutil.copy2(path,backup/path.name)
    print('Backup:',backup,flush=True)
    try:
        if '// FIT PRO protected API transport' not in js:
            write(JS,(CLIENT+'\n'+js).encode())
        write(API,updated.encode())
        subprocess.run(['systemctl','restart','fitpro'],check=True)
        check()
    except BaseException:
        for p,data in old.items():
            write(p,data)
        subprocess.run(['systemctl','restart','fitpro'],check=True)
        raise
    print('FITPRO_ADMIN_LOGIN_READY')

if __name__=='__main__':
    main()

