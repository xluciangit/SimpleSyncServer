'use strict';

const { fmtBytes } = require('../lib/db');
const { escapeHtml } = require('../lib/security');



const FAVICON_TAG = '<link rel="icon" type="image/png" href="/static/android_app_icon.png">';

const ICON_LOGO     = '<img src="/static/android_app_icon.png" style="width:34px;height:34px;object-fit:contain;border-radius:8px" alt="">';
const ICON_DASH     = '<img src="/static/dashboard.png" style="width:22px;height:22px;object-fit:contain" alt="">';
const ICON_SETTINGS = '<img src="/static/settings.png" style="width:22px;height:22px;object-fit:contain" alt="">';
const ICON_USERS    = '<img src="/static/user_logout.png" style="width:22px;height:22px;object-fit:contain" alt="">';
const ICON_USER     = '<img src="/static/user.png" style="width:16px;height:16px;object-fit:contain;vertical-align:middle" alt="">';
const ICON_SIGNOUT  = '<img src="/static/user_logout.png" style="width:22px;height:22px;object-fit:contain" alt="">';
const ICON_MOON     = '<img src="/static/blue_moon.png" style="width:20px;height:20px;object-fit:contain" alt="">';
const ICON_SUN      = '<img src="/static/blue_sun.png" style="width:20px;height:20px;object-fit:contain" alt="">';

const BASE_STYLE = `
  *{box-sizing:border-box;margin:0;padding:0}
  :root{
    --bg:#16161C;--surface:#222228;--surface2:#2A2A32;
    --border:#32323C;--accent:#4A6CF7;--accent2:#39C5D9;
    --red:#FF6B6B;--yellow:#FBBF24;
    --text:#FFFFFF;--muted:#8A8A9A;--radius:10px;
    --input-bg:#16161C;--btn-primary-text:#fff;
    --sidebar-w:56px;
  }
  [data-theme="light"]{
    --bg:#EEF4FC;--surface:#D8DFE8;--surface2:#CBD4E0;
    --border:#B8C8DA;--accent:#3F86E8;--accent2:#39C5D9;
    --red:#DC2626;--yellow:#D97706;
    --text:#0D1A2E;--muted:#4A6A90;--radius:10px;
    --input-bg:#FFFFFF;--btn-primary-text:#fff;
  }
  html,body{height:100%}
  body{background:var(--surface);color:var(--text);font-family:'Segoe UI',system-ui,sans-serif;min-height:100vh}
  a{color:var(--accent);text-decoration:none}

  .app{display:flex;height:100vh;overflow:hidden}

  .sidebar{
    width:var(--sidebar-w);flex-shrink:0;
    background:var(--surface);
    display:flex;flex-direction:column;align-items:center;
    padding:10px 6px 10px;gap:4px;
    height:100vh;
    overflow:hidden;
    position:sticky;top:0;z-index:10;
  }
  .sidebar-logo{width:36px;height:36px;margin-bottom:12px;display:flex;align-items:center;justify-content:center}
  .nav-btn{
    width:44px;height:44px;border-radius:10px;border:none;cursor:pointer;
    display:flex;align-items:center;justify-content:center;
    background:transparent;color:var(--text);opacity:1;
    transition:background .15s;position:relative;
    text-decoration:none;
  }
  .nav-btn svg{width:20px;height:20px;pointer-events:none}
  .nav-btn:hover{background:var(--surface2)}
  .nav-btn.active{background:var(--surface2)}
  .nav-btn.active::before{
    content:'';position:absolute;left:0;top:50%;transform:translateY(-50%);
    width:3px;height:24px;background:var(--accent);border-radius:0 3px 3px 0;
  }
  .nav-spacer{flex:1}
  .icon-btn{
    width:36px;height:36px;border-radius:8px;border:none;cursor:pointer;
    display:flex;align-items:center;justify-content:center;
    background:transparent;color:var(--text);transition:background .15s;
  }
  .icon-btn svg{width:18px;height:18px}
  .icon-btn:hover{background:var(--surface2)}

  .content-col{flex:1;display:flex;flex-direction:column;min-width:0;overflow:hidden}

  .page-hdr{
    height:46px;flex-shrink:0;
    background:var(--surface);
    display:flex;align-items:center;
    padding:0 18px;
    gap:10px;
  }
  .page-title{font-size:.95rem;font-weight:700;color:var(--text);letter-spacing:-.01em;flex:1}
  .hdr-meta{color:var(--muted);font-size:.78rem;display:flex;align-items:center;gap:10px}
  .badge{background:var(--surface2);border:1px solid var(--border);padding:2px 8px;border-radius:20px;font-size:.7rem;color:var(--muted)}

  .content-panel{
    flex:1;overflow-y:auto;
    background:var(--bg);
    border-top-left-radius:12px;
    overscroll-behavior:contain;
    -webkit-overflow-scrolling:touch;
  }
  .wrap{max-width:1100px;margin:0 auto;padding:24px 20px}
  .wrap-narrow{max-width:640px;margin:0 auto;padding:24px 20px}

  .card{background:var(--surface);border:1px solid var(--border);border-radius:var(--radius);padding:22px}
  .card h2{font-size:1rem;font-weight:600;color:var(--accent);margin-bottom:16px}
  .section{margin-bottom:24px}
  .section h3{font-size:.9rem;font-weight:600;color:var(--text);margin-bottom:14px;padding-bottom:8px;border-bottom:1px solid var(--border)}
  .section-title{font-size:.95rem;font-weight:700;color:var(--text);margin:22px 0 12px}
  .btn{cursor:pointer;border:none;border-radius:8px;padding:9px 18px;font-size:.85rem;font-weight:600;transition:.15s;display:inline-block}
  .btn-primary{background:var(--accent);color:var(--btn-primary-text)}.btn-primary:hover{opacity:.88}
  .btn-ghost{background:var(--surface2);color:var(--text);border:1px solid var(--border)}.btn-ghost:hover{border-color:var(--accent);color:var(--accent)}
  .btn-red{background:rgba(255,107,107,.12);color:var(--red);border:1px solid rgba(255,107,107,.28)}.btn-red:hover{background:rgba(255,107,107,.22)}
  .btn-sm{padding:5px 12px;font-size:.78rem}
  .form-group{margin-bottom:14px}
  .form-group label{display:block;font-size:.8rem;color:var(--muted);margin-bottom:6px}
  input[type=text],input[type=password],input[type=url],select{
    background:var(--input-bg);border:1px solid var(--border);border-radius:8px;
    padding:10px 14px;color:var(--text);font-size:.9rem;width:100%;outline:none;transition:.15s
  }
  input[type=text]:focus,input[type=password]:focus,input[type=url]:focus,select:focus{border-color:var(--accent)}
  .err{background:rgba(255,107,107,.1);border:1px solid rgba(255,107,107,.35);border-radius:8px;padding:10px 14px;color:var(--red);font-size:.85rem;margin-bottom:14px}
  .ok{background:rgba(74,222,128,.1);border:1px solid rgba(74,222,128,.35);border-radius:8px;padding:10px 14px;color:var(--accent2);font-size:.85rem;margin-bottom:14px}
  .warn{background:rgba(251,191,36,.07);border:1px solid rgba(251,191,36,.28);border-radius:8px;padding:10px 14px;font-size:.82rem;color:var(--yellow);margin-bottom:14px}
  .grid2{display:grid;grid-template-columns:1fr 1fr;gap:20px}
  @media(max-width:720px){.grid2{grid-template-columns:1fr}}
  .stats-row{display:flex;gap:14px;margin-bottom:24px;flex-wrap:wrap}
  .stat{background:var(--surface);border:1px solid var(--border);border-radius:var(--radius);padding:16px 20px;flex:1;min-width:130px}
  .stat .val{font-size:1.6rem;font-weight:700;color:var(--accent)}
  .stat .lbl{font-size:.76rem;color:var(--muted);margin-top:4px}
  .key-row{display:flex;align-items:center;gap:8px;flex-wrap:wrap;background:var(--bg);border:1px solid var(--border);border-radius:8px;padding:11px 14px;margin-bottom:12px}
  .key-val{font-family:monospace;font-size:.83rem;color:var(--accent2);word-break:break-all;flex:1}
  .folder-item{border:1px solid var(--border);border-radius:8px;margin-bottom:10px;overflow:hidden}
  .folder-hdr{display:flex;align-items:center;gap:12px;padding:12px 16px;background:var(--surface);cursor:pointer;user-select:none}
  .folder-hdr:hover{background:var(--surface2)}
  .folder-body{padding:0 16px;max-height:0;overflow:hidden;background:var(--bg);transition:max-height .25s ease,padding .25s ease}
  .folder-body.open{padding:14px 16px;max-height:1000px}
  .date-row{display:flex;gap:8px;align-items:center;padding:6px 0;border-bottom:1px solid var(--border);font-size:.85rem}
  .date-row:last-child{border-bottom:none}
  .date-tag{background:rgba(74,108,247,.12);color:var(--accent);border-radius:6px;padding:2px 10px;font-size:.78rem;min-width:90px;text-align:center}
  .form-row{display:flex;gap:8px;margin-top:4px}
  .form-row input{flex:1}
  #toast{position:fixed;bottom:24px;right:24px;background:var(--surface);border:1px solid var(--border);border-radius:10px;padding:12px 20px;color:var(--text);font-size:.88rem;opacity:0;pointer-events:none;transition:opacity .3s;z-index:9999;max-width:300px}
  #toast.show{opacity:1}
  .modal-overlay{display:none;position:fixed;inset:0;background:rgba(0,0,0,.65);z-index:1000;align-items:center;justify-content:center}
  .modal-box{background:var(--surface);border:1px solid var(--border);border-radius:var(--radius);padding:28px 24px;max-width:420px;width:90%;box-shadow:0 12px 40px rgba(0,0,0,.5)}
  .modal-title{font-size:1.05rem;font-weight:600;margin-bottom:16px}
`;

function navSidebar(active, csrfToken, theme, isAdmin) {
    const items = [
        { id: 'dash',     href: '/',        icon: ICON_DASH,     label: 'Dashboard' },
        { id: 'settings', href: '/settings', icon: ICON_SETTINGS, label: 'Settings'  },

    ];

    const navItems = items.map(item => `
        <a href="${item.href}" class="nav-btn${active === item.id ? ' active' : ''}" title="${item.label}">
            ${item.icon}
        </a>`).join('');

    const isDark = theme !== 'light';

    return `
    <nav class="sidebar">
        <div class="sidebar-logo">${ICON_LOGO}</div>
        ${navItems}
        <div class="nav-spacer"></div>
        <button class="icon-btn" onclick="toggleTheme()" title="Toggle theme" id="theme-btn">
            ${isDark ? ICON_SUN : ICON_MOON}
        </button>
        <form method="POST" action="/logout" style="display:contents">
            <input type="hidden" name="_csrf" value="${csrfToken}">
            <button class="nav-btn" type="submit" title="Sign out" style="margin-top:4px">
                ${ICON_SIGNOUT}
            </button>
        </form>
    </nav>`;
}

function sharedScript(csrfToken, theme) {
    return `
function toast(m){const el=document.getElementById('toast');el.textContent=m;el.className='show';clearTimeout(el._t);el._t=setTimeout(()=>el.className='',3200)}
function toggleTheme(){
    const cur=document.documentElement.getAttribute('data-theme');
    const next=cur==='light'?'dark':'light';
    document.documentElement.setAttribute('data-theme',next);
    fetch('/settings/theme',{method:'POST',headers:{'Content-Type':'application/x-www-form-urlencoded'},body:'theme='+next+'&_csrf=${csrfToken}'});
    setTimeout(()=>location.reload(),150);
}
function tog(n){
    const el=document.getElementById('fb-'+n);
    if(el) el.classList.toggle('open');
}
document.addEventListener('click',function(e){
    const hdr=e.target.closest('.folder-hdr[data-folder]');
    if(hdr) tog(hdr.dataset.folder);
    const rem=e.target.closest('[data-remove]');
    if(rem) showRemoveFolderModal(decodeURIComponent(rem.dataset.remove));
});`;
}

function renderLogin({ error, csrfToken, nonce = '', theme = 'dark' }) {
    return `<!DOCTYPE html><html lang="en" data-theme="${theme}"><head>
<meta charset="UTF-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>Login – SimpleSync Server</title>
${FAVICON_TAG}
<style>${BASE_STYLE}
  body{display:flex;align-items:center;justify-content:center;background:var(--bg)}
  .login-card{background:var(--surface);border:1px solid var(--border);border-radius:14px;padding:36px 32px;width:100%;max-width:400px}
  .login-logo{display:flex;align-items:center;gap:10px;margin-bottom:6px}
  .login-logo span{font-size:1.2rem;font-weight:700;color:var(--text)}
  .login-sub{color:var(--muted);font-size:.85rem;margin-bottom:28px}
</style></head><body>
<div class="login-card">
  <div class="login-logo">${ICON_LOGO}<span>SimpleSync Server</span></div>
  <p class="login-sub">Sign in to manage your sync server</p>
  ${error ? `<div class="err">${escapeHtml(error)}</div>` : ''}
  <form method="POST" action="/login">
    <input type="hidden" name="_csrf" value="${csrfToken}">
    <div class="form-group"><label>Username</label>
      <input type="text" name="username" autofocus autocomplete="username" required></div>
    <div class="form-group"><label>Password</label>
      <input type="password" name="password" autocomplete="current-password" required></div>
    <button class="btn btn-primary" style="width:100%;margin-top:8px" type="submit">Sign In</button>
  </form>
</div>
</body></html>`;
}

function renderChangePassword({ error, isFirstTime, csrfToken, nonce = '' }) {
    return `<!DOCTYPE html><html lang="en" data-theme="dark"><head>
<meta charset="UTF-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>Change Password – SimpleSync Server</title>
${FAVICON_TAG}
<style>${BASE_STYLE}
  body{display:flex;align-items:center;justify-content:center;background:var(--bg)}
  .login-card{background:var(--surface);border:1px solid var(--border);border-radius:14px;padding:36px 32px;width:100%;max-width:420px}
</style></head><body>
<div class="login-card">
  <h2 style="margin-bottom:8px">${isFirstTime ? 'Set a password to continue' : 'Change Password'}</h2>
  ${isFirstTime ? '<p style="color:var(--muted);font-size:.85rem;margin-bottom:20px">Your account was created with a temporary password.</p>' : ''}
  ${error ? `<div class="err">${escapeHtml(error)}</div>` : ''}
  <form method="POST" action="/change-password">
    <input type="hidden" name="_csrf" value="${csrfToken}">
    <div class="form-group"><label>New Password</label>
      <input type="password" name="new_password" autofocus required>
      <p style="font-size:.75rem;color:var(--muted);margin-top:5px">Min 8 chars · uppercase · lowercase · number · special character</p></div>
    <div class="form-group"><label>Confirm New Password</label>
      <input type="password" name="confirm_password" required></div>
    <button class="btn btn-primary" style="width:100%;margin-top:8px" type="submit">Set Password</button>
  </form>
</div>
</body></html>`;
}

function renderDashboard({ username, apiKey, folders, totalFiles, totalBytes, uptime, theme = 'dark', csrfToken, diskFree, diskUsed, diskTotal, folderError = null, flashMsg = null, nonce = '' }) {
    const folderRows = folders.length === 0
        ? '<p style="color:var(--muted);padding:12px 0">No folders yet. Add one below.</p>'
        : folders.map(f => {
            const stats = f.stats || [];
            const tFiles = stats.reduce((a, s) => a + s.count, 0);
            const tBytes = stats.reduce((a, s) => a + s.totalBytes, 0);
            const rows = stats.length === 0
                ? '<p style="color:var(--muted);font-size:.85rem">No uploads yet</p>'
                : stats.map(s => `<div class="date-row">
                    <span class="date-tag">${s.date}</span>
                    <span style="color:var(--muted);flex:1">${s.count} file${s.count !== 1 ? 's' : ''}</span>
                    <span style="color:var(--accent2)">${fmtBytes(s.totalBytes)}</span>
                </div>`).join('');

            return `<div class="folder-item">
                <div class="folder-hdr" data-folder="${encodeURIComponent(f.name)}">
                    <img src="/static/folder.png" style="width:18px;height:18px;object-fit:contain" alt="">
                    <span style="font-weight:600;flex:1">${escapeHtml(f.name)}</span>
                    <span style="color:var(--muted);font-size:.82rem">${tFiles} files · ${fmtBytes(tBytes)}</span>
                    <span style="color:var(--muted);margin-left:8px;font-size:.8rem">▾</span>
                </div>
                <div class="folder-body" id="fb-${encodeURIComponent(f.name)}">
                    ${rows}
                    <div style="margin-top:12px">
                        <button class="btn btn-red btn-sm" data-remove="${encodeURIComponent(f.name)}">Remove</button>
                    </div>
                </div>
            </div>`;
        }).join('');

    return `<!DOCTYPE html><html lang="en" data-theme="${theme}"><head>
<meta charset="UTF-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>SimpleSync Server</title>
${FAVICON_TAG}
<style>${BASE_STYLE}</style></head><body>
<div class="app">
${navSidebar('dash', csrfToken, theme, false)}
<div class="content-col">
  <div class="page-hdr">
    <span class="page-title">Dashboard</span>
    <div class="hdr-meta">
      <span class="badge">v1.2.2</span>
      <span class="badge"><img src="/static/stopwatch.png" style="width:13px;height:13px;object-fit:contain;vertical-align:middle;margin-right:3px" alt=""> ${uptime}</span>
      <span>${escapeHtml(username)}</span>
    </div>
  </div>
  <div class="content-panel">
  <div class="wrap">
    <div class="stats-row">
      <div class="stat"><div class="val">${folders.length}</div><div class="lbl">Configured Folders</div></div>
      <div class="stat"><div class="val">${totalFiles.toLocaleString()}</div><div class="lbl">Files in DB</div></div>
      <div class="stat"><div class="val">${totalBytes}</div><div class="lbl">Total Size</div></div>
      <div class="stat"><div class="val">${diskFree}</div><div class="lbl">Free Disk</div></div>
      <div class="stat"><div class="val" style="font-size:1rem">${diskUsed} / ${diskTotal}</div><div class="lbl">Disk Used / Total</div></div>
    </div>

    <div class="card" style="margin-bottom:20px">
      <h2>API Key</h2>
      ${apiKey
        ? `<div class="warn" style="margin-bottom:12px">Enter this key in SimpleSync Companion to authorise uploads.</div>
           <div class="key-row">
             <span style="font-family:monospace;font-size:.83rem;color:var(--muted);flex:1;min-width:0;overflow:hidden;text-overflow:ellipsis;white-space:nowrap">Configured ••••••••••••••••••••••••${apiKey.slice(-8)}</span>
           </div>
           <p style="font-size:.78rem;color:var(--muted);margin-bottom:10px">To copy the full key go to Settings → Regenerate Key.</p>`
        : `<p style="color:var(--muted);font-size:.85rem;margin-bottom:10px">No key yet — go to Settings → Regenerate Key.</p>`
      }
      <a href="/settings" class="btn btn-ghost btn-sm">Manage in Settings →</a>
    </div>

    ${flashMsg ? `<div class="ok" style="margin-bottom:14px">✓ ${escapeHtml(flashMsg)}</div>` : ''}
    ${folderError ? `<div class="err" style="margin-bottom:12px">${escapeHtml(folderError)}</div>` : ''}

    <div class="section-title">Sync Folders</div>
    <div id="folders-list">${folderRows}</div>

    <div class="section-title">Integrity Check</div>
    <div class="card" style="margin-bottom:28px">
      <p style="color:var(--muted);font-size:.85rem;margin-bottom:14px">Scans file records and removes entries where the file no longer exists on disk.</p>
      <button class="btn btn-ghost btn-sm" type="button" onclick="showIntegrityModal('user')">Run Integrity Check</button>
    </div>
  </div>
  </div>
</div>
</div>
<div id="toast"></div>

<div id="removeFolderModal" class="modal-overlay">
  <div class="modal-box">
    <div class="modal-title">Remove: <span id="removeFolderName" style="color:var(--accent)"></span></div>
    <p style="color:var(--muted);font-size:.88rem;margin-bottom:16px">All records for this folder will be removed from the database.</p>
    <div style="background:var(--bg);border:1px solid var(--border);border-radius:8px;padding:14px;margin-bottom:16px">
      <label style="display:flex;align-items:flex-start;gap:10px;cursor:pointer">
        <input type="checkbox" id="removeFolderFilesChk" style="margin-top:3px;accent-color:var(--red)" onchange="onRemoveFolderChkChange(this)">
        <span>
          <span style="font-size:.88rem;font-weight:600;color:var(--red)">Also delete all files on disk</span><br>
          <span style="font-size:.78rem;color:var(--muted)">Permanently deletes the folder and all its contents. Cannot be undone.</span>
        </span>
      </label>
    </div>
    <div id="removeFolderWarn" style="display:none;background:rgba(255,107,107,.1);border:1px solid rgba(255,107,107,.3);border-radius:8px;padding:10px 14px;font-size:.82rem;color:var(--red);margin-bottom:16px">
      <img src="/static/alert.png" style="width:14px;height:14px;object-fit:contain;vertical-align:middle;margin-right:4px" alt=""> All files in this folder will be permanently deleted from disk.
    </div>
    <div style="display:flex;gap:10px;justify-content:flex-end">
      <button class="btn btn-ghost btn-sm" onclick="hideRemoveFolderModal()">Cancel</button>
      <form id="removeFolderForm" method="POST" action="/web/folders/remove" style="display:inline">
        <input type="hidden" name="_csrf" value="${csrfToken}">
        <input type="hidden" id="removeFolderNameInput" name="name" value="">
        <input type="checkbox" id="removeFolderFilesHidden" name="delete_files" value="on" style="display:none">
        <button class="btn btn-red btn-sm" type="submit">Confirm Remove</button>
      </form>
    </div>
  </div>
</div>

<div id="integrityModal" class="modal-overlay">
  <div class="modal-box">
    <div class="modal-title">Run Integrity Check</div>
    <p id="integrityModalDesc" style="color:var(--muted);font-size:.88rem;margin-bottom:16px"></p>
    <div style="background:rgba(255,107,107,.08);border:1px solid rgba(255,107,107,.3);border-radius:8px;padding:10px 14px;font-size:.82rem;color:var(--red);margin-bottom:20px">
      <img src="/static/alert.png" style="width:14px;height:14px;object-fit:contain;vertical-align:middle;margin-right:4px" alt=""> DB entries for missing files will be permanently removed.
    </div>
    <div style="display:flex;gap:10px;justify-content:flex-end">
      <button class="btn btn-ghost btn-sm" onclick="hideIntegrityModal()">Cancel</button>
      <form id="integrityForm" method="POST" style="display:inline">
        <input type="hidden" name="_csrf" value="${csrfToken}">
        <button class="btn btn-primary btn-sm" type="submit">Run</button>
      </form>
    </div>
  </div>
</div>

<script nonce="${nonce}">
${sharedScript(csrfToken, theme)}
function showRemoveFolderModal(name){
    document.getElementById('removeFolderNameInput').value=name;
    document.getElementById('removeFolderName').textContent=name;
    document.getElementById('removeFolderFilesChk').checked=false;
    document.getElementById('removeFolderFilesHidden').checked=false;
    document.getElementById('removeFolderWarn').style.display='none';
    const m=document.getElementById('removeFolderModal');
    m.style.display='flex';m.onclick=e=>{if(e.target===m)hideRemoveFolderModal()};
}
function hideRemoveFolderModal(){document.getElementById('removeFolderModal').style.display='none'}
function onRemoveFolderChkChange(chk){
    document.getElementById('removeFolderFilesHidden').checked=chk.checked;
    document.getElementById('removeFolderWarn').style.display=chk.checked?'block':'none';
}
function showIntegrityModal(scope){
    const m=document.getElementById('integrityModal');
    const all=scope==='all';
    document.getElementById('integrityModalDesc').textContent=all
        ?'Scans all user file records and removes entries where the file no longer exists on disk.'
        :'Scans your file records and removes entries where the file no longer exists on disk.';
    document.getElementById('integrityForm').action=all?'/users/integrity-check':'/settings/integrity-check';
    m.style.display='flex';m.onclick=e=>{if(e.target===m)hideIntegrityModal()};
}
function hideIntegrityModal(){document.getElementById('integrityModal').style.display='none'}
</script>
</body></html>`;
}

function renderSettings({ username, apiKey, error, success, theme = 'dark', isAdmin = false, dateFmt = 'dmy', localUrl = null, uploadMaxBytes = '', csrfToken, nonce = '', uptime = '' }) {
    return `<!DOCTYPE html><html lang="en" data-theme="${theme}"><head>
<meta charset="UTF-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>Settings – SimpleSync Server</title>
${FAVICON_TAG}
<style>${BASE_STYLE}</style></head><body>
<div class="app">
${navSidebar('settings', csrfToken, theme, isAdmin)}
<div class="content-col">
  <div class="page-hdr">
    <span class="page-title">Settings</span>
    <div class="hdr-meta">
      <span class="badge">v1.2.2</span>
      ${uptime ? `<span class="badge"><img src="/static/stopwatch.png" style="width:13px;height:13px;object-fit:contain;vertical-align:middle;margin-right:3px" alt=""> ${uptime}</span>` : ''}
      <span>${escapeHtml(username)}</span>
    </div>
  </div>
  <div class="content-panel">
  <div class="wrap-narrow">
    ${error ? `<div class="err">${escapeHtml(error)}</div>` : ''}
    ${success ? `<div class="ok">✓ ${escapeHtml(success)}</div>` : ''}

    <div class="card section">
      <h3>Account</h3>
      <div class="form-group">
        <label>Username</label>
        <div style="background:var(--bg);border:1px solid var(--border);border-radius:8px;padding:10px 14px;color:var(--muted);font-size:.9rem">${escapeHtml(username)}</div>
      </div>
    </div>

    <div class="card section">
      <h3>Change Password</h3>
      <form method="POST" action="/settings/password">
        <input type="hidden" name="_csrf" value="${csrfToken}">
        <div class="form-group"><label>Current Password</label>
          <input type="password" name="current_password"></div>
        <div class="form-group"><label>New Password</label>
          <input type="password" name="new_password"></div>
        <div class="form-group"><label>Confirm New Password</label>
          <input type="password" name="confirm_password"></div>
        <button class="btn btn-primary btn-sm" type="submit">Change Password</button>
      </form>
    </div>

    ${isAdmin ? `
    <div class="card section">
      <h3>User Management</h3>
      <p style="color:var(--muted);font-size:.85rem;margin-bottom:14px">Create and manage user accounts, view security events and blocked IPs.</p>
      <a href="/users" class="btn btn-primary btn-sm">Open User Management</a>
    </div>
    ` : ''}
    ${!isAdmin ? `
    <div class="card section">
      <h3>API Key</h3>
      ${apiKey
        ? `<div class="ok" style="margin-bottom:12px">✓ Copy this key into the Android app now — it won't be shown again after you leave this page.</div>
           <div class="key-row">
             <span id="kv" style="font-family:monospace;font-size:.83rem;color:var(--accent2);flex:1;min-width:0;overflow-wrap:break-word;word-break:break-all">${apiKey}</span>
             <button type="button" class="btn btn-ghost btn-sm" onclick="copyKey()">Copy</button>
           </div>`
        : `<p style="color:var(--muted);font-size:.85rem;margin-bottom:12px">Key is stored as a hash and can't be shown again. Regenerate to get a new key.</p>`
      }
      <button type="button" class="btn btn-red btn-sm" style="margin-top:10px" onclick="showRegenModal()">Regenerate Key</button>
      <div id="regenModal" class="modal-overlay">
        <div class="modal-box">
          <div class="modal-title">Regenerate API Key?</div>
          <p style="color:var(--muted);font-size:.9rem;margin-bottom:20px">A new key will be generated. <strong style="color:var(--text)">You'll need to update the Android app with the new key.</strong></p>
          <div style="display:flex;gap:10px;justify-content:flex-end">
            <button class="btn btn-ghost btn-sm" onclick="hideRegenModal()">Cancel</button>
            <form method="POST" action="/settings/regen-key" style="display:inline">
              <input type="hidden" name="_csrf" value="${csrfToken}">
              <button class="btn btn-red btn-sm" type="submit">Yes, Regenerate</button>
            </form>
          </div>
        </div>
      </div>
    </div>

    <div class="card section">
      <h3><img src="/static/calendar.png" style="width:18px;height:18px;object-fit:contain;vertical-align:middle;margin-right:6px" alt="">Folder Date Format</h3>
      <p style="color:var(--muted);font-size:.85rem;margin-bottom:4px">Sets the subfolder name used when files sync. Today: <strong id="dateSample" style="color:var(--accent2)"></strong></p>
      <form method="POST" action="/settings/dateformat" id="datefmtForm" onsubmit="return checkUploadBeforeSubmit()" style="margin-top:14px">
        <input type="hidden" name="_csrf" value="${csrfToken}">
        <div style="display:flex;flex-direction:column;gap:10px;margin-bottom:14px">
          <label style="display:flex;align-items:center;gap:10px;cursor:pointer;font-size:.9rem">
            <input type="radio" name="date_format" value="dmy" ${dateFmt === 'dmy' ? 'checked' : ''} onchange="updateSample('dmy')">
            <span>DD.MM.YYYY <span style="color:var(--muted);font-size:.8rem">(e.g. 24.03.2025)</span></span>
          </label>
          <label style="display:flex;align-items:center;gap:10px;cursor:pointer;font-size:.9rem">
            <input type="radio" name="date_format" value="mdy" ${dateFmt === 'mdy' ? 'checked' : ''} onchange="updateSample('mdy')">
            <span>MM.DD.YYYY <span style="color:var(--muted);font-size:.8rem">(e.g. 03.24.2025)</span></span>
          </label>
        </div>
        <button type="submit" class="btn btn-primary btn-sm">Save</button>
      </form>
    </div>
    ` : `
    <div class="card section">
      <h3>Local Network URL</h3>
      <p style="color:var(--muted);font-size:.85rem;margin-bottom:14px">Direct LAN or Static IP address for large file uploads — bypasses Cloudflare's 100 MB limit.</p>
      <form method="POST" action="/settings/local-url">
        <input type="hidden" name="_csrf" value="${csrfToken}">
        <div class="form-group" style="margin-bottom:12px">
          <input type="url" name="local_url" value="${escapeHtml(localUrl || '')}" placeholder="e.g. http://192.168.1.100:8080" autocomplete="off" spellcheck="false">
        </div>
        <div style="display:flex;gap:8px">
          <button class="btn btn-primary btn-sm" type="submit">Save</button>
          ${localUrl ? `<button class="btn btn-ghost btn-sm" type="submit" name="clear_url" value="1">Clear</button>` : ''}
        </div>
      </form>
      ${localUrl ? `<p style="color:var(--muted);font-size:.8rem;margin-top:10px">App tries LAN/Static IP first, falls back to tunnel if unreachable.</p>` : ''}
    </div>

    <div class="card section">
      <h3>Upload Size Limit</h3>
      <p style="color:var(--muted);font-size:.85rem;margin-bottom:14px">Maximum file size allowed per upload.</p>
      <form method="POST" action="/settings/upload-limit">
        <input type="hidden" name="_csrf" value="${csrfToken}">
        <div class="form-group" style="margin-bottom:12px">
          <select name="upload_max_gb">
            ${[0,1,2,3,4,5,6,7,8,9,10,20,30,40,50,100].map(gb => {
                const bytes = gb * 1024 * 1024 * 1024;
                const sel = uploadMaxBytes === (gb === 0 ? '' : String(bytes));
                return `<option value="${gb}"${sel ? ' selected' : ''}>${gb === 0 ? 'Unlimited' : gb + ' GB'}</option>`;
            }).join('')}
          </select>
        </div>
        <button class="btn btn-primary btn-sm" type="submit">Save</button>
      </form>
    </div>
    `}
  </div>
  </div>
</div>
</div>
<div id="toast"></div>
<script nonce="${nonce}">
${sharedScript(csrfToken, theme)}
function copyKey(){
    const el=document.getElementById('kv');
    const v=el?(el.value||el.textContent||'').trim():'';
    if(!v){toast('No API key to copy');return;}
    navigator.clipboard.writeText(v).then(()=>toast('✓ API key copied!')).catch(()=>toast('Could not copy'));
}
function showRegenModal(){const m=document.getElementById('regenModal');m.style.display='flex';m.onclick=e=>{if(e.target===m)hideRegenModal()};}
function hideRegenModal(){document.getElementById('regenModal').style.display='none';}
function updateSample(fmt){
    const el=document.getElementById('dateSample');if(!el)return;
    const now=new Date(),dd=String(now.getDate()).padStart(2,'0'),mm=String(now.getMonth()+1).padStart(2,'0'),yyyy=String(now.getFullYear());
    el.textContent=fmt==='mdy'?mm+'.'+dd+'.'+yyyy:dd+'.'+mm+'.'+yyyy;
}
updateSample('${dateFmt}');
document.querySelectorAll('input[name="date_format"]').forEach(r=>r.addEventListener('change',function(){updateSample(this.value);}));
function checkUploadBeforeSubmit(){
    try{
        const xhr=new XMLHttpRequest();xhr.open('GET','/web/upload-status',false);xhr.send();
        if(xhr.status===200){
            const s=JSON.parse(xhr.responseText);
            if(s.active>0){alert('An upload is in progress — please wait.');return false;}
            if((Date.now()-s.lastUploadAt)/1000<15)return confirm('An upload just finished. Changing the format will rename today\\'s folder. Continue?');
        }
    }catch(e){}
    return true;
}
</script>
</body></html>`;
}

function renderUsersPage({ users, blocked = [], secEvents = [], theme = 'dark', error, success, csrfToken, nonce = '', uptime = '' }) {
    const userRows = users.map(u => {
        const isAdmin = u.is_admin === 1;
        const created = u.created_at ? u.created_at.split(' ')[0] : '—';
        return `
        <div class="folder-item" style="margin-bottom:10px">
            <div style="padding:12px 16px;background:var(--surface)">
                <div style="display:flex;align-items:center;gap:8px;flex-wrap:wrap">
                    ${ICON_USER}
                    <span style="font-weight:600;flex:1;min-width:0">${u.username}</span>
                    ${isAdmin ? '<span class="badge" style="color:var(--accent)">Admin</span>' : ''}
                    <span style="color:var(--muted);font-size:.8rem">Created ${created}</span>
                </div>
                ${!isAdmin ? `<div style="display:flex;gap:6px;margin-top:8px;flex-wrap:wrap">
                    <button class="btn btn-ghost btn-sm" onclick="showPwModal(${u.id},'${u.username}')">Change Password</button>
                    <button class="btn btn-red btn-sm" onclick="showDelModal(${u.id},'${u.username}')">Delete</button>
                </div>` : ''}
            </div>
        </div>`;
    }).join('');

    return `<!DOCTYPE html><html lang="en" data-theme="${theme}"><head>
<meta charset="UTF-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>User Management – SimpleSync Server</title>
${FAVICON_TAG}
<style>${BASE_STYLE}</style></head><body>
<div class="app">
${navSidebar('users', csrfToken, theme, true)}
<div class="content-col">
  <div class="page-hdr">
    <span class="page-title">User Management</span>
    <div class="hdr-meta">
      <span class="badge">v1.2.2</span>
      ${uptime ? `<span class="badge"><img src="/static/stopwatch.png" style="width:13px;height:13px;object-fit:contain;vertical-align:middle;margin-right:3px" alt=""> ${uptime}</span>` : ''}
      <span class="badge" style="color:var(--accent)">Admin</span>
    </div>
  </div>
  <div class="content-panel">
  <div class="wrap" style="max-width:860px">
    ${error ? `<div class="err">${escapeHtml(error)}</div>` : ''}
    ${success ? `<div class="ok">✓ ${escapeHtml(success)}</div>` : ''}

    <div class="grid2" style="margin-bottom:28px">
      <div class="card section">
        <h3>Create New User</h3>
        <form method="POST" action="/users/create">
          <input type="hidden" name="_csrf" value="${csrfToken}">
          <div class="form-group"><label>Username</label>
            <input type="text" name="username" placeholder="e.g. alice" maxlength="63" required autocomplete="off"></div>
          <div class="form-group"><label>Password</label>
            <input type="password" name="password" required autocomplete="new-password"></div>
          <div class="form-group"><label>Confirm Password</label>
            <input type="password" name="confirm_password" required autocomplete="new-password"></div>
          <button class="btn btn-primary btn-sm" type="submit">Create User</button>
        </form>
      </div>
      <div class="card section">
        <h3>About Users</h3>
        <p style="color:var(--muted);font-size:.85rem;line-height:1.6">
          Each user gets their own isolated API key, sync folders, and file storage.<br><br>
          Usernames <strong style="color:var(--text)">cannot be changed</strong> after creation.<br><br>
          The <strong style="color:var(--text)">admin</strong> account manages users only — it cannot upload or sync files.<br><br>
          Users log in at <code style="color:var(--accent2)">/login</code> and use their API key in the companion app.
        </p>
      </div>
    </div>

    <div class="section-title">All Users (${users.length})</div>
    ${userRows}

    <div class="section-title">Database Integrity Check</div>
    <div class="card section" style="margin-bottom:28px">
      <p style="color:var(--muted);font-size:.85rem;margin-bottom:14px">Scans all user file records and removes entries where the file no longer exists on disk.</p>
      <button class="btn btn-ghost btn-sm" type="button" onclick="showIntegrityModal('all')">Run Integrity Check (All Users)</button>
    </div>

    <div class="section-title">Recent Security Events (last 100)</div>
    ${secEvents.length === 0
      ? '<p style="color:var(--muted);font-size:.85rem;padding:10px 0 20px">No security events recorded yet.</p>'
      : `<div style="background:var(--surface);border:1px solid var(--border);border-radius:8px;overflow:hidden;margin-bottom:28px">
          <div style="overflow-y:auto;max-height:205px;-webkit-overflow-scrolling:touch">
          <table style="width:100%;border-collapse:collapse;font-size:.82rem">
            <thead><tr style="background:var(--surface2);position:sticky;top:0;z-index:1">
              <th style="padding:8px 12px;text-align:left;color:var(--muted);font-weight:600">Time</th>
              <th style="padding:8px 12px;text-align:left;color:var(--muted);font-weight:600">IP</th>
              <th style="padding:8px 12px;text-align:left;color:var(--muted);font-weight:600">Event</th>
            </tr></thead>
            <tbody>
            ${secEvents.map(e => `<tr style="border-top:1px solid var(--border)">
              <td style="padding:7px 12px;color:var(--muted);white-space:nowrap">${e.created_at.split('.')[0]}</td>
              <td style="padding:7px 12px;font-family:monospace;color:var(--text)">${escapeHtml(e.ip)}</td>
              <td style="padding:7px 12px;color:var(--text)">${escapeHtml(e.event)}</td>
            </tr>`).join('')}
            </tbody>
          </table>
          </div>
        </div>`
    }

    <div class="section-title">Blocked IPs (${blocked.length})</div>
    ${blocked.length === 0
      ? '<p style="color:var(--muted);font-size:.85rem;padding:10px 0 20px">No IPs are currently blocked.</p>'
      : blocked.map(b => `
        <div class="folder-item" style="margin-bottom:10px">
          <div class="folder-hdr" style="cursor:default">
            <span style="color:var(--red);font-size:.85rem">✕</span>
            <span style="font-weight:600;font-family:monospace;flex:1">${escapeHtml(b.ip)}</span>
            <span style="color:var(--muted);font-size:.8rem;margin-right:12px">Blocked ${b.blocked_at.split(' ')[0]}</span>
            <form method="POST" action="/users/unblock" style="display:inline">
              <input type="hidden" name="_csrf" value="${csrfToken}">
              <input type="hidden" name="ip" value="${escapeHtml(b.ip)}">
              <button class="btn btn-ghost btn-sm" type="submit" onclick="return confirm('Unblock ${escapeHtml(b.ip)}?')">Unblock</button>
            </form>
          </div>
        </div>`).join('')
    }
  </div>
  </div>
</div>
</div>
<div id="toast"></div>

<div id="delModal" class="modal-overlay">
  <div class="modal-box">
    <div class="modal-title">Delete User: <span id="delName" style="color:var(--accent)"></span></div>
    <p style="color:var(--muted);font-size:.88rem;margin-bottom:16px">The user account will be removed and they will no longer be able to log in or use the API.</p>
    <div style="background:var(--bg);border:1px solid var(--border);border-radius:8px;padding:14px;margin-bottom:16px">
      <p style="font-size:.82rem;font-weight:600;color:var(--text);margin-bottom:10px">What else should be deleted?</p>
      <label style="display:flex;align-items:flex-start;gap:10px;cursor:pointer;margin-bottom:10px">
        <input type="checkbox" id="chkDb" name="delete_db" value="on" style="margin-top:2px;accent-color:var(--accent)">
        <span>
          <span style="font-size:.88rem;color:var(--text);font-weight:600">Database records</span><br>
          <span style="font-size:.78rem;color:var(--muted)">Removes all folder configs and upload history. Files on disk are kept.</span>
        </span>
      </label>
      <label style="display:flex;align-items:flex-start;gap:10px;cursor:pointer">
        <input type="checkbox" id="chkFiles" name="delete_files" value="on" style="margin-top:2px;accent-color:var(--red)">
        <span>
          <span style="font-size:.88rem;color:var(--red);font-weight:600">Files on disk</span><br>
          <span style="font-size:.78rem;color:var(--muted)">Permanently deletes all uploaded files. Also deletes database records.</span>
        </span>
      </label>
    </div>
    <div id="delWarn" style="display:none;background:rgba(255,107,107,.1);border:1px solid rgba(255,107,107,.35);border-radius:8px;padding:10px 14px;font-size:.82rem;color:var(--red);margin-bottom:14px">
      <img src="/static/alert.png" style="width:14px;height:14px;object-fit:contain;vertical-align:middle;margin-right:4px" alt=""> This cannot be undone.
    </div>
    <div style="display:flex;gap:10px;justify-content:flex-end">
      <button class="btn btn-ghost btn-sm" onclick="hideDelModal()">Cancel</button>
      <form id="delForm" method="POST" action="/users/delete" style="display:inline">
        <input type="hidden" name="_csrf" value="${csrfToken}">
        <input type="hidden" id="delUserId" name="user_id" value="">
        <button class="btn btn-red btn-sm" type="submit">Delete User</button>
      </form>
    </div>
  </div>
</div>

<div id="pwModal" class="modal-overlay">
  <div class="modal-box">
    <div class="modal-title">Change Password for <span id="pwName" style="color:var(--accent)"></span></div>
    <form method="POST" action="/users/change-password">
      <input type="hidden" name="_csrf" value="${csrfToken}">
      <input type="hidden" id="pwUserId" name="user_id" value="">
      <div class="form-group"><label>New Password</label>
        <input type="password" name="new_password" id="pwInput" required autocomplete="new-password"></div>
      <div class="form-group"><label>Confirm Password</label>
        <input type="password" name="confirm_password" required autocomplete="new-password"></div>
      <div style="display:flex;gap:10px;justify-content:flex-end;margin-top:8px">
        <button type="button" class="btn btn-ghost btn-sm" onclick="hidePwModal()">Cancel</button>
        <button type="submit" class="btn btn-primary btn-sm">Update Password</button>
      </div>
    </form>
  </div>
</div>

<div id="integrityModal" class="modal-overlay">
  <div class="modal-box">
    <div class="modal-title">Run Integrity Check</div>
    <p id="integrityModalDesc" style="color:var(--muted);font-size:.88rem;margin-bottom:16px"></p>
    <div style="background:rgba(255,107,107,.08);border:1px solid rgba(255,107,107,.3);border-radius:8px;padding:10px 14px;font-size:.82rem;color:var(--red);margin-bottom:20px">
      <img src="/static/alert.png" style="width:14px;height:14px;object-fit:contain;vertical-align:middle;margin-right:4px" alt=""> DB entries for missing files will be permanently removed.
    </div>
    <div style="display:flex;gap:10px;justify-content:flex-end">
      <button class="btn btn-ghost btn-sm" onclick="hideIntegrityModal()">Cancel</button>
      <form id="integrityForm" method="POST" style="display:inline">
        <input type="hidden" name="_csrf" value="${csrfToken}">
        <button class="btn btn-primary btn-sm" type="submit">Run</button>
      </form>
    </div>
  </div>
</div>

<script nonce="${nonce}">
${sharedScript(csrfToken, theme)}
function showDelModal(id,name){
    document.getElementById('delUserId').value=id;
    document.getElementById('delName').textContent=name;
    document.getElementById('chkDb').checked=false;
    document.getElementById('chkFiles').checked=false;
    document.getElementById('delWarn').style.display='none';
    const m=document.getElementById('delModal');m.style.display='flex';m.onclick=e=>{if(e.target===m)hideDelModal()};
}
function hideDelModal(){document.getElementById('delModal').style.display='none'}
document.addEventListener('DOMContentLoaded',function(){
    const chkDb=document.getElementById('chkDb'),chkFiles=document.getElementById('chkFiles'),w=document.getElementById('delWarn');
    function upd(){if(w)w.style.display=(chkDb&&chkDb.checked)||(chkFiles&&chkFiles.checked)?'block':'none';}
    if(chkFiles)chkFiles.addEventListener('change',function(){if(this.checked&&chkDb)chkDb.checked=true;upd();});
    if(chkDb)chkDb.addEventListener('change',function(){if(!this.checked&&chkFiles)chkFiles.checked=false;upd();});
});
function showPwModal(id,name){
    document.getElementById('pwUserId').value=id;
    document.getElementById('pwName').textContent=name;
    document.getElementById('pwInput').value='';
    const m=document.getElementById('pwModal');m.style.display='flex';m.onclick=e=>{if(e.target===m)hidePwModal()};
    setTimeout(()=>document.getElementById('pwInput').focus(),50);
}
function hidePwModal(){document.getElementById('pwModal').style.display='none'}
function showIntegrityModal(scope){
    const m=document.getElementById('integrityModal');
    const all=scope==='all';
    document.getElementById('integrityModalDesc').textContent=all
        ?'Scans all user file records and removes entries where the file no longer exists on disk.'
        :'Scans your file records and removes entries where the file no longer exists on disk.';
    document.getElementById('integrityForm').action=all?'/users/integrity-check':'/settings/integrity-check';
    m.style.display='flex';m.onclick=e=>{if(e.target===m)hideIntegrityModal()};
}
function hideIntegrityModal(){document.getElementById('integrityModal').style.display='none'}
</script>
</body></html>`;
}


module.exports = { renderLogin, renderChangePassword, renderDashboard, renderSettings, renderUsersPage };
