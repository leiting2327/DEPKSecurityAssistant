const { app, BrowserWindow, Menu, shell, dialog, ipcMain } = require('electron');
const path = require('path');
const fs = require('fs');
const fsp = fs.promises;
const os = require('os');
const crypto = require('crypto');
const { execFile } = require('child_process');
const DEPKEngine = require('./engine-shared.js');

app.setName('DEPK Security Assistant');

const INSTALL_DIR = process.env.LOCALAPPDATA
  ? path.join(process.env.LOCALAPPDATA, 'DEPKSecurityAssistant')
  : path.join(os.homedir(), 'AppData', 'Local', 'DEPKSecurityAssistant');
const INSTALLED_EXE = 'DEPKSecurityAssistant.exe';
function isSetupMode() {
  if (process.argv.includes('--app')) return false;
  if (process.argv.includes('--setup')) return true;
  const exeDir = path.dirname(process.execPath);
  if (fs.existsSync(path.join(exeDir, '.portable'))) return false;
  if (fs.existsSync(path.join(exeDir, '.depkinstalled'))) return false; // 已安装位置 → 直接主程序
  return exeDir.toLowerCase() !== INSTALL_DIR.toLowerCase();
}

let win = null;
const SETUP = isSetupMode();
const QUAR_DIR = path.join(os.homedir(), 'DEPKSecurity', 'Quarantine');
const META_FILE = path.join(QUAR_DIR, 'meta.json');
const WATCHED = {};   // dir -> fs.FSWatcher

/* ---------- 工具 ---------- */
function runPs(script) {
  return new Promise((resolve) => {
    const args = ['-NoProfile', '-NonInteractive', '-ExecutionPolicy', 'Bypass', '-Command', script];
    execFile('powershell.exe', args, { timeout: 20000, maxBuffer: 16 * 1024 * 1024, windowsHide: true }, (err, stdout) => {
      resolve(err ? { ok: false, err: String(err && err.message || err), out: stdout || '' } : { ok: true, out: stdout || '' });
    });
  });
}
function jsonOut(script) { // powershell -> ConvertTo-Json -Compress
  return runPs(`${script} | ConvertTo-Json -Depth 5 -Compress`).then(r => {
    if (!r.ok) return { ok: false, err: r.err };
    try { return { ok: true, data: JSON.parse(r.out) }; } catch (e) { return { ok: true, data: null, raw: r.out }; }
  });
}
async function loadMeta() {
  try { return JSON.parse(await fsp.readFile(META_FILE, 'utf8')); } catch (e) { return []; }
}
async function saveMeta(list) {
  await fsp.mkdir(QUAR_DIR, { recursive: true });
  await fsp.writeFile(META_FILE, JSON.stringify(list, null, 1), 'utf8');
}

/* ---------- IPC：真实系统能力 ---------- */
ipcMain.handle('depk:scanDir', async (e, root) => {
  const rootPath = String(root || os.homedir());
  const out = { root: rootPath, files: 0, threats: [], errors: 0, start: Date.now() };
  const MAX = 6000;
  async function walk(dir, depth) {
    if (out.files >= MAX || depth > 14) return;
    let entries;
    try { entries = await fsp.readdir(dir, { withFileTypes: true }); } catch (err) { out.errors++; return; }
    for (const ent of entries) {
      if (out.files >= MAX) return;
      const full = path.join(dir, ent.name);
      try {
        if (ent.isDirectory()) {
          if (ent.name === '$RECYCLE.BIN' || ent.name === 'System Volume Information') continue;
          await walk(full, depth + 1);
        } else if (ent.isFile()) {
          const st = await fsp.stat(full);
          if (st.size > 200 * 1024 * 1024) continue; // 跳过超大文件
          let head;
          try {
            const fh = await fsp.open(full, 'r');
            const buf = Buffer.alloc(Math.min(st.size, 4 * 1024 * 1024));
            await fh.read(buf, 0, buf.length, 0);
            await fh.close();
            head = new Uint8Array(buf);
          } catch (err) { out.errors++; continue; }
          const res = DEPKEngine.analyzeBuf(head, ent.name);
          out.files++;
          if (res.verdict !== '无威胁' && res.sev !== 'low') {
            out.threats.push({ name: ent.name, path: full, size: st.size, verdict: res.verdict, sev: res.sev, score: res.score, rules: res.rules.map(r => r.name), entropy: +res.entropy.toFixed(2), time: Date.now() });
          }
        }
      } catch (err) { out.errors++; }
    }
  }
  await walk(rootPath, 0);
  out.dur = ((Date.now() - out.start) / 1000).toFixed(1) + ' 秒';
  return out;
});

ipcMain.handle('depk:getDrives', async () => {
  const r = await jsonOut('Get-CimInstance Win32_LogicalDisk | Select-Object DeviceID,DriveType,VolumeName,Size,FreeSpace,FileSystem');
  if (!r.ok) return { ok: false, err: r.err };
  return { ok: true, data: (r.data || []).map(d => ({
    letter: d.DeviceID, type: d.DriveType === 2 ? '可移动' : d.DriveType === 3 ? '本地' : d.DriveType === 4 ? '网络' : '其他',
    name: d.VolumeName || '', size: d.Size || 0, free: d.FreeSpace || 0, fs: d.FileSystem || ''
  })) };
});

ipcMain.handle('depk:getProcesses', async () => {
  const r = await jsonOut("Get-Process | Select-Object Id,ProcessName,CPU,WorkingSet64,Path,StartTime | Sort-Object WorkingSet64 -Descending | Select-Object -First 120");
  if (!r.ok) return { ok: false, err: r.err };
  return { ok: true, data: (r.data || []).map(p => ({
    pid: p.Id, name: p.ProcessName, cpu: p.CPU != null ? +p.CPU.toFixed(1) : null,
    mem: p.WorkingSet64 || 0, path: p.Path || '', start: p.StartTime ? new Date(p.StartTime).toLocaleString('zh-CN') : ''
  })) };
});
ipcMain.handle('depk:killProcess', async (e, pid) => {
  const r = await runPs(`Stop-Process -Id ${Number(pid)} -Force -ErrorAction Stop`);
  return { ok: r.ok, err: r.err };
});

ipcMain.handle('depk:getStartup', async () => {
  const script = [
    "Get-ItemProperty 'HKCU:\\Software\\Microsoft\\Windows\\CurrentVersion\\Run' | Select-Object -Property * -ExcludeProperty PS*",
    "Get-ItemProperty 'HKLM:\\Software\\Microsoft\\Windows\\CurrentVersion\\Run' | Select-Object -Property * -ExcludeProperty PS*"
  ].join(';');
  const r = await runPs(script);
  if (!r.ok) return { ok: false, err: r.err };
  const items = [];
  for (const line of r.out.split(/\r?\n/)) {
    const m = line.match(/^(\w+)\s+:\s+(.+)$/);
    if (m) items.push({ name: m[1], command: m[2].trim(), hive: /^HKCU/.test(line) ? 'HKCU' : 'HKLM' });
  }
  return { ok: true, data: items };
});

ipcMain.handle('depk:getSysInfo', async () => {
  const r = await jsonOut("Get-CimInstance Win32_OperatingSystem | Select-Object Caption,Version,BuildNumber,OSArchitecture,TotalVisibleMemorySize,FreePhysicalMemory,LastBootUpTime; Get-CimInstance Win32_ComputerSystem | Select-Object Manufacturer,Model,TotalPhysicalMemory,NumberOfProcessors; Get-CimInstance Win32_Processor | Select-Object Name,NumberOfCores,NumberOfLogicalProcessors");
  const osInfo = Array.isArray(r.data) ? r.data[0] : (r.data && r.data[0]) || {};
  const sysInfo = Array.isArray(r.data) ? r.data[1] : (r.data && r.data[1]) || {};
  const cpuInfo = Array.isArray(r.data) ? r.data[2] : (r.data && r.data[2]) || {};
  return { ok: true, data: {
    osName: osInfo.Caption || os.platform(), osVer: osInfo.Version || '', build: osInfo.BuildNumber || '',
    arch: osInfo.OSArchitecture || os.arch(), hostname: os.hostname(), user: os.userInfo().username,
    totalMem: (osInfo.TotalVisibleMemorySize || 0) * 1024, freeMem: (osInfo.FreePhysicalMemory || 0) * 1024,
    boot: osInfo.LastBootUpTime ? new Date(osInfo.LastBootUpTime).toLocaleString('zh-CN') : '',
    manufacturer: sysInfo.Manufacturer || '', model: sysInfo.Model || '',
    cpu: cpuInfo.Name || os.cpus()[0].model, cores: cpuInfo.NumberOfCores || os.cpus().length,
    threads: cpuInfo.NumberOfLogicalProcessors || os.cpus().length,
    uptime: Math.floor(os.uptime() / 3600)
  } };
});

ipcMain.handle('depk:getNetConns', async () => {
  const r = await runPs('Get-NetTCPConnection -ErrorAction SilentlyContinue | Where-Object {$_.State -ne "Listen"} | Select-Object -First 80 LocalAddress,LocalPort,RemoteAddress,RemotePort,State,OwningProcess');
  if (!r.ok) return { ok: false, err: r.err };
  const rows = [];
  for (const line of r.out.split(/\r?\n/)) {
    const m = line.match(/^(\S+)\s+(\d+)\s+(\S+)\s+(\d+)\s+(\w+)\s+(\d+)$/);
    if (m) rows.push({ local: m[1] + ':' + m[2], remote: m[3] + ':' + m[4], state: m[5], pid: m[6] });
  }
  return { ok: true, data: rows };
});

ipcMain.handle('depk:getSoftware', async () => {
  const script = "Get-ItemProperty 'HKLM:\\Software\\Microsoft\\Windows\\CurrentVersion\\Uninstall\\*','HKLM:\\Software\\Wow6432Node\\Microsoft\\Windows\\CurrentVersion\\Uninstall\\*','HKCU:\\Software\\Microsoft\\Windows\\CurrentVersion\\Uninstall\\*' -ErrorAction SilentlyContinue | Where-Object {$_.DisplayName} | Select-Object DisplayName,DisplayVersion,Publisher,InstallDate,EstimatedSize,UninstallString,QuietUninstallString,InstallLocation,DisplayIcon,PSChildName | ConvertTo-Json -Depth 3 -Compress";
  const r = await jsonOut(script);
  if (!r.ok) return { ok: false, err: r.err };
  const list = (r.data || []).map(p => ({
    name: p.DisplayName, version: p.DisplayVersion || '', publisher: p.Publisher || '',
    date: p.InstallDate || '', sizeKB: Number(p.EstimatedSize) || 0,
    uninstall: p.UninstallString || '', quiet: p.QuietUninstallString || '',
    location: p.InstallLocation || '', icon: p.DisplayIcon || '', key: p.PSChildName || ''
  })).filter(x => x.name);
  const seen = new Set(); const uniq = list.filter(x => { const k = x.name.toLowerCase(); if (seen.has(k)) return false; seen.add(k); return true; });
  return { ok: true, data: uniq, count: uniq.length };
});
ipcMain.handle('depk:getFirewallRules', async () => {
  const r = await runPs("Get-NetFirewallRule -ErrorAction SilentlyContinue | Where-Object {$_.Enabled -eq 'True'} | Select-Object -First 60 DisplayName,Direction,Action,Profile");
  if (!r.ok) return { ok: false, err: r.err };
  const rows = [];
  for (const line of r.out.split(/\r?\n/)) {
    const m = line.match(/^(\S[\S\s]*?)\s+(Inbound|Outbound)\s+(Allow|Block)\s+(\w+)$/);
    if (m) rows.push({ name: m[1].trim(), dir: m[2] === 'Inbound' ? '入站' : '出站', act: m[3] === 'Allow' ? '允许' : '阻止', profile: m[4] });
  }
  return { ok: true, data: rows };
});

/* ---------- 真实隔离区（文件移动 + 元数据） ---------- */
ipcMain.handle('depk:quarantine', async (e, { path: src, verdict }) => {
  try {
    await fsp.mkdir(QUAR_DIR, { recursive: true });
    const id = 'RQ-' + Date.now().toString(36).toUpperCase() + Math.floor(Math.random() * 900 + 100);
    const dest = path.join(QUAR_DIR, id + path.extname(src));
    await fsp.rename(src, dest);
    const meta = await loadMeta();
    const st = await fsp.stat(dest);
    meta.unshift({ id, name: path.basename(src), origPath: src, path: dest, size: st.size, verdict, time: Date.now() });
    await saveMeta(meta);
    return { ok: true, id };
  } catch (err) { return { ok: false, err: String(err.message || err) }; }
});
ipcMain.handle('depk:listQ', async () => { return { ok: true, data: await loadMeta() }; });
ipcMain.handle('depk:restoreQ', async (e, id) => {
  try {
    const meta = await loadMeta();
    const it = meta.find(x => x.id === id);
    if (!it) return { ok: false, err: '未找到隔离记录' };
    await fsp.mkdir(path.dirname(it.origPath), { recursive: true });
    await fsp.rename(it.path, it.origPath);
    await saveMeta(meta.filter(x => x.id !== id));
    return { ok: true };
  } catch (err) { return { ok: false, err: String(err.message || err) }; }
});
ipcMain.handle('depk:deleteQ', async (e, id) => {
  try {
    const meta = await loadMeta();
    const it = meta.find(x => x.id === id);
    if (it) await fsp.rm(it.path, { force: true });
    await saveMeta(meta.filter(x => x.id !== id));
    return { ok: true };
  } catch (err) { return { ok: false, err: String(err.message || err) }; }
});

/* ---------- 实时文件监控（fs.watch） ---------- */
ipcMain.handle('depk:watchStart', async (e, dirs) => {
  try { for (const w of Object.values(WATCHED)) w.close(); Object.keys(WATCHED).forEach(k => delete WATCHED[k]); } catch (err) {}
  const defaults = ['Downloads', 'Desktop', 'Documents'].map(d => path.join(os.homedir(), d));
  const targets = (dirs && dirs.length) ? dirs : defaults;
  for (const dir of targets) {
    if (!dir || !fs.existsSync(dir)) continue;
    try {
      WATCHED[dir] = fs.watch(dir, { recursive: true }, (evt, fname) => {
        if (win && !win.isDestroyed()) win.webContents.send('depk:watchEvent', { dir, evt, file: String(fname || ''), time: Date.now() });
      });
    } catch (err) { return { ok: false, err: '无法监控 ' + dir + '：' + String(err.message || err) }; }
  }
  return { ok: true, watched: Object.keys(WATCHED) };
});
ipcMain.handle('depk:watchStop', async () => {
  for (const w of Object.values(WATCHED)) w.close();
  Object.keys(WATCHED).forEach(k => delete WATCHED[k]);
  return { ok: true };
});

/* ---------- 窗口 ---------- */
function createWindow() {
  win = new BrowserWindow({
    width: SETUP ? 1000 : 1500, height: SETUP ? 720 : 930,
    minWidth: SETUP ? 900 : 1060, minHeight: SETUP ? 640 : 700,
    title: SETUP ? 'DEPK Security Assistant - 安装向导' : 'DEPK Security Assistant',
    icon: path.join(__dirname, 'build', 'icon.ico'),
    backgroundColor: '#202020', show: false,
    frame: !SETUP, autoHideMenuBar: true, resizable: !SETUP,
    webPreferences: {
      contextIsolation: true, nodeIntegration: false, sandbox: false,
      preload: path.join(__dirname, 'preload.js')
    }
  });
  win.loadFile(SETUP ? 'installer.html' : 'index.html');
  win.once('ready-to-show', () => win.show());
  win.on('closed', () => { win = null; });
  win.webContents.setWindowOpenHandler(({ url }) => {
    if (/^https?:/i.test(url)) shell.openExternal(url);
    return { action: 'deny' };
  });
}
Menu.setApplicationMenu(null);
app.whenReady().then(() => { createWindow(); app.on('activate', () => { if (BrowserWindow.getAllWindows().length === 0) createWindow(); }); });
app.on('window-all-closed', () => { if (process.platform !== 'darwin') app.quit(); });
if (SETUP) {
  ipcMain.on('win:min', () => { if (win) win.minimize(); });
  ipcMain.on('win:close', () => { if (win) win.close(); });
  ipcMain.on('win:max', () => { if (win) win.isMaximized() ? win.unmaximize() : win.maximize(); });
}
/* ---------- 动态沙盒（真实受限运行样本并采集行为） ---------- */
const DYN_SANDBOX_PS = 'param([string]$Sample,[int]$Seconds=10)\n$ErrorActionPreference=\'Continue\'\n$tmp = Join-Path $env:TEMP ("DEPKSandbox_" + [guid]::NewGuid().ToString(\'N\'))\nNew-Item -ItemType Directory -Path $tmp -Force | Out-Null\nCopy-Item -LiteralPath $Sample -Destination $tmp -Force\n$target = Join-Path $tmp (Split-Path $Sample -Leaf)\n$base = @(Get-ChildItem $tmp -Recurse -File -ErrorAction SilentlyContinue | ForEach-Object FullName)\n$baseConns = @(Get-NetTCPConnection -ErrorAction SilentlyContinue | Where-Object {$_.RemoteAddress -notmatch \'^(127\\.|::1|0\\.0\\.0\\.0|10\\.|192\\.168\\.|172\\.(1[6-9]|2\\d|3[01])\\.)\'} | ForEach-Object {"$($_.RemoteAddress):$($_.RemotePort)"})\n$report = @{procs=@();files=@();conns=@();events=@()}\n$p = $null\ntry {\n  $p = Start-Process -FilePath $target -WorkingDirectory $tmp -WindowStyle Hidden -PassThru -ErrorAction Stop\n  $report.events += @("样本已启动 - " + (Split-Path $Sample -Leaf))\n} catch { $report.events += @("启动失败: $($_.Exception.Message)") }\nif($p){\n  $started = Get-Date\n  $procIds = @($p.Id)\n  $seen = @{}\n  while((Get-Date) -lt $started.AddSeconds($Seconds) -and -not $p.HasExited){\n    Start-Sleep -Milliseconds 600\n    try {\n      Get-CimInstance Win32_Process -ErrorAction SilentlyContinue | Where-Object {$_.ParentProcessId -in $procIds} | ForEach-Object {\n        if(-not $seen[$_.ProcessId]){ $seen[$_.ProcessId]=$true; $report.procs += @([pscustomobject]@{pid=$_.ProcessId;name=$_.Name;path=$_.ExecutablePath;parent=$_.ParentProcessId;time=(Get-Date).ToString(\'HH:mm:ss\')}); $procIds += $_.ProcessId }\n      }\n    } catch {}\n    try {\n      Get-NetTCPConnection -ErrorAction SilentlyContinue | Where-Object {$_.OwningProcess -in $procIds -and $_.RemoteAddress -notmatch \'^(127\\.|::1|0\\.0\\.0\\.0|10\\.|192\\.168\\.|172\\.(1[6-9]|2\\d|3[01])\\.)\'} | ForEach-Object {\n        $k = "$($_.RemoteAddress):$($_.RemotePort)"\n        if($k -notin $baseConns -and $report.conns -notcontains $k){ $report.conns += $k }\n      }\n    } catch {}\n  }\n  try { cmd /c "taskkill /T /F /PID $($p.Id)" 2>$null | Out-Null } catch {}\n  try { Stop-Process -Id $p.Id -Force -ErrorAction SilentlyContinue } catch {}\n  Start-Sleep -Milliseconds 400\n  $after = @(Get-ChildItem $tmp -Recurse -File -ErrorAction SilentlyContinue | ForEach-Object FullName)\n  $report.files = @($after | Where-Object {$_ -notin $base})\n  $report.events += @("样本已运行 $Seconds 秒，进程树已强制终止")\n}\ntry { Remove-Item $tmp -Recurse -Force -ErrorAction SilentlyContinue } catch {}\n$report | ConvertTo-Json -Depth 5 -Compress';
ipcMain.handle('depk:dynSandbox', async (e, { path: sample, seconds }) => {
  const SECONDS = Math.min(Math.max(Number(seconds) || 8, 3), 30);
  if (!sample || !fs.existsSync(sample)) return { ok: false, err: '样本文件不存在' };
  const psPath = path.join(os.tmpdir(), 'depk_dynsandbox_' + Date.now() + '.ps1');
  let report = { ok: false, err: '未知错误' };
  try {
    await fsp.writeFile(psPath, DYN_SANDBOX_PS, 'utf8');
    const r = await runPs(`& '${psPath}' '${sample.replace(/'/g, "''")}' ${SECONDS}`);
    if (r.ok && r.out.trim()) {
      const start = r.out.indexOf('{'); const end = r.out.lastIndexOf('}');
      const json = start >= 0 && end > start ? r.out.slice(start, end + 1) : r.out.trim();
      report = JSON.parse(json); report.ok = true;
    } else report = { ok: false, err: r.err || '无输出' };
  } catch (err) { report = { ok: false, err: String(err.message || err) }; }
  finally { try { await fsp.rm(psPath, { force: true }); } catch (e3) {} }
  return report;
});
ipcMain.handle('depk:pickFile', async () => {
  const { dialog } = require('electron');
  const r = await dialog.showOpenDialog(win, { properties: ['openFile'], title: '选择要分析的样本文件' });
  if (r.canceled || !r.filePaths.length) return { ok: false, canceled: true };
  return { ok: true, path: r.filePaths[0] };
});

/* =====================================================
   安装向导（--setup 模式）：安装 / 卸载 / 开机抢先启动
   ===================================================== */
const setupApi = { ok: false, err: 'setup 未初始化' };

function sendSetupProgress(done, total, file) {
  if (win && !win.isDestroyed()) win.webContents.send('setup:progress', { done, total, file });
}
async function countFiles(dir) {
  let n = 0;
  for (const e of await fsp.readdir(dir, { withFileTypes: true })) {
    if (e.isDirectory()) n += await countFiles(path.join(dir, e.name)); else n++;
  }
  return n;
}
async function copyTree(src, dst, onFile) {
  await fsp.mkdir(dst, { recursive: true });
  for (const e of await fsp.readdir(src, { withFileTypes: true })) {
    const s = path.join(src, e.name), d = path.join(dst, e.name);
    if (e.isDirectory()) await copyTree(s, d, onFile);
    else { await fsp.copyFile(s, d); onFile && onFile(d); }
  }
}
async function psExec(script) {
  return new Promise((resolve) => {
    execFile('powershell.exe', ['-NoProfile', '-NonInteractive', '-ExecutionPolicy', 'Bypass', '-Command', script],
      { timeout: 30000, windowsHide: true }, (err, stdout) => resolve({ ok: !err, err: err ? String(err.message || err) : '' }));
  });
}
function createShortcut(lnkPath, target, args, desc, icon) {
  const q = s => "'" + String(s).replace(/'/g, "''") + "'";
  return psExec(`$ws=New-Object -ComObject WScript.Shell; $s=$ws.CreateShortcut(${q(lnkPath)}); $s.TargetPath=${q(target)}; $s.Arguments=${q(args || '')}; $s.Description=${q(desc || '')}; $s.IconLocation=${q(icon || target + ',0')}; $s.Save()`);
}

if (SETUP) {
  ipcMain.handle('setup:getStatus', async () => {
    const exeDir = path.dirname(process.execPath);
    const here = fs.existsSync(path.join(exeDir, '.depkinstalled'));
    const dflt = fs.existsSync(path.join(INSTALL_DIR, '.depkinstalled'));
    const dir = here ? exeDir : (dflt ? INSTALL_DIR : '');
    return { installed: !!dir, dir, exePath: dir ? path.join(dir, INSTALLED_EXE) : path.join(INSTALL_DIR, INSTALLED_EXE) };
  });

  ipcMain.handle('setup:pickDir', async () => {
    const r = await dialog.showOpenDialog(win || undefined, {
      title: '选择 DEPK Security Assistant 安装位置',
      buttonLabel: '选择此文件夹',
      properties: ['openDirectory', 'createDirectory']
    });
    return r.canceled ? null : r.filePaths[0];
  });

  ipcMain.handle('setup:install', async (e, { dir, autostart }) => {
    try {
      const target = String(dir || INSTALL_DIR);
      const src = path.dirname(process.execPath);
      // 防护：安装目录不能等于安装包所在目录（否则复制到自身，Windows 会报 ENOENT）
      if (path.resolve(target).toLowerCase() === path.resolve(src).toLowerCase()) {
        return { ok: false, err: '安装位置与安装包所在目录相同，请选择其他文件夹（如 D:\\DEPKSecurityAssistant）' };
      }
      await fsp.mkdir(target, { recursive: true });
      // 先关闭已运行的旧版本（避免文件被占用导致覆盖失败），但保留本次安装向导自身
      await psExec(`Get-Process DEPKSecurityAssistant -ErrorAction SilentlyContinue | Where-Object { $_.Id -ne ${process.pid} } | Stop-Process -Force -ErrorAction SilentlyContinue`);
      const total = await countFiles(src);
      let done = 0;
      await copyTree(src, target, (f) => {
        done++; if (done % 3 === 0 || done === total) sendSetupProgress(done, total, path.basename(f));
      });
      // 已安装标记：安装到任意路径都能识别为"已安装位置"，下次双击直接进主程序
      await fsp.writeFile(path.join(target, '.depkinstalled'), 'DEPK Security Assistant installed\n', 'utf8');
      // 安装后的 exe 使用固定名称（Setup 文件名可任意）
      const exe = path.join(target, INSTALLED_EXE);
      if (path.basename(process.execPath).toLowerCase() !== INSTALLED_EXE.toLowerCase()) {
        await fsp.copyFile(process.execPath, exe);
        await fsp.rm(path.join(target, path.basename(process.execPath)), { force: true });
      }
      sendSetupProgress(total, total, '完成');
      // 快捷方式
      const sm = path.join(process.env.APPDATA || '', 'Microsoft', 'Windows', 'Start Menu', 'Programs');
      await createShortcut(path.join(sm, 'DEPK Security Assistant.lnk'), exe, '', 'DEPK Security Assistant - 终端安全防护', exe);
      await createShortcut(path.join(os.homedir(), 'Desktop', 'DEPK Security Assistant.lnk'), exe, '', 'DEPK Security Assistant', exe);
      // 注册表（卸载项 + Run 键）
      const unreg = 'HKCU:\\Software\\Microsoft\\Windows\\CurrentVersion\\Uninstall\\DEPKSecurityAssistant';
      await psExec(`New-Item -Path ${unreg} -Force | Out-Null; Set-ItemProperty ${unreg} DisplayName 'DEPK Security Assistant'; Set-ItemProperty ${unreg} DisplayVersion '3.4.216'; Set-ItemProperty ${unreg} Publisher 'DEPK Security'; Set-ItemProperty ${unreg} DisplayIcon '${exe}',0; Set-ItemProperty ${unreg} InstallLocation '${target}'; Set-ItemProperty ${unreg} UninstallString '\"${exe}\" --setup'`);
      // 开机抢先启动：计划任务（登录触发 + 高优先级） + Run 键双保险
      if (autostart) {
        await psExec(`$a=New-ScheduledTaskAction -Execute '${exe}' -Argument '--app'; $t=New-ScheduledTaskTrigger -AtLogOn; $s=New-ScheduledTaskSettingsSet -Priority 4 -ExecutionTimeLimit ([TimeSpan]::Zero) -AllowStartIfOnBatteries; Register-ScheduledTask -TaskName 'DEPKSecurityGuard' -Action $a -Trigger $t -Settings $s -Force | Out-Null`);
        await psExec(`Set-ItemProperty 'HKCU:\\Software\\Microsoft\\Windows\\CurrentVersion\\Run' DEPKSecurityAssistant '\"${exe}\" --app'`);
      }
      return { ok: true };
    } catch (err) { return { ok: false, err: String(err.message || err) }; }
  });

  ipcMain.handle('setup:launchInstalled', async () => {
    const exe = path.join(INSTALL_DIR, INSTALLED_EXE);
    try { execFile(exe, ['--app'], { detached: true, stdio: 'ignore' }).unref(); } catch (e) {}
    setTimeout(() => { if (win) win.close(); }, 400);
    return { ok: true };
  });

  ipcMain.handle('setup:uninstall', async (e, { dir } = {}) => {
    try {
      const target = String(dir || INSTALL_DIR);
      await psExec(`taskkill /F /IM DEPKSecurityAssistant.exe 2>$null | Out-Null`);
      await psExec(`Remove-Item -LiteralPath '${path.join(os.homedir(), 'Desktop', 'DEPK Security Assistant.lnk')}' -Force -ErrorAction SilentlyContinue`);
      await psExec(`Remove-Item -LiteralPath '${path.join(process.env.APPDATA || '', 'Microsoft', 'Windows', 'Start Menu', 'Programs', 'DEPK Security Assistant.lnk')}' -Force -ErrorAction SilentlyContinue`);
      await psExec(`Remove-Item 'HKCU:\\Software\\Microsoft\\Windows\\CurrentVersion\\Uninstall\\DEPKSecurityAssistant' -Recurse -Force -ErrorAction SilentlyContinue`);
      await psExec(`Remove-ItemProperty 'HKCU:\\Software\\Microsoft\\Windows\\CurrentVersion\\Run' DEPKSecurityAssistant -ErrorAction SilentlyContinue`);
      await psExec(`Unregister-ScheduledTask -TaskName 'DEPKSecurityGuard' -Confirm:$false -ErrorAction SilentlyContinue`);
      // 删除安装目录（保留用户隔离区数据）
      const total = await countFiles(target); let done = 0;
      const walk = async (dir) => {
        for (const e of await fsp.readdir(dir, { withFileTypes: true })) {
          const p = path.join(dir, e.name);
          if (e.isDirectory()) { if (e.name === 'DEPKSecurity') continue; await walk(p); }
          else { try { await fsp.rm(p, { force: true }); } catch (err) {} }
          done++; if (done % 5 === 0) sendSetupProgress(done, total, e.name);
        }
        try { await fsp.rmdir(dir); } catch (err) {}
      };
      await walk(target);
      // 运行中的 exe 可能被占用：交给脱离进程延迟清理
      execFile('cmd.exe', ['/c', `timeout /t 3 /nobreak >nul & rmdir /s /q "${target}" & schtasks /delete /tn DEPKSecurityGuard /f >nul 2>&1`], { detached: true, stdio: 'ignore', windowsHide: true }).unref();
      sendSetupProgress(total, total, '完成');
      return { ok: true };
    } catch (err) { return { ok: false, err: String(err.message || err) }; }
  });
}

/* =====================================================
   软件卸载工具（Geek 风格）：卸载 / 强制删除 / 残留清理
   ===================================================== */
const UNINST_ROOTS = [
  'HKCU:\\Software\\Microsoft\\Windows\\CurrentVersion\\Uninstall',
  'HKLM:\\Software\\Microsoft\\Windows\\CurrentVersion\\Uninstall',
  'HKLM:\\Software\\Wow6432Node\\Microsoft\\Windows\\CurrentVersion\\Uninstall'
];
function normName(name) { return String(name).replace(/[（）()\[\]【】\s\-_.+]+/g, '').toLowerCase(); }
function appKeyPaths(name) {
  return UNINST_ROOTS.map(r => `${r}\\${name}`).concat([`HKCU:\\Software\\${name}`, `HKLM:\\Software\\${name}`, `HKLM:\\Software\\WOW6432Node\\${name}`, `HKCU:\\Software\\Microsoft\\Windows\\CurrentVersion\\App Paths\\${name}`]);
}

ipcMain.handle('depk:uninstallApp', async (e, { cmd, quiet }) => {
  const target = (quiet && /msiexec|unins|uninstall/i.test(quiet)) ? quiet : cmd;
  if (!target) return { ok: false, err: '该程序未提供卸载命令' };
  try {
    execFile('cmd.exe', ['/c', 'start', '""', '/wait', target], { detached: true, stdio: 'ignore', windowsHide: true }).unref();
    return { ok: true, msg: '已启动卸载程序' };
  } catch (err) { return { ok: false, err: String(err.message || err) }; }
});

ipcMain.handle('depk:forceRemove', async (e, { key, name, location }) => {
  try {
    // 删除注册表卸载项
    for (const root of UNINST_ROOTS) await psExec(`Remove-Item '${root}\\${String(key).replace(/[^0-9A-Za-z_. -]/g, '')}' -Recurse -Force -ErrorAction SilentlyContinue`);
    // 删除常见注册表残留
    for (const kp of appKeyPaths(String(name).replace(/[^0-9A-Za-z\u4e00-\u9fa5 ._-]/g, ''))) await psExec(`Remove-Item '${kp}' -Recurse -Force -ErrorAction SilentlyContinue`);
    // 删除安装目录
    let delDirs = 0;
    if (location && fs.existsSync(location)) {
      await psExec(`cmd /c rmdir /s /q "${location}" 2>nul`); delDirs++;
    }
    return { ok: true, delDirs };
  } catch (err) { return { ok: false, err: String(err.message || err) }; }
});

ipcMain.handle('depk:scanResidual', async (e, { name, location }) => {
  const hits = [];
  const nn = normName(name);
  if (!nn) return { ok: true, data: hits };
  // 注册表残留
  const r = await runPs(`Get-ChildItem 'HKCU:\\Software','HKLM:\\Software','HKLM:\\Software\\WOW6432Node' -ErrorAction SilentlyContinue | Where-Object {$_.Name -like '*${nn}*'} | Select-Object -ExpandProperty Name`);
  if (r.ok) {
    for (const line of r.out.split(/\r?\n/)) {
      const t = line.trim();
      if (t && t.length > 6 && t !== 'HKEY_CURRENT_USER\\Software' && t !== 'HKEY_LOCAL_MACHINE\\Software') hits.push({ type: 'reg', path: t.replace(/^HKEY_CURRENT_USER/, 'HKCU').replace(/^HKEY_LOCAL_MACHINE/, 'HKLM'), size: 0 });
    }
  }
  // 文件系统残留
  const fDirs = [];
  if (location) fDirs.push(location);
  const baseDirs = [process.env.APPDATA || '', process.env.LOCALAPPDATA || '', path.join(process.env.ProgramData || 'C:\\ProgramData'), process.env.ProgramFiles || '', process.env['ProgramFiles(x86)'] || '', os.homedir()];
  for (const base of baseDirs) {
    if (!base || !fs.existsSync(base)) continue;
    try {
      for (const ent of await fsp.readdir(base, { withFileTypes: true })) {
        const p = path.join(base, ent.name);
        if (ent.isDirectory() && normName(ent.name).includes(nn)) fDirs.push(p);
        else if (ent.isFile() && /\.(exe|dll|dat|log)$/i.test(ent.name) && normName(ent.name).includes(nn)) fDirs.push(p);
      }
    } catch (err) {}
  }
  const seen2 = new Set();
  for (const p of fDirs) {
    if (seen2.has(p.toLowerCase())) continue; seen2.add(p.toLowerCase());
    let size = 0; try { const st = await fsp.stat(p); size = st.isDirectory() ? 0 : st.size; } catch (err) {}
    hits.push({ type: 'file', path: p, size });
  }
  return { ok: true, data: hits };
});

ipcMain.handle('depk:deleteResidual', async (e, { paths }) => {
  let deleted = 0;
  for (const p of (paths || [])) {
    try {
      if (/^HKCU:|^HKLM:/i.test(p)) { await psExec(`Remove-Item '${p}' -Recurse -Force -ErrorAction SilentlyContinue`); deleted++; }
      else { await fsp.rm(p, { recursive: true, force: true }); deleted++; }
    } catch (err) {}
  }
  return { ok: true, deleted };
});

ipcMain.handle('depk:openLocation', async (e, p) => {
  try { execFile('explorer.exe', ['/select,', p], { detached: true, stdio: 'ignore' }).unref(); return { ok: true }; }
  catch (err) { return { ok: false, err: String(err.message || err) }; }
});
ipcMain.handle('depk:copyText', async (e, t) => {
  const { clipboard } = require('electron');
  clipboard.writeText(String(t || ''));
  return { ok: true };
});

/* ---------- IPC：摄像头/麦克风防护（真实 Windows 隐私开关） ---------- */
const CONSENT='Software\\Microsoft\\Windows\\CurrentVersion\\CapabilityAccessManager\\ConsentStore';

async function privacyGet(dev){
  const script=`
$ErrorActionPreference='SilentlyContinue'
function Get-Consent($d){
  $base="HKCU:\\${CONSENT}\\$d"
  $master=(Get-ItemProperty -Path $base -Name '(default)' -ErrorAction SilentlyContinue).'(default)'
  if(-not $master){$master='Allow'}
  $used=@()
  $np=Join-Path $base 'NonPackaged'
  if(Test-Path $np){
    Get-ChildItem $np -ErrorAction SilentlyContinue | ForEach-Object {
      $p=Get-ItemProperty $_.PSPath -ErrorAction SilentlyContinue
      $st=$p.LastUsedTimeStart; $sp=$p.LastUsedTimeStop
      if($st){ $used += [pscustomobject]@{ name=$_.PSChildName; inUse=[bool]($sp -eq 0 -or $null -eq $sp) } }
    }
  }
  [pscustomobject]@{ master=$master; used=@($used) }
}
$w=Get-Consent 'webcam'; $m=Get-Consent 'microphone'
[pscustomobject]@{ webcam=$w; microphone=$m } | ConvertTo-Json -Depth 5 -Compress`;
  return jsonOut(script);
}
async function privacySet(dev, deny){
  const val = deny ? 'Deny' : 'Allow';
  const script=`
$ErrorActionPreference='SilentlyContinue'
$d='${dev}'; $v='${val}'
$u="HKCU:\\${CONSENT}\\$d"
$s="HKLM:\\${CONSENT}\\$d"
try{ Set-ItemProperty -Path $u -Name '(default)' -Value $v -ErrorAction Stop; $uok=$true }catch{ $uok=$false }
try{ Set-ItemProperty -Path $s -Name '(default)' -Value $v -ErrorAction Stop; $sok=$true }catch{ $sok=$false }
[pscustomobject]@{ user=$uok; machine=$sok } | ConvertTo-Json -Compress`;
  return jsonOut(script);
}
async function privacyKill(name){
  const script=`
$ErrorActionPreference='SilentlyContinue'
$n='${String(name||'').replace(/'/g,"''")}'
$k=@(Get-Process -ErrorAction SilentlyContinue | Where-Object { $_.ProcessName -like "*$n*" })
$k | Stop-Process -Force -ErrorAction SilentlyContinue
[pscustomobject]@{ killed=@($k | ForEach-Object { $_.ProcessName }) } | ConvertTo-Json -Compress`;
  return jsonOut(script);
}
ipcMain.handle('privacy:status', async () => {
  const r = await privacyGet();
  if (!r.ok) return { ok:false, err:r.err };
  return { ok:true, data:r.data };
});
ipcMain.handle('privacy:set', async (e, { dev, deny }) => {
  const r = await privacySet(dev, !!deny);
  if (!r.ok) return { ok:false, err:r.err };
  return { ok:true, data:r.data };
});
ipcMain.handle('privacy:kill', async (e, name) => {
  const r = await privacyKill(name);
  if (!r.ok) return { ok:false, err:r.err };
  return { ok:true, data:r.data };
});
