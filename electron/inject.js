// 纯 Node 向 Windows exe 注入图标与版本信息（无需 wine）
const fs = require('fs');
const { NtExecutable, NtExecutableResource } = require('pe-library');
const resedit = require('resedit');

const exePath = process.argv[2];
const icoPath = process.argv[3];

const exeData = fs.readFileSync(exePath);
const exe = NtExecutable.from(exeData);
const res = NtExecutableResource.from(exe);

// 图标
const iconFile = resedit.Data.IconFile.from(fs.readFileSync(icoPath));
const iconItems = iconFile.icons.map((icon) => icon.data);
resedit.Resource.IconGroupEntry.replaceIconsForResource(res.entries, 1, 0, iconItems);

// 版本信息
const vi = resedit.Resource.VersionInfo.createEmpty();
vi.setFileVersion(3, 4, 210, 0, 0x0804);
vi.setProductVersion(3, 4, 210, 0, 0x0804);
vi.setStringValues({ lang: 0x0804, codepage: 1200 }, {
  CompanyName: 'DEPK Security',
  FileDescription: 'DEPK Security Assistant - 终端安全防护',
  FileVersion: '3.4.210',
  InternalName: 'DEPKSecurityAssistant',
  LegalCopyright: '© 2026 Doubao Security',
  OriginalFilename: 'DEPKSecurityAssistant.exe',
  ProductName: 'DEPK Security Assistant',
  ProductVersion: '3.4.210'
});
res.replaceResourceEntry(vi.generateResource());

res.outputResource(exe);
fs.writeFileSync(exePath, Buffer.from(exe.generate()));
console.log('icon + version injected ->', exePath);
