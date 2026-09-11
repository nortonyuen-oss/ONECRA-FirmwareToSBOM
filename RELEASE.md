# Release record

每個交付給客戶的 build 記錄喺呢度。目的好單純:客戶手上嗰個 zip,要可以對返
係邊個 commit、邊個 fw2sbom 版本、邊個 CPython build 出嚟嘅。

一個產 SBOM 嘅工具,自己嘅供應鏈冇記錄就好難講得通。

Build artifacts 本身唔入 git(見 [.gitignore](.gitignore))—— 呢個檔案就係佢哋
嘅 index。

## 點樣核對客戶手上嘅檔案

```bash
sha256sum fw2sbom-portable.zip          # 對返下面表格
```

Windows:

```powershell
Get-FileHash -Algorithm SHA256 .\fw2sbom-portable.zip
```

Portable zip 係 **reproducible** 嘅:`scripts/build-portable.ps1` 用
`scripts/make_deterministic_zip.py` 寫入,entry 排序固定、timestamp 固定、
壓縮等級固定。同一個 commit + 同一個 CPython embeddable,任何機任何時間 rebuild
都會出到同一個 SHA-256。所以下面嗰個 hash 唔單止係「我哋嗰次 build 嘅紀錄」,
而係可以獨立重現嘅。

PyInstaller 嘅 `.exe` **唔係** reproducible(PyInstaller 會 embed build path
同 timestamp),所以 exe 嘅 hash 只係「嗰一次 build 嘅紀錄」,rebuild 會唔同。

---

## v1.4.0

| | |
|---|---|
| Tag | `v1.4.0`(`git rev-list -n 1 v1.4.0` 攞 commit) |
| Build 日期 | 2026-09-11 |
| CPython | 3.12.7 embeddable, amd64(python.org 官方) |

### Portable 版(免簽章,推薦交付)

| | |
|---|---|
| 檔案 | `dist-portable/fw2sbom-portable.zip` |
| 大小 | 11,185,077 bytes |
| SHA-256 | `785738f629ef18ab77c178bc95a5eac544e78055231cb8b07e0c54a65ae8ee42` |
| 內容 | 41 個檔案,全部喺 `fw2sbom-portable/` 之下 |
| Reproducible | 是 —— `.\scripts\build-portable.ps1` |

解壓後雙擊 `Start-fw2sbom.bat`。唔會撞 SmartScreen「未知發行者」,因為包入面
冇任何由我哋自己 compile / link 出嚟嘅 binary。

### PyInstaller 單檔 exe(會撞 SmartScreen)

| | |
|---|---|
| 檔案 | `dist/fw2sbom-service.exe` |
| 大小 | 9,715,379 bytes |
| SHA-256 | `ec82dbcd934e5bec4c6823f44fb328a2d436bbfddf83a4c8b1922ac194f26d1f` |
| Reproducible | 否 —— rebuild 會出唔同 hash |

未簽章。客戶電腦嘅 SmartScreen / 防毒有機會直接攔截。要真正解決要買 EV code
signing 憑證;喺嗰之前,**優先交付上面嘅 portable 版**。

### 包入面屬於我哋嘅檔案

zip 入面大部分 bytes 係 python.org 嘅 embeddable CPython。以下先係 fw2sbom
本身 —— 呢啲 hash 就算換 CPython 版本重新打包都唔會變,所以係最穩陣嘅身分證明:

| 檔案 | SHA-256 |
|---|---|
| `fw2sbom.py` | `c37ba70f00f7040a66375ad893833a0df0eafa3f4ff0f2019fcf55c6023808ab` |
| `service.py` | `7108a164bb5350e264587de49d8f87ed52695ccceabb21a8c35661c5fb919f01` |
| `evidence_report.py` | `5d22a065d38f2213ac9f7a4c310f135ca75bfa914e413b1f0ba14e43a65bbdcc` |
| `onecra_logo.png` | `a870f4d03b9bdbcc4c6bbc0077c09872bfe49a627400338a46d42a72b4a0c589` |
| `onecra_icon.png` | `21b5280d2f905b5c7ccbcd1b8f284371f24e374e212f71a2838813f98b7596a1` |
| `Start-fw2sbom.bat` | `1c52c4f0c7d2cae205dc199475c8a666e20e180a7301b7354499c1106a7adee5` |

### 這個版本有咩

首個有紀錄嘅 release。相對之前嘅內部 build:

- CycloneDX 1.6 SBOM + 7 張工作表嘅 Excel 證據報告,兩份交付物
- 通用 packetized / ISP-dump 容器偵測與去框(唔依賴廠商 magic)
- Opacity 判定:加密映像會產生 opaque component 而唔係空 SBOM
- 架構識別:ARM Cortex-M 同 MCS-51 / 8051
- 內嵌標準資料:VESA E-EDID、DDC/CI MCCS
- 33 個軟體元件簽章
- 本機拖拉式 web UI(`service.py`),header 顯示工具版本

---

## 新開一個 release 嘅步驟

```powershell
# 1. 改 fw2sbom.py 的 TOOL_VERSION,commit
# 2. 重新打包(會自己驗 CPython 的 SHA-256、跑 smoke test、出可重現的 zip)
.\scripts\build-portable.ps1

# 3. 把腳本最後印出來的 hash 貼上本檔新增一節
# 4. 打 tag
git tag -a v1.5.0 -m "fw2sbom v1.5.0"
```

第一次喺新機器 build,或者換 CPython 版本嗰陣,`scripts/python-embed.sha256`
未必有對應嘅 pin。腳本會警告並印出下載到嘅 SHA-256 —— **去 python.org 嘅
release 頁對一對**,啱先至用 `-PinHash` 記低:

```powershell
.\scripts\build-portable.ps1 -PythonVersion 3.12.8 -PinHash
```

盲目 `-PinHash` 等於把一個未經驗證嘅下載洗成一個睇落好可信嘅檔案,冇意思。
