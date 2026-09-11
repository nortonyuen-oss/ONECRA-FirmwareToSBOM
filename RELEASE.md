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

## v1.5.0

| | |
|---|---|
| Tag | `v1.5.0` |
| Build 日期 | 2026-09-11 |
| CPython | 3.12.7 embeddable, amd64(python.org 官方) |

Roadmap **Phase 0**:測試安全網、簽章外部化、repo 治理。分析行為對既有映像不變,
除咗兩項修正(見下)。

### Portable 版(免簽章,推薦交付)

| | |
|---|---|
| 檔案 | `dist-portable/fw2sbom-portable.zip` |
| 大小 | 11,191,000 bytes |
| SHA-256 | `f5a99f49a4f632e4994e490091e24accdb1048bea62855fbfb2b1387a628fe5e` |
| 內容 | 46 個檔案(多咗 5 個 signature 包),全部喺 `fw2sbom-portable/` 之下 |
| Reproducible | 是 —— `.\scripts\build-portable.ps1`,CI 每次 build 兩次對 hash |

### PyInstaller 單檔 exe

**呢個版本冇 build。** 用 `pyinstaller fw2sbom-service.spec`(唔好用裸嘅
`--onefile`,spec 嘅 `datas` 帶住 `signatures/`,冇咗就會對每份韌體都報「找不到
元件」)。

### 包入面屬於我哋嘅檔案

| 檔案 | SHA-256 |
|---|---|
| `fw2sbom.py` | `4b95dd78c2a071a189c0a64bac88fb4a3a328123e964f23eb018f5f154c534a7` |
| `service.py` | `9fd27fd07d6dad087a1443db2dc4f2d6e39c611f803069e81ba78dac1b1a03d6` |
| `evidence_report.py` | `5d22a065d38f2213ac9f7a4c310f135ca75bfa914e413b1f0ba14e43a65bbdcc` |
| `onecra_logo.png` | `a870f4d03b9bdbcc4c6bbc0077c09872bfe49a627400338a46d42a72b4a0c589` |
| `onecra_icon.png` | `21b5280d2f905b5c7ccbcd1b8f284371f24e374e212f71a2838813f98b7596a1` |
| `Start-fw2sbom.bat` | `1c52c4f0c7d2cae205dc199475c8a666e20e180a7301b7354499c1106a7adee5` |
| `signatures/linux.json` | `ab663eee96607955e31d6750e8e0d7df3d2f9d089cf2082a9fd5d4857868b315` |
| `signatures/mcu-lib.json` | `d489590644a6da6b132f67bc39c55eecd82c3d479122e64a451e60cbd3daeb54` |
| `signatures/mcu-rtos.json` | `b87ccae1c638bd469f2c6d6766c54fc800ec7cee669fa1eba93235f8446271e3` |
| `signatures/vendor-nordic.json` | `8da7fdc631d7e71bb4c51edb007b5ce511d99810dde95a657e87ceade9def63e` |
| `signatures/vendor-st.json` | `6c7a683dc98afba1553cd28ba66add045bf62458b2ca714d9089da1c2240f4de` |

### 新增

- **測試套件**(`tests/`):55 個 regression test,對 9 份即時合成嘅韌體映像。
  Fixture 由 `tests/make_fixtures.py` 以固定 seed 產生,byte-identical 可重現,
  唔入倉庫。
- **CycloneDX 1.6 schema 驗證**:9 份 fixture SBOM 全部通過官方 schema。
  呢個輸出**之前從未驗證過**。
- **CI**(`.github/workflows/ci.yml`):Ubuntu + Windows × Python 3.9 / 3.13,
  跑測試 + schema 驗證 + CLI 全 fixture 分析;另一個 job build portable 版兩次
  並比對 hash,令「可重現」由聲稱變成每次 push 都驗證嘅事實。
- **簽章外部化**:34 個簽章由 `fw2sbom.py` 搬去 `signatures/*.json`,依生態系
  分 5 包。載入時驗證 regex / weight / vgroup / CycloneDX type。客戶可用
  `--signatures DIR` 或 `FW2SBOM_SIGNATURES` 加自己嘅包,同名覆蓋內建。
  **完全搵唔到簽章包會直接 exit 1**,唔會產出一份空 SBOM。
- **UTF-16LE 字串萃取**:之前只讀 ASCII,UTF-16 嘅版本 banner 完全睇唔到。
- SBOM metadata 新增 `fw2sbom:signature_database_size` 同
  `fw2sbom:signature_packs` —— 「掃過 34 樣嘢搵到 2 樣」要可稽核,個 34 就要
  喺檔案入面。
- `pyproject.toml`(開發用安裝 + CLI entry point,依然零 runtime 依賴)。

### 修正

- **Opacity 判定同簽章比對自相矛盾**。`analyze_opacity()` 喺簽章比對之前跑,
  所以可以一邊講「payload is OPAQUE - static component identification is not
  possible」,一邊列出 8 個帶精確版本嘅元件。由 fixture `packet_back.bin` 揭發。
  而家證據贏過統計:一旦有元件由 payload 讀出嚟,verdict 降為 `mixed`,原本嘅
  判定記入 `fw2sbom:payload_verdict_before_reconciliation`。真正冇嘢可讀嘅
  加密映像不受影響,仍然係 `opaque`。分區段判定係 Phase 2 嘅正解。
- **UTF-16 字串會偷前一個 ASCII 字串嘅最後一個字元**(NUL 結尾令佢睇落似
  UTF-16 單元)。證據會逐字引用命中字串入稽核文件,所以呢個唔可以留。
- `service.py` 嘅 `_SBOM_STORE` 之前冇上限,長期執行會累積每一次分析嘅結果。
  改成 32 個 entry + 1 小時 TTL,有鎖。

### 已知缺口(有測試盯住)

`KnownGapTest` 斷言嘅係「今日做唔到」嘅行為 —— 壓縮過嘅 Linux router 映像目前
搵唔到任何元件。**呢啲測試喺 Phase 2 完成時應該會失敗**,嗰次失敗就係功能完成
嘅訊號,唔係 regression。

---

## v1.4.1

| | |
|---|---|
| Tag | `v1.4.1` |
| Build 日期 | 2026-09-11 |
| CPython | 3.12.7 embeddable, amd64(python.org 官方) |

`TOOL_VERSION` 由 1.4.0 升到 1.4.1。功能同 1.4.0 一樣,呢個 bump 係為咗令
**工具版本、git tag、交付出去嘅 zip 三者對得返**(原因見下面〈關於 v1.4.0 tag〉)。

### Portable 版(免簽章,推薦交付)

| | |
|---|---|
| 檔案 | `dist-portable/fw2sbom-portable.zip` |
| 大小 | 11,185,077 bytes |
| SHA-256 | `32e43f46ae1e2857d207062b6d76482e3bc69c6ab198dceab9cc763145cbbe34` |
| 內容 | 41 個檔案,全部喺 `fw2sbom-portable/` 之下 |
| Reproducible | 是 —— `.\scripts\build-portable.ps1` |

解壓後雙擊 `Start-fw2sbom.bat`。唔會撞 SmartScreen「未知發行者」,因為包入面
冇任何由我哋自己 compile / link 出嚟嘅 binary。

### PyInstaller 單檔 exe

**呢個版本冇 build。** `dist/fw2sbom-service.exe` 如果仲喺度,係 1.4.0 嗰個,
唔好當 1.4.1 交出去。要嘅話照 [README](README.md#打包成單一執行檔給客戶用) 嘅
PyInstaller 指令重新 build,再喺度補返一行。

exe 未簽章,客戶電腦嘅 SmartScreen / 防毒有機會直接攔截。要真正解決要買 EV code
signing 憑證;喺嗰之前,**優先交付上面嘅 portable 版**。

### 包入面屬於我哋嘅檔案

zip 入面大部分 bytes 係 python.org 嘅 embeddable CPython。以下先係 fw2sbom
本身 —— 呢啲 hash 就算換 CPython 版本重新打包都唔會變,所以係最穩陣嘅身分證明:

| 檔案 | SHA-256 |
|---|---|
| `fw2sbom.py` | `8f9253a068309fa834a7b741c9afd5a042649c52962d9dbc69d9edc121fa5f40` |
| `service.py` | `7108a164bb5350e264587de49d8f87ed52695ccceabb21a8c35661c5fb919f01` |
| `evidence_report.py` | `5d22a065d38f2213ac9f7a4c310f135ca75bfa914e413b1f0ba14e43a65bbdcc` |
| `onecra_logo.png` | `a870f4d03b9bdbcc4c6bbc0077c09872bfe49a627400338a46d42a72b4a0c589` |
| `onecra_icon.png` | `21b5280d2f905b5c7ccbcd1b8f284371f24e374e212f71a2838813f98b7596a1` |
| `Start-fw2sbom.bat` | `1c52c4f0c7d2cae205dc199475c8a666e20e180a7301b7354499c1106a7adee5` |

### 呢個版本有咩

首個有紀錄嘅 release:

- CycloneDX 1.6 SBOM + 7 張工作表嘅 Excel 證據報告,兩份交付物
- 通用 packetized / ISP-dump 容器偵測與去框(唔依賴廠商 magic)
- Opacity 判定:加密映像會產生 opaque component 而唔係空 SBOM
- 架構識別:ARM Cortex-M 同 MCS-51 / 8051
- 內嵌標準資料:VESA E-EDID、DDC/CI MCCS
- 33 個軟體元件簽章
- 本機拖拉式 web UI(`service.py`),header 顯示工具版本
- 可重現嘅 portable 打包流程(`scripts/build-portable.ps1`)

---

## 關於 v1.4.0 tag

`v1.4.0` tag(已 push 上 origin)指向 initial commit `11f464c`,**早過**
`bd44dc6`「web UI header 顯示版本號」。即係話嗰個 tag 嘅 `service.py`
(`0fd1f0d6…`)同我哋實際打包交付嘅(`7108a164…`)唔同。

tag 已經發佈,move 佢會令任何已經 fetch 過嘅人見到 tag 內容變咗,所以冇郁佢。
1.4.1 就係用嚟消除呢個落差 —— 由呢個版本開始,tag、`TOOL_VERSION` 同 zip 三者
永遠一致。

v1.4.0 從來冇正式記錄過交付 hash,所以冇嘢要喺度補。

---

## 新開一個 release 嘅步驟

```powershell
# 1. 改 fw2sbom.py 的 TOOL_VERSION,commit
# 2. 重新打包(會自己驗 CPython 的 SHA-256、跑 smoke test、出可重現的 zip)
.\scripts\build-portable.ps1

# 3. 把腳本最後印出來的 hash 貼上本檔新增一節
# 4. 打 tag
git tag -a v1.5.0 -m "fw2sbom v1.5.0"
git push origin master --follow-tags
```

第一次喺新機器 build,或者換 CPython 版本嗰陣,`scripts/python-embed.sha256`
未必有對應嘅 pin。腳本會警告並印出下載到嘅 SHA-256 —— **去 python.org 嘅
release 頁對一對**,啱先至用 `-PinHash` 記低:

```powershell
.\scripts\build-portable.ps1 -PythonVersion 3.12.8 -PinHash
```

盲目 `-PinHash` 等於把一個未經驗證嘅下載洗成一個睇落好可信嘅檔案,冇意思。
