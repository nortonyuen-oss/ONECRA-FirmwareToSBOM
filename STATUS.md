# 專案狀態

快照日期:**2026-09-14** · 版本 **v1.8.0**

這份是「現在站在哪裡」的單頁摘要。逐個 release 的細節在 [RELEASE.md](RELEASE.md),
完整的分階段計劃與缺口分析在 roadmap 文件。

---

## 一句話

fw2sbom 從 firmware 二進位映像產生 **CycloneDX 1.6 / SPDX 2.3** SBOM,每個元件
都帶證據與 confidence。目標是讓客戶把韌體拖進本機網頁介面,拿到可以餵給 CVE
比對系統的 SBOM,滿足歐盟 CRA 的要求。

零 pip 依賴,純 Python 標準函式庫。交付方式是一個免簽章的 portable 資料夾,
客戶解壓後雙擊即可執行。

---

## 對各類客戶產品的覆蓋

| 產品類別 | 狀態 | 說明 |
|---|---|---|
| **IoT / MCU**<br>ARM Cortex-M、8051 | 可用 | 架構識別、封包容器去框、加密映像誠實標記、內嵌標準資料(EDID / MCCS)。版本能拿的都拿了,拿不到的說明為什麼 |
| **Router / Gateway**<br>Linux, MIPS / ARM | 可用(OpenWrt 類) | uImage + 壓縮 kernel + SquashFS + ELF。真實 GL.iNet router:**366 個元件、362 個帶精確版本、262 個帶授權、1268 條依賴邊**。FIT / TRX / 廠商自訂檔頭尚未支援 |
| **CCTV / NVR**<br>Linux, 專有 SoC | 部分 | 用標準 uImage + SquashFS 的機型現在就能分析。廠商自訂容器要逐個加;整段加密的機型上限仍是 opaque |
| **PC BIOS / UEFI**<br>x86, EDK2 | 未開始 | 獨立的問題域(Flash Descriptor / FV / FFS / GUID),與 Linux 那條路幾乎不共用程式碼 |

### 真實韌體實測

| 映像 | 結果 |
|---|---|
| GL.iNet GL-MT300N-V2,OpenWrt 22.03.4,MIPS,14.6 MB | 366 個元件(OpenWrt 22.03.4、Linux 5.10.176、GCC 11.2.0、binutils 2.37,加 opkg 資料庫 359 個套件的精確版本)。10.2 秒 |
| 客戶 nRF5 BLE firmware,Cortex-M,212 KB | 架構、opacity、證據鏈正確。2 個元件,兩者**結構上**不帶版本,SBOM 已說明原因與取得途徑 |

---

## 已完成

| 版本 | 內容 |
|---|---|
| `v1.4.0` | 起點:CycloneDX 1.6、Excel 證據報告、封包去框、opacity 判定、Cortex-M / 8051、EDID / MCCS、拖拉式 web UI |
| `v1.4.1` | 可重現的 portable 打包流程;工具版本 = tag = zip 三者對齊 |
| `v1.5.0` | **Phase 0**:測試安全網(fixture 產生器 + regression 測試)、CI、CycloneDX schema 驗證、簽章外部化成 JSON、UTF-16LE 字串 |
| `v1.6.0` | **Phase 1**:SPDX 2.3 輸出、`--firmware-version`、`version_note` 版本策略 |
| `v1.7.1` | 專有授權與第三方歸屬,隨套件交付 |
| `v1.8.0` | **Phase 2 第二階段**:ELF reader、指令集識別、依賴圖、聲明授權與廠商 CPE、kernel module metadata |
| `v1.7.0` | **Phase 2 第一階段**:容器走訪、解壓、SquashFS 4.0 reader、opkg / dpkg / apk 套件資料庫、發行版識別、真實韌體 corpus 測試 |

### 工程現況

| 項目 | 狀態 |
|---|---|
| 程式碼 | 約 7,300 行,7 個模組 + 6 個簽章包(36 個簽章) |
| 依賴 | 無。Python 3.9+ 標準函式庫 |
| 測試 | 101 個。9 個合成 fixture + 1 份真實廠商韌體 corpus |
| Schema 驗證 | CycloneDX 1.6 與 SPDX 2.3 皆對官方 schema 驗證 |
| CI | Ubuntu + Windows × Python 3.9 / 3.13;另有真實韌體 job 與可重現打包驗證 |
| 交付 | Portable zip,byte-reproducible,hash 記錄在 RELEASE.md |
| 授權 | 專有([LICENSE](LICENSE));第三方歸屬見 [THIRD-PARTY-NOTICES.md](THIRD-PARTY-NOTICES.md) |
| 下載頁 | **已上線** <https://nortonyuen-oss.github.io/ONECRA-FirmwareToSBOM/> |

---

## 過程中修正的實際錯誤

這些不是新功能,是工具原本會對客戶說錯話的地方:

1. **Opacity 判定與元件清單自相矛盾** — 可以一邊印「無法識別元件」一邊列出 8 個
   帶精確版本的元件。現在證據贏過統計。
2. **`gcc-arm-none-eabi` 在任何 GCC 編譯的映像上命中**,包括 MIPS —— 稽核文件裡
   的一句錯陳述。通用部分已拆成 `gcc` 簽章。
3. **UTF-16 字串會偷走前一個 ASCII 字串的最後一個字元** —— 證據會逐字引用命中
   字串進文件,不能留。
4. **打包腳本的 smoke test 會產生 `__pycache__`** —— `.pyc` 內嵌原始碼 mtime,
   會同時破壞可重現性並把 build cache 送給客戶。
5. **`_SBOM_STORE` 無上限** —— 長期執行的服務會累積每一次分析的結果。

---

## 下一步

Phase 2 剩餘(擴闊 router / CCTV 覆蓋):

- 更多容器格式:FIT、TRX、TP-Link / D-Link / HiSilicon 等廠商自訂檔頭
- 更多檔案系統:JFFS2、UBI / UBIFS、CramFS
- 分區段 opacity 判定
- 對**沒有套件資料庫**的映像,逐檔做簽章比對並歸屬到檔案(ELF reader 已就位,
  但目前只在有資料庫時用來建依賴圖)
- CCTV:廠商 SBOM 匯入與合併

之後:Phase 3(HEX / SREC / UF2 / ELF 輸入、ESP32、RISC-V)、Phase 4(UEFI)。

**已取消的範圍:** CPE 2.3 產生、上傳到平台 —— 兩者都由另一個系統負責。

---

## 下載站

**已上線:**<https://nortonyuen-oss.github.io/ONECRA-FirmwareToSBOM/>

由 GitHub Pages 從 `master` 的 `/docs` 發佈。端到端驗證過:從公開網址下載到的
zip,雜湊與頁面公佈的一致;解壓後用套件內的直譯器跑真實 router 韌體,得到 366
個元件,CycloneDX 與 SPDX 皆通過官方 schema。

倉庫因此**維持 public**(原本決定轉 private,已推翻 —— 免費帳戶的 Pages 只支援
公開倉庫)。git history 已查核:無客戶資料。授權為專有。

---

## 待辦(非程式碼)

| 項目 | 說明 |
|---|---|
| 重建 PyInstaller exe | `dist/fw2sbom-service.exe` 仍是 1.4.0。重建**必須**用 `pyinstaller fw2sbom-service.spec`,裸 `--onefile` 不會帶 `signatures/` |
| CPython hash pin | `scripts/python-embed.sha256` 仍為空。下次有網時跑 `build-portable.ps1 -PinHash` 並對照 python.org |
| 真實 CCTV 韌體樣本 | 有樣本才能決定 Phase 2 剩餘項目的優先次序 |
