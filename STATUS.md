# 專案狀態

快照日期:**2026-09-14** · 版本 **v1.13.1**

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
| **IoT / Wi-Fi SoC**<br>Espressif ESP32 系列 | 可用 | Application image 與整顆 flash dump 都按自己的結構切(partition table 就是地圖)。晶片型號與指令集由 header 宣告讀出,ESP-IDF 版本由 `esp_app_desc_t` 讀出(confidence 0.97)。IDF 內含的 mbedTLS / lwIP / FreeRTOS 版本**不作推導** |
| **Router / Gateway**<br>Linux, MIPS / ARM | 可用(OpenWrt 類) | uImage + 壓縮 kernel + SquashFS + ELF。真實 GL.iNet router:**366 個元件、362 個帶精確版本、262 個帶授權、1268 條依賴邊**。FIT / TRX / 廠商自訂檔頭尚未支援 |
| **CCTV / NVR**<br>Linux, 專有 SoC | 部分 | 用標準 uImage + SquashFS 的機型現在就能分析,**即使沒有套件資料庫也能從檔案本身取得元件**。整段加密的機型上限是 opaque,但可以**匯入廠商 SBOM 並與映像比對**。廠商自訂容器要逐個加 |
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
| `v1.9.0` | **Phase 2 第三階段**:逐檔簽章比對(冇套件資料庫嘅映像先有 rootfs 元件)、證據指向檔案路徑 |
| `v1.10.0` | **Phase 2 第四階段**:分區段 opacity 判定、抹除 flash 識別、逐區段 opaque 元件 |
| `v1.11.0` | **Phase 2 完成**:廠商 SBOM 匯入與比對(來源保留、版本衝突偵測) |
| `v1.12.0` | **Phase 3 第一階段**:直接讀 ELF / Intel HEX / S-record / UF2 |
| `v1.13.0` | **Phase 3 第二階段**:Espressif ESP32 系列(image / partition table / app descriptor、宣告式指令集) |
| `v1.13.1` | 修正:畫面上的元件清單改由 SBOM 文件推導,不再與下載到的文件不一致 |
| `v1.7.0` | **Phase 2 第一階段**:容器走訪、解壓、SquashFS 4.0 reader、opkg / dpkg / apk 套件資料庫、發行版識別、真實韌體 corpus 測試 |

### 工程現況

| 項目 | 狀態 |
|---|---|
| 程式碼 | 約 9,100 行(含測試),10 個模組 + 6 個簽章包(36 個簽章) |
| 依賴 | 無。Python 3.9+ 標準函式庫 |
| 測試 | 155 個。12 個合成 fixture + 真實廠商韌體 corpus(1 份 router、3 份 ESP32) |
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
6. **逐區段判定時漏掉「指令集正面識別即為明文」** —— 普通 Cortex-M 韌體被報成
   加密區段(v1.10.0–v1.11.0)。所有測試當時都通過,因為測試輔助函式跳過了
   `main()` 實際會走的那一步;輔助函式現在與 `main()` 同路。
7. **整份映像一起量 opacity,空白區壓過密文** —— 一個 64 MB flash dump 裡 3.6 MB
   的加密 kernel 被判成「明文、無元件」。把「讀不到」報成「裡面沒有東西」,正是
   這個工具存在的理由要防止的事。由真實 CCTV 韌體樣本揭發。
8. **網頁畫面的元件清單與下載到的文件不一致** — 畫面那份是另外組出來的,
   每一種後來新增的元件來源都只進了文件、沒進畫面。客戶先看畫面、再把檔案交給
   稽核,兩者不一致就沒有東西分得出哪一份才對。現在畫面由文件推導。
9. **廠商 SBOM 比對漏掉 Espressif 元件** — ESP32 韌體因此與任何廠商 SBOM 都
   「完全一致」,而版本衝突正是這個功能存在的理由。

---

## 下一步

**Phase 2 已完成。** 剩餘的擴充項目都需要我們手上沒有的韌體樣本:

- 更多容器格式:FIT、TRX、TP-Link / D-Link / HiSilicon 等廠商自訂檔頭
- 更多檔案系統:JFFS2、UBI / UBIFS、CramFS

這兩項沒有真實樣本就只能照規格書寫,驗證不到廠商實際的偏差 —— `gcc-arm-none-eabi`
誤報那次已經示範過合成 fixture 看不出真實問題。

Phase 3 剩餘:raw 映像(非 ESP32、非 ELF)的 RISC-V / Xtensa 指令集辨識 ——
ESP32 已由 header 的 chip ID 直接解決,ELF 輸入本來就涵蓋,所以剩下的是「一份
沒有任何檔頭的 RISC-V raw dump」這個窄情況。之後:Phase 4(UEFI)。

值得考慮的下一項:**ESP-IDF 內含元件的版本對照**。一份只寫著 `esp-idf 5.5.4`
的 SBOM 對 CVE 比對幫助有限 —— 真正會中 CVE 的是 mbedTLS 與 lwIP。但 release
build 常常把這些元件的字串剝掉(Tasmota 就是),所以唯一的出路是維護一張
「IDF 版本 → 內含元件版本」對照表。那是可以查證的公開資料,但必須逐版維護,
而且要標成「由 IDF 版本推得」而非「在映像中觀察到」,否則就違反了這個工具的
基本原則。**尚未實作,先記在這裡。**

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
| 真實客戶 ESP32 韌體 | 目前只用公開的 Tasmota 映像驗證過。客戶的 build 多半會填滿 app descriptor(專案名稱、應用版本),那條路徑值得用真檔跑一次 |
