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

**PyInstaller 單檔 `.exe` 已經取消**(2026-09-16),往後唔會再有。佢冇數位簽章,
Windows SmartScreen 會跳「未知發行者」,而 portable 版存在嘅理由就係繞開呢件事 ——
同時維護兩種交付形式等於維護一個較差嘅。另外 PyInstaller 會 embed build path 同
timestamp,所以嗰啲 exe 嘅 hash 從來只係「嗰一次 build 嘅紀錄」,rebuild 會唔同。
下面 v1.7.1 之前嘅 release 仲有 exe 嘅紀錄,保留返 —— 嗰啲係當時真係交付過嘅嘢。

---

## v1.17.0

| | |
|---|---|
| Tag | `v1.17.0` |
| 程式碼 commit | `c8a32b2aecf8a5e100d8233f2abbe29b64c0c61c` |
| Build 日期 | 2026-09-18 |
| CPython | 3.12.7 embeddable, amd64(python.org 官方) |

### Portable 版(唯一交付形式)

| | |
|---|---|
| 檔案 | `dist-portable/fw2sbom-portable.zip` |
| 大小 | 11,271,978 bytes |
| SHA-256 | `ec449492b8254beb6cb653bb3bc9c22c570a431786d6816eb0d10a4e8d96925c` |
| 內容 | 59 個檔案 |
| Reproducible | 是 |

### 包入面屬於我哋嘅檔案

| 檔案 | SHA-256 |
|---|---|
| `fw2sbom.py` | `1e1f65790eda3d183a27c6790b7b9f3859d0becae5b896ff7a1c36a38f1df8c5` |
| `container.py` | `3036596b0b5bfbf69677881f8b44a6015fd9fcecd14a830fe44803a8de6413bf` |
| `service.py` | `36c730580108a248fffdcfa83267c37088c2b6b7274de05ce27c61bbbf343698` |

其餘檔案與 v1.16.0 相同。

### 新增:進度條

拖檔案入去之後,頁面顯示而家做緊邊步、做到邊:

```
拆解與掃描各區段                                          70%
解析執行檔 546 / 3274                        第 5 步 / 共 7 步 · 已用 6.8 秒
```

- **只喺伺服器回報「真係做完咗某樣嘢」先前進,從來唔靠計時器推。** 一條自己慢慢
  爬、然後卡喺 90% 嘅進度條,係為咗令等待感覺短啲而講嘅細謊 —— 呢個工具唔應該講。
  亦只會向前,唔會倒退。
- **只顯示已用時間,唔顯示估計剩餘時間。** 同一個階段喺 router、BIOS、攝影機韌體
  上花嘅時間差好幾倍(實測去框階段:ESP32 佔 55%、BIOS 佔 3%),估出嚟都係亂估。
- 階段內一律係實際計數:封包框間距 408 / 498、判斷區段 2 / 4、解析執行檔
  546 / 3274、掃描檔案 1200 / 3274。區段掃描按位元組數加權。
- 真實瀏覽器跑 router,**百分比同說明文字冇一段停超過 2.3 秒**。第一版 BIOS 會喺
  40% 企 4.5 秒、router 喺 10% 企 3.4 秒 —— 都係量度咗先知,之後兩處都加咗逐步回報。

### 修正:網頁從 v1.9.0 起漏掉 rootfs 元件

**逐檔掃描 rootfs 嘅功能只入咗 CLI 同測試,從來冇入到網頁服務。**任何冇套件資料庫
嘅 Linux 映像 —— 大部分 CCTV 韌體都係 —— 喺網頁上會漏晒所有由 rootfs 搵到嘅元件,
而 CLI 同全部測試都正常。CramFS 測試檔:CLI 報 busybox 1.36.1 同 mbedtls 3.4.0,
網頁兩樣都冇。

呢個係**第三次**「兩條路各自複製一份流程、慢慢分歧」嘅同一種錯誤。所以修法唔係補
一行,而係 CLI、網頁、測試**共用一條 `run_analysis()`**。

- CLI 完全冇變,而且有證據:19 份映像(全部 fixture 加 router、BIOS、ESP32、加密
  D-Link)嘅 CycloneDX 文件同 verbose log,重構前後**38 份逐字一致**。
- 測試 helper 以前自己抄一份流程,仲係抄 `main()` 嘅 —— 所以網頁錯咗佢照過。而家
  有一個測試逐個 fixture 比較網頁同 pipeline 嘅元件,**用舊版 service.py 跑過,確認
  會失敗**。

> 如果你之前用網頁分析過冇套件資料庫嘅 Linux 韌體(尤其 CCTV),**請用呢版重跑**。

### 修正:網頁將 Linux 映像嘅架構顯示成「未識別」

CLI 一直會退而用 rootfs 入面 ELF 讀出嘅架構;網頁淨係睇檔頭層級嘅判定,所以一部
MIPS router 顯示「未識別」,但下載到嘅文件入面寫得清清楚楚。

### 效能

量度進度條之前先量咗時間,發現全圖熵值計算佔 router 分析 43%,其中兩個統計做緊
可以避免嘅工夫:

| 統計 | 改動 | 加速(中位數) |
|---|---|---|
| 最長重複位元組 | 唔再為長度 1 嘅 run 生 match object(一個 byte 一個,router 上一千四百萬個) | ×9 |
| 可列印字元比例 | 由 Python 逐 byte 迴圈改成 `bytes.translate` | ×11 |

兩者**結果完全一致** —— 改動前後對 19 份映像記錄全部熵值結果,冇一個唔同。每次全圖
掃描(router)慳約 5 秒。

要講清楚:呢部開發機嘅負載好唔穩定,同一份工作可以由 6.6 秒跳到 14.5 秒,所以上面
用嘅係交替執行、五次取中位數嘅數字,唔係單次量度。

### 測試

232 個(由 214 增加)。新增 `ProgressTest` 九項、`AnalysisJobTest` 六項(真 HTTP
伺服器、真輪詢),加埋上面兩個修正嘅迴歸測試。

---

## v1.16.0

| | |
|---|---|
| Tag | `v1.16.0` |
| 程式碼 commit | `e80b4b5ad697434c1f5f4a6c8e1ede5f3c39fa76` |
| Build 日期 | 2026-09-17 |
| CPython | 3.12.7 embeddable, amd64(python.org 官方) |

### Portable 版(唯一交付形式)

| | |
|---|---|
| 檔案 | `dist-portable/fw2sbom-portable.zip` |
| 大小 | 11,265,146 bytes |
| SHA-256 | `db0475c2b3d635e85a66dd8ae96b2364453636cd566255eab545961017bda491` |
| 內容 | 59 個檔案(多咗 `cramfs.py`、`vendor_container.py`) |
| Reproducible | 是 |

### 包入面屬於我哋嘅檔案

| 檔案 | SHA-256 |
|---|---|
| `fw2sbom.py` | `4746460ac68b7564b9528e380f90d8fcf8b6c5145699e5d083d57e02125e729e` |
| `container.py` | `96c1dc6095ea5844529cce9febed25b30892a3409c67b878c38e46ca4005bb78` |
| `cramfs.py` | `b506da28dcf7ee83d08f641c11efdb48ccc9a96159e8eb0215bfefc8b3e6217a` |
| `vendor_container.py` | `9efb3dda2b60d6dc001f77f655181957969f4edd0249f7efee325944cf11267b` |

其餘檔案與 v1.15.1 相同。

### 新增:廠商外層容器

消費級 router 嘅韌體下載檔好少係裸映像,而係前面加咗廠商自己嘅檔頭。檔頭好細,
後面就係我哋本來讀得懂嘅韌體 —— 所以一個 `.trx` 檔同一份完整 SBOM 之間,爭嘅
只係「知道要跳過 32 個 byte」。

| 容器 | Magic | 常見於 |
|---|---|---|
| Broadcom TRX v1 / v2 | `HDR0` | Netgear、Linksys、Asus、Buffalo |
| Netgear CHK | `*#$^` | Netgear(入面通常包住一個 TRX) |
| D-Link SHRS | `SHRS` | D-Link |
| Instar BNEG | `BNEG` | Instar IP camera |
| Moxa FRM | `*FRM` | Moxa 工業閘道器 |

**呢個模組刻意寫得好薄:佢乜都唔解壓。** 認得容器、記低檔頭講咗乜、將檔頭嗰幾十
個 byte 標記為已解釋,**其餘交返原本嘅流程**。兩件唔會做嘅事:唔猜 payload 位置
(切錯位唔會大聲失敗,只會令之後每一項發現都偏移);唔假裝加密嘅 payload 讀得到。

### 新增:CramFS

好多細型 Linux 裝置(攝影機、機上盒、舊閘道器)喺 router 用 SquashFS 嗰個位置用
CramFS。`cramfs.py` **提供同 `squashfs.SquashFS` 一模一樣嘅介面**,所以後面全部
照跑:套件資料庫、ELF 依賴分析、逐檔簽章掃描,一行都唔使改。

兩個會令人寫錯嘅細節:**兩種位元組序都存在,而且 inode 入面嘅欄位會跟住翻**
(淨係翻 word 唔翻欄位,會得出幾 MB 嘅檔案大小同零長度檔名);**長度嘅單位唔係
byte**(`namelen` 同 `offset` 數嘅都係 4-byte 單位)。

驗證方式值得一提:公開樣本**同樣內容有 LE 同 BE 兩份**,所以兩個 decoder 係互相
驗證,唔淨係各自對照規格書。12 個變體全部讀出**完全相同**嘅檔案清單同內容。

### 修正:一個喺最常走嗰條路上嘅缺陷

**未識別區段被標成「已解開」。** 嗰個旗標嘅意思係「無論熵值幾高,呢段我哋讀得明」
—— 於是**任何唔屬於已知容器嘅高熵區段,都會因為「我哋有佢啲 bytes」而被判成明文**。
一個加密嘅 D-Link SHRS payload,熵值 **7.951**,就係咁被報成 plaintext。

呢個係 v1.15.0 嗰個問題嘅同一個錯誤,但喺最常走嗰條路上。同場修埋 uImage 檔頭同
未壓縮 kernel 兩處一樣嘅假宣稱。**由今次加入嘅真實樣本測試揭發 —— 之前 194 個
測試全部綠。**

### 樣本來源

`scripts/fetch-corpus.py` 新增 8 個格式樣本,來自 unblob 專案(MIT)。佢哋用 Git LFS
存放,所以 fetcher 加咗 LFS 指標解析 —— 唔係嘅話會下載到一個 128-byte 嘅文字檔,
而且完全唔會報錯。

要講清楚:呢批係**格式變體向量,唔係完整廠商韌體**。啱用嚟寫 reader,唔可以當成
「喺真實映像上行得通」嘅證明 —— 所以 router / ESP32 / BIOS 嗰幾份真檔仍然喺度。

### 測試

214 個(由 194 增加)。新增 `VendorContainerTest` 七項、`CramFSTest` 九項、
`RealFormatSampleTest` 四項(對住公開樣本)。

---

## v1.15.1

| | |
|---|---|
| Tag | `v1.15.1` |
| 程式碼 commit | `3588f582a0d24e8cadfc8ef59023520c362cab02` |
| Build 日期 | 2026-09-17 |
| CPython | 3.12.7 embeddable, amd64(python.org 官方) |

### Portable 版(唯一交付形式)

| | |
|---|---|
| 檔案 | `dist-portable/fw2sbom-portable.zip` |
| 大小 | 11,256,981 bytes |
| SHA-256 | `b126359d97c2a9f6d0340777f77860ced3168fe22f6a06936a12d1925a6bfcf1` |
| 內容 | 57 個檔案 |
| Reproducible | 是 |

### 包入面屬於我哋嘅檔案

| 檔案 | SHA-256 |
|---|---|
| `fw2sbom.py` | `aa64dcb27df60c4ec749d2516932bc84d4afc77450431218642057bc9d15c009` |
| `service.py` | `cbc3f4743a3a18fbb90c33d231d1815b6f99395c6c3918e7c262da46c48fff9e` |

其餘檔案與 v1.15.0 相同。

### 修正

三項都係**攞住真實 BIOS 掉入真實頁面**先見到嘅,唔係跑測試跑出嚟 —— 所以三項當時
都冇一個失敗測試。

- **廠商 SBOM 比對睇唔到 BIOS 模組清單。** 一份 BIOS 嘅廠商 SBOM 列嘅就係模組,
  但比對只認得簽章命中、套件同 Espressif 元件 —— 結果 **`PciBusDxe` 被報成「聲明
  咗但未觀察到」,而佢就喺上面張清單度**。廠商列幾多個模組就錯幾多個。
  呢個唔係「答少咗」,係**答錯咗**:睇落一切正常,實情係根本冇比對成功。
  而家用返同 opacity 調和一樣嗰份 `structural_components()`,一個真實嘅 `DxeCore`
  版本衝突亦因此浮返出嚟。
- **瀏覽器將 123 個模組全部標成簽章命中** —— 冇一個係由字串比對嚟嘅,呢個標籤
  等於逐個講錯。而家標「UEFI 模組」。
- **頁面文案仲停留喺 Phase 4 之前**,成版嘢冇一句講到佢讀得到 PC BIOS。

### 測試

194 個(由 192 增加)。

---

## v1.15.0

| | |
|---|---|
| Tag | `v1.15.0` |
| 程式碼 commit | `8b00a2db8fa89e580360f9c1100633564d093bd2` |
| Build 日期 | 2026-09-16 |
| CPython | 3.12.7 embeddable, amd64(python.org 官方) |

Roadmap **Phase 4**:UEFI / PC BIOS。

### Portable 版(唯一交付形式)

| | |
|---|---|
| 檔案 | `dist-portable/fw2sbom-portable.zip` |
| 大小 | 11,256,788 bytes |
| SHA-256 | `2b9ab85e31e10d8afbd7075c7dc12f1eca02261b4381df9fda6a9c1a29f43e3f` |
| 內容 | 57 個檔案(多咗 `uefi.py`) |
| Reproducible | 是 |

### 包入面屬於我哋嘅檔案

| 檔案 | SHA-256 |
|---|---|
| `fw2sbom.py` | `aeaf35926d00db0cf01e88495b55961e6a8d41c804d701477075ed4262adfb3d` |
| `container.py` | `9366132ebeac6b27f92a1dfd3f6ff064b2dc101d707fb4cddb0fa3c11e9d5564` |
| `uefi.py` | `1d4e31601ee9c48a6d2f97f2a7fc927f4dadef606915ff20b70401ed9695d52b` |

其餘檔案與 v1.14.0 相同。

### 新增:`uefi.py`

BIOS 係唯一一類**字串比對乜都搵唔到**嘅韌體。一份 EDK2 release build 入面冇任何
函式庫 banner ——實測公開 OVMF 映像,成 4 MB,我哋**全部 36 個簽章一個都冇命中**。

但佢有另一樣嘢:**build 系統自己寫低嘅清單**。

- **每個模組都帶住自己個名**(`USER_INTERFACE` section),名被剝咗仲有 GUID 精確
  指認。同一份 OVMF:**123 個模組,119 個有名**。
- **結構就係切法**:flash descriptor → BIOS region → firmware volume → file →
  section,而其中一個 section 通常係 LZMA,入面先係真正嘅嘢。實測
  **1.4 MB 解開變 16 MB,123 個模組有 112 個喺入面**。唔解壓縮嘅工具見到十幾個
  模組就當讀完咗一份 BIOS。
- **解開嘅內容照樣跑字串比對** —— 嗰份 OVMF 唯一命中嘅元件(OpenSSL,得符號冇
  版本)就只有喺解壓後嘅 volume 先搵得到。
- **Management Engine 唔會當成韌體一部分**:客戶 dump 通常係成顆 SPI flash,ME
  係簽章過嘅 Intel 程式碼,Intel 以外冇人讀得明。依 descriptor 切開,ME 照實報
  opaque、未列舉。
- **指令集由 PE 檔頭讀出**(x86-64 / IA-32 / AArch64 / RISC-V),唔使估。

### 三個刻意嘅限制

- **唔發 purl。** UEFI 模組唔係任何生態系裡嘅套件,硬生一個 `pkg:generic/DxeCore`
  等於餵畀 CVE 比對系統一個世上冇嘅識別碼 —— 比留空更糟。身分用 GUID。
- **`VERSION` section 唔係函式庫版本。** EDK2 實務上幾乎永遠係 `1.0`,照報並附
  一句講明佢描述嘅係模組本身。
- **EFI/Tiano 壓縮認得但解唔開**,呢類 section 會**明確報告讀唔到**,而唔係略過
  ——略過會令清單靜靜變短。

### 修正(兩個係跑真檔先揭發到)

- **Pad file 嘅 GUID 係全 0xFF,同抹除 flash 一模一樣。** 用 GUID 判斷 volume
  結尾,會喺第一個 pad 度停 —— 真實 OVMF 入面**成個 PEI volume 嘅模組就係咁冇咗**。
- **Variable store 同模組 volume 共用檔頭。** 當 FFS 咁行會由 NVRAM 內容「生」出
  一個唔存在嘅模組。真實映像第一次跑就生咗一個。
- **只係切出嚟嘅區段被標成「已解開」。** `expanded` 嘅意思係「無論熵值幾高我哋都
  讀得明呢段」。但 ESP32 partition 同 UEFI flash region 只係由檔案切一段出嚟。
  後果:**加密嘅 ESP32 partition 或者 Intel ME 區會因為「我哋有佢啲 bytes」而被
  判成明文**。ESP32 嗰條路徑一樣受影響,一齊修咗。
- **Opacity 調和睇唔到結構性元件。** 啱啱列完 123 個 BIOS 模組,標題寫住「無法
  靜態識別元件」。調和函式而家連 UEFI / Espressif 元件一齊計。

### 測試

192 個(由 164 增加)。新增 `UefiTest` 二十項、`RealBiosTest` 八項(對住真實 OVMF
映像),連兩個合成 fixture(`uefi_volume.bin`、`uefi_flash.bin`)。CI 多咗一個
真實 BIOS 端到端 job。

### 驗證狀態

firmware volume / file / section / LZMA 呢條路係對住公開 EDK2 OVMF build 開發同
驗證嘅。**Intel flash descriptor 嗰段係照公開規格寫,未跑過真實廠商 dump** ——
手上仲未有客戶嘅 BIOS 樣本。

---

## v1.14.0

| | |
|---|---|
| Tag | `v1.14.0` |
| 程式碼 commit | `ac1e1303667e1807f4319056ed476d1c6e413184` |
| Build 日期 | 2026-09-16 |
| CPython | 3.12.7 embeddable, amd64(python.org 官方) |

### Portable 版(唯一交付形式)

| | |
|---|---|
| 檔案 | `dist-portable/fw2sbom-portable.zip` |
| 大小 | 11,246,254 bytes |
| SHA-256 | `b25f09724d59e1d96b8358601c5e77b178734f9ab548dc881ef252cba82a1776` |
| 內容 | 56 個檔案 |
| Reproducible | 是 |

### 包入面屬於我哋嘅檔案

| 檔案 | SHA-256 |
|---|---|
| `fw2sbom.py` | `8200d052667e9b1ddaa93ba107bc9cd435ebc9af45c0bf2764c96790335be160` |
| `service.py` | `ee77a04f742391b484a7363cabc45b4bead9bc107c8b79fe38e6b849be37f520` |
| `vendor_sbom.py` | `46d282e21ca523b5ea209c7aa989320145b104f0ee81d583b7ba82e43f0243d5` |

其餘檔案與 v1.13.1 相同。

### 新增

- **拖拉介面可以匯入廠商 SBOM。** 呢條路本來淨係 CLI 有 —— 而最需要佢嗰批客戶,
  正正就係最掂唔到 CLI 嗰批:映像加密就讀唔到入面嘅元件,任何靜態工具都一樣,
  唯一出路係向供應商攞佢自己嘅 SBOM(CRA 下製造商本來就有權要求)。
- **一次可以放多份**(一個產品往往唔止一個供應商,合併成一份就分唔出邊句係邊個講)。
  加或者減廠商文件會即時重跑比對,唔會留低一個舊結果喺畫面。
- **衝突行先。** 每份文件顯示「獲映像佐證 / 版本衝突 / 未觀察到」,衝突用紅色標出
  —— 廠商聲明嘅版本同映像入面編咗嘅唔同,係成個比對功能存在嘅理由。
- **讀唔到嘅廠商檔案會講明原因,唔會靜靜略過。**「0 個衝突」同「我哋根本打唔開你
  供應商嗰份檔案」喺畫面上一模一樣,除非後者講出嚟。而且唔會連累客戶本來要嘅
  韌體分析。
- **上傳嘅廠商 SBOM 一樣唔會寫入磁碟**(`vendor_sbom.loads()` 直接讀 bytes),
  頁面上印住嗰句承諾維持成立。
- 頁面文案補返 v1.12.0 同 v1.13.0 嘅輸入格式:`.hex` / `.s19` / `.uf2` / `.elf` /
  ESP32 映像同整顆 flash dump。之前淨係寫住 `.bin`,客戶根本唔知可以掉其他格式入去。

### 修正

- **冇 purl 嘅廠商 SBOM 比對唔到任何嘢。** 比對淨係用 purl 做 key,但供應商自己產
  嘅 SPDX 好多時冇 purl。結果成份文件都歸類做「聲明咗但未觀察到」—— 睇落好似一切
  正常,其實係根本冇比對成功。而家 purl 同名稱都當 key。

### 已取消

- **PyInstaller 單檔 `.exe`。** 冇數位簽章,Windows SmartScreen 會跳「未知發行者」,
  而 portable 版存在嘅理由就係繞開呢件事;同時維護兩種交付形式等於維護一個較差嘅。
  `fw2sbom-service.spec` 已移除,歷史 release 嘅 exe 紀錄保留。

### 測試

164 個(由 155 增加)。新增服務端廠商 SBOM 七項、比對規則兩項,連 `parse_multipart`
第一次有測試(佢之前會靜靜掉咗除最後一份之外嘅所有廠商檔案)。

---

## v1.13.1

| | |
|---|---|
| Tag | `v1.13.1` |
| 程式碼 commit | `93d202b2ab84c3db09e30994db54be07b15bd9e7` |
| Build 日期 | 2026-09-14 |
| CPython | 3.12.7 embeddable, amd64(python.org 官方) |

### Portable 版(免簽章,推薦交付)

| | |
|---|---|
| 檔案 | `dist-portable/fw2sbom-portable.zip` |
| 大小 | 11,242,539 bytes |
| SHA-256 | `16cdaada6a7f1cb3816e3723597a1350cd2e305cff1eeed489535482bfd89a10` |
| 內容 | 56 個檔案 |
| Reproducible | 是 |

### 包入面屬於我哋嘅檔案

| 檔案 | SHA-256 |
|---|---|
| `fw2sbom.py` | `ff65ecd77989c7f5f49aca1eb1c1f07c9388c7fde1f3a9517a32e7432e665ae6` |
| `service.py` | `ba96f63a2a74ff9d2facdd19873b4a351e7fb961bbd3ff85c1f46654d31969eb` |

其餘檔案與 v1.13.0 相同。

### 修正

- **瀏覽器畫面上嘅元件清單同下載到嘅文件唔一致。** 畫面嗰份係另外砌嘅(只睇
  signature、embedded standard、套件資料庫),所以之後加嘅每一種來源
  ——廠商 SBOM、os-release、Espressif app descriptor——都係文件入面有、畫面上冇。
  一份 ESP32 韌體畫面顯示 1 個元件,下載到嘅文件有 3 個。客戶先睇畫面、再把
  檔案交畀稽核,兩者唔一致就冇嘢分得出邊份啱。
  **畫面嗰份而家由文件本身推出嚟**,冇得再各行各路。
- **唯一保留嘅差異已經寫明:**讀唔到嘅區段會以 `fw2sbom:opaque` 記錄喺 SBOM 入面
  (「呢度列舉唔到」本身就係一項發現),但唔會擺上畫面同已識別嘅元件排埋一齊
  ——噉樣睇落好似我哋識別咗佢。
- **Signature 元件而家一樣帶 `fw2sbom:evidence_class`**(其餘幾種本來就有)。
  呢個欄位就係「由套件資料庫讀出」同「有條字串啱啱命中 regex」之間嘅分別。
- **廠商 SBOM 比對有同一個盲點,只係喺另一邊:**攞嚟同廠商文件對帳嗰份平面清單
  漏咗 Espressif 元件,所以 ESP32 韌體同任何廠商 SBOM 都「完全一致」。廠商聲稱
  嘅 IDF 版本同映像自己宣告嘅唔同,正正就係呢個功能存在嘅理由。

### 測試

155 個(由 151 增加)。

---

## v1.13.0

| | |
|---|---|
| Tag | `v1.13.0` |
| 程式碼 commit | `35cf37a49aa0582653236904039dfded78fa6d69`(ESP32 實作;`v1.13.0` 標籤指向之後嗰個發佈 commit) |
| Build 日期 | 2026-09-14 |
| CPython | 3.12.7 embeddable, amd64(python.org 官方) |

Roadmap **Phase 3(第二階段)**:Espressif ESP32 系列。

### Portable 版(免簽章,推薦交付)

| | |
|---|---|
| 檔案 | `dist-portable/fw2sbom-portable.zip` |
| 大小 | 11,242,015 bytes |
| SHA-256 | `6b014fcc5b3d657e98c1dbeaf1ab9f9b38b1c36ab71dc38465b68cdd27eb3296` |
| 內容 | 56 個檔案(多咗 `esp32.py`) |
| Reproducible | 是 |

### 包入面屬於我哋嘅檔案

| 檔案 | SHA-256 |
|---|---|
| `fw2sbom.py` | `01540f85b3551e916584ea623a3e9fecfeb8df54161ea19c009d99aa2c422f33` |
| `container.py` | `2e946118b0760620ffcbbd283d631710951b79769063902f0fd40a2b415a2ea5` |
| `esp32.py` | `9791d914db0122f1ee2f92eea3bbcd0f5cdfce1c0428b32a537bec02aa9bf162` |

其餘檔案與 v1.12.0 相同。

### 新增

- **`esp32.py`** —— ESP32 韌體按佢自己嘅結構切,唔再當一嚿嘢掃:

  | 輸入 | 切法 |
  |---|---|
  | Application image(OTA 檔) | 24-byte header + 每個帶載入位址嘅 segment |
  | 整顆 flash / factory 檔 | 0x1000 bootloader、0x8000 partition table,**按 partition 切** |

- **晶片型號係讀出嚟,唔係估**。Header 嘅 chip ID 直接寫明 ESP32 / S2 / S3 /
  C2 / C3 / C5 / C6 / H2 / P4,連帶指令集。**冇任何熵值或 opcode 統計分得開
  Xtensa 同 RISC-V**,但呢個欄位分得開。表上冇嘅新型號會照實報
  `unknown chip 0xNNNN`。
- **ESP-IDF 版本由 `esp_app_desc_t` 讀出** —— 結構欄位,唔係啱啱命中 regex 嘅
  字串,所以 confidence 同套件資料庫同級(0.97),
  `fw2sbom:evidence_class = esp-idf-app-descriptor`。連帶讀出專案名稱、應用
  版本、build 日期時間、原始 ELF 嘅 SHA-256。
- **空欄位當冇資料**。真實 build 好多時只填一部分(公開嘅 Tasmota 映像淨係填
  `idf_ver`),空字串唔會變成「版本係空字串」嘅元件 —— 嗰樣比冇元件更糟,因為
  CVE 比對會當真。
- **Flash dump 入面邊個 image 代表產品**:帶 app descriptor 嗰個。Bootloader
  位置最低但永遠冇 descriptor,攞第一個搵到嘅會報錯 entry point 兼漏咗 IDF
  版本。

### 驗證

唔淨止合成 fixture:ESP32 同 ESP32-C3 嘅公開 Tasmota v15.6.0 映像、加一份完整
factory flash 映像都實際跑過,三份都讀到 `esp-idf 5.5.4.260407`。真實 partition
佈局唔一定照教科書(Tasmota 用 `safeboot` 而唔係 `factory`)—— 呢點就係跑真檔
先見到嘅。

### 已知限制

ESP-IDF 本身帶咗 mbedTLS、lwIP、FreeRTOS,但**版本唔會由 IDF 版本推導出嚟**。
Tasmota 呢類 release build 剝走咗呢啲元件自己嘅字串(成個 2 MB 映像有 7,070 段
可列印字串,但一個 `mbedtls` / `lwip` / `FreeRTOS` 都冇),所以 SBOM 就唔會有
佢哋 —— 呢個係「讀唔到」,唔係「唔存在」。

### 測試

151 個(由 133 增加)。新增 `EspressifTest` 十八項,連兩個合成 fixture
(`esp32_app.bin`、`esp32_flash.bin`),兩者都納入 CycloneDX schema 驗證。

---

## v1.12.0

| | |
|---|---|
| Tag | `v1.12.0` |
| Build 日期 | 2026-09-14 |
| CPython | 3.12.7 embeddable, amd64(python.org 官方) |

Roadmap **Phase 3(第一階段)**:交付格式。

### Portable 版(免簽章,推薦交付)

| | |
|---|---|
| 檔案 | `dist-portable/fw2sbom-portable.zip` |
| 大小 | 11,236,313 bytes |
| SHA-256 | `33d2d753f258a3790bbecc7f93fce17022f6533139da733fb336b1966b74af9c` |
| 內容 | 55 個檔案(多咗 `image_input.py`) |
| Reproducible | 是 |

### 包入面屬於我哋嘅檔案

| 檔案 | SHA-256 |
|---|---|
| `fw2sbom.py` | `cf95b312453a0d8d508c8c08c8c914d7867346f9a589854142d897f3fa359236` |
| `image_input.py` | `58baf56e63a7ddd2eeb0ce909a0ad324c73bd60e57fb03b5db7a08c3d8120aa1` |
| `service.py` | `119d0882f4ab7ee4b2a14cbc30f28e4b0edca2e293300230ab67ef89186f56f0` |

其餘檔案與 v1.11.0 相同。

### 新增

- **`image_input.py`** —— 直接讀四種交付格式,唔再叫人先跑 `objcopy`:

  | 格式 | 來源 | 定址 |
  |---|---|---|
  | Intel HEX | 燒錄工具 | 16 / 20 / 32-bit |
  | Motorola S-record | 燒錄工具 | 16 / 24 / 32-bit |
  | UF2 | RP2040、部分 Nordic | 512-byte 區塊 |
  | ELF | linker 直接輸出 | PT_LOAD 區段 |

- **空隙填 `0xFF`** —— 四種格式都係稀疏嘅,重組要決定空隙放咩。`0xFF` 係抹除
  flash 讀出嚟嘅值,亦係裝置自己會見到嘅嘢。填充量會如實記錄。
- **重組過程寫入 SBOM** —— `input_format`、`image_base_address`、`entry_point`、
  `padding_inserted_bytes`,加一句 `offset_basis` 講明「本文件嘅 offset 指向重建
  出嚟嘅映像,唔係交付檔案入面嘅位元組位置」。
- **雜湊仍然描述交付檔案** —— 客戶核對嘅係人哋寄畀佢嗰個檔案,唔係我哋重建出嚟
  嗰個。
- ELF 讀 ARM / MIPS / RISC-V / Xtensa / AArch64;`p_paddr` 優先於 `p_vaddr`
  (MCU 上 load address 先係位元組實際寫入嘅地方)。
- Object file(冇 program header)會明確拒絕並講明「多數係 object file 而唔係
  linked image」。

### 修正

- **v1.10.0 引入逐區段判定嗰陣,漏咗「指令集正面識別即為明文」呢條規則。**
  密集 MCU 程式碼本來就達 7 bits/byte,單靠熵值門檻會判成加密 —— 結果
  **普通 Cortex-M 韌體被報成讀唔到嘅加密區段**。v1.10.0 同 v1.11.0 都受影響。
- 當時所有測試都通過,因為測試輔助函式跳過咗 `main()` 實際會行嗰步
  (`summarise_opacity`)。輔助函式而家同 `main()` 行同一條路,並加咗一項測試
  直接鎖住呢個行為。

### 測試

133 個(由 122 增加)。新增 `InputFormatTest` 七項、`ReassembledAnalysisTest`
三項,同一項專門鎖住上面嗰個 regression。

### 驗證

同一份韌體以五種形式交付(`.bin`、`.hex`、`.s19`、`.uf2`、`.elf`),
**五次分析結果完全一致**。

---

## v1.11.0

| | |
|---|---|
| Tag | `v1.11.0` |
| Build 日期 | 2026-09-14 |
| CPython | 3.12.7 embeddable, amd64(python.org 官方) |

Roadmap **Phase 2 完成**:廠商 SBOM 匯入與比對。

### 點解要有呢樣

靜態分析有硬上限。映像加密,元件就喺密碼後面 —— 唯一出路係向供應商攞佢哋自己
嘅 SBOM。v1.10.0 喺一部真實 CCTV 上示範咗呢個上限:kernel 熵值 7.9999,
ECB 模式特徵,再落去冇嘢可以做。

### Portable 版(免簽章,推薦交付)

| | |
|---|---|
| 檔案 | `dist-portable/fw2sbom-portable.zip` |
| 大小 | 11,230,514 bytes |
| SHA-256 | `fa1a571814f800ee4cc0cc705acd617509f986fef9eaee7d0e7d94b2d353c1b6` |
| 內容 | 54 個檔案(多咗 `vendor_sbom.py`) |
| Reproducible | 是 |

### 包入面屬於我哋嘅檔案

| 檔案 | SHA-256 |
|---|---|
| `fw2sbom.py` | `9119096f908bd75c9a137be3958c7ec745449ac78d0dee16362496bbf73227a4` |
| `vendor_sbom.py` | `3b92b6056bc3dcf54192402c6ead76e2ba3fd1fe9616c0cb09b65f62bdab6c10` |

其餘檔案與 v1.10.0 相同。

### 新增

- **`--vendor-sbom FILE`**(可重複)—— 接受 CycloneDX 1.x 或 SPDX 2.x JSON,
  因為廠商用邊套工具就出邊種格式。
- **來源保留** —— 每個合併入嚟嘅元件標明出自邊份文件(檔名、格式、序號、產生
  工具、時間),`evidence_class = vendor-sbom`,而且 **confidence 係 0.0**:
  我哋冇觀察過佢,唔會安一個我哋冇嘅信心值上去。
- **三種關係標記** —— `vendor_corroborated`(映像佐證到)、`vendor_conflict`
  (同映像衝突)、`vendor_unverified`(未觀察到,既唔證實亦唔否定)。
- **版本衝突獨立記錄** —— 廠商聲稱嘅版本同映像入面實際嘅唔同,會出現喺 CLI
  輸出、SBOM metadata,同該元件嘅 property。呢個係一項發現,唔係一個要擺平嘅
  分歧;工具冇資格決定邊個啱,只有資格指出兩者唔同。
- 比對用**去版本嘅 purl** 做主鍵,冇 purl 先用名稱。

### 測試

122 個(由 113 增加)。新增 `VendorSbomTest` 九項:CycloneDX 與 SPDX 讀取、
四種壞文件、版本衝突偵測、來源標記、多文件合併、合併後仍通過 schema。

### 驗證

同時合併一份 CycloneDX 同一份 SPDX 落真實 router 映像:371 個元件,
CycloneDX 與 SPDX 輸出各自 **0 schema errors**。

---

## v1.10.0

| | |
|---|---|
| Tag | `v1.10.0` |
| Build 日期 | 2026-09-14 |
| CPython | 3.12.7 embeddable, amd64(python.org 官方) |

Roadmap **Phase 2(第四階段)**:分區段 opacity 判定。

### 呢個版本修咗一個會令客戶收到錯誤結論嘅缺陷

一份 64 MB 嘅 flash dump,入面得 3.6 MB 加密 kernel,其餘係抹除過嘅空白 flash。
整份一齊量:熵值 **0.736**,判定 **plaintext**,SBOM 講「呢份韌體係明文,而且
冇任何元件」。

真相係佢唯一嘅內容區段**根本讀唔出嚟**(熵值 7.9999、最長同值 run 3、2083 個
重複 16-byte 對齊區塊 —— ECB 模式特徵)。

**將「讀唔到」報成「入面冇嘢」,正正係呢個工具存在嘅理由要防止嘅事。**

| | v1.9.0 | v1.10.0 |
|---|---|---|
| 判定 | `plaintext`(熵值 0.736) | `opaque`(熵值 7.9999) |
| Opaque 元件 | 0 | 1(帶 offset、大小、判定依據) |
| 空白區段 | 「unidentified region」 | 認出係抹除過嘅 flash |

### Portable 版(免簽章,推薦交付)

| | |
|---|---|
| 檔案 | `dist-portable/fw2sbom-portable.zip` |
| 大小 | 11,225,043 bytes |
| SHA-256 | `0e46012b0d6f1cdd507e38acccbfa7b981852cca159e4ce97e4b83bc0f543ab1` |
| 內容 | 53 個檔案 |
| Reproducible | 是 |

### 包入面屬於我哋嘅檔案

| 檔案 | SHA-256 |
|---|---|
| `fw2sbom.py` | `ef730c62c5665640e76b3eb7768217a58551f47705f091123915bd022d6659ea` |
| `service.py` | `23ee6e68287663b1a9b02cf5a76726fd954dc21d3e22dc760c1d93409821c802` |

其餘檔案與 v1.9.0 相同。

### 新增

- **逐區段 opacity 判定** —— 每個區段用自己嘅位元組判定,唔再由整份映像一個
  數字決定。
- **抹除 flash 識別** —— ≥99% 係 0x00/0xFF 嘅區域認出係空白,唔計入判斷,
  標籤由「unidentified region」改為「blank flash」。
- **每個讀唔到嘅區段各自成為一個 opaque 元件** —— 帶 offset、大小、熵值、
  判定依據,而唔係整份映像一個籠統標記。
- **頭條判定由區段推導** —— 而且會寫明「整份一齊量會得到 X;嗰個數字被冇內容
  嘅區域主導咗」,令讀報告嘅人知道點解天真嘅量法會出錯。
- CLI 唔再淨係講「0 component(s) identified」;會補「N region(s) could not be
  enumerated and are recorded as opaque」。

### 測試

113 個(由 106 增加)。新增 `SegmentOpacityTest` 七項,連同一個新嘅合成 fixture
`encrypted_kernel.bin` —— 重現「細加密區 + 大空白尾」呢個缺陷類型,唔含任何
客戶資料。

---

## v1.9.0

| | |
|---|---|
| Tag | `v1.9.0` |
| Build 日期 | 2026-09-14 |
| CPython | 3.12.7 embeddable, amd64(python.org 官方) |

Roadmap **Phase 2(第三階段)**:掃描根檔案系統入面嘅檔案。

### 之前嘅缺口

Filesystem segment 嘅 `content` 係 `None`,所以 rootfs 入面 3274 個檔案
**一個都冇被掃過簽章**。rootfs 嘅資訊全部嚟自套件資料庫同 ELF 中繼資料。
有資料庫嗰陣冇乜所謂;冇資料庫嘅映像(大部分非 OpenWrt 廠商裝置)就完全
攞唔到 rootfs 嘅元件。

### 對真實韌體嘅效果

同一台 GL.iNet router,**模擬冇套件資料庫**(即係 CCTV 嗰種情況):

| | v1.8.0 | v1.9.0 |
|---|---|---|
| rootfs 元件 | **0** | **9** |
| 總元件(signature) | 6 | 15 |

以套件資料庫做 ground truth 對過,版本全部啱:BusyBox 1.35.0
(`/bin/busybox`)、curl 7.88.1(`/usr/bin/curl`)、zlib 1.2.11
(`/usr/lib/libz.so.1.2.11`)、U-Boot 2022.01(`/usr/sbin/fw_printenv`)。

**有套件資料庫嗰陣結果完全不變**(366 個元件)—— 冇加噪音。

### Portable 版(免簽章,推薦交付)

| | |
|---|---|
| 檔案 | `dist-portable/fw2sbom-portable.zip` |
| 大小 | 11,223,099 bytes |
| SHA-256 | `92e1af9c566888d6affe155ae63ba5ef8635997d6932915f84cd20b5020c512e` |
| 內容 | 53 個檔案 |
| Reproducible | 是 |

### 包入面屬於我哋嘅檔案

| 檔案 | SHA-256 |
|---|---|
| `fw2sbom.py` | `f0f7a3b11414607cde356e358b62831bd76f5fe1e0e454e8625a21814c2e57a1` |
| `container.py` | `64515067d21dd5e3804628eda8167c1bf31f5ea3c218281b488df0b1251ff7a6` |

其餘檔案與 v1.8.0 相同。

### 新增

- **逐檔簽章比對** —— 掃描**冇被任何套件認領**嘅 rootfs 檔案。套件管理員嘅記錄
  對佢涵蓋嘅檔案係權威嘅,喺上面再疊啟發式只會加噪音;佢冇涵蓋嗰部分先係新資訊。
  冇套件資料庫嘅裝置,咁就係每一個檔案。
- **證據指向實際檔案路徑** —— 稽核人員可以去睇 `/usr/sbin/dropbear`;
  「offset 0x3f1a80」佢做唔到任何嘢。
- **區分可執行檔同其他檔案** —— 編譯進二進位檔嘅 banner 同設定檔入面一行版本
  註記,證據力唔同。`fw2sbom:evidence_file_kind` 記低。
- **排除套件管理員自己嘅 bookkeeping 目錄** —— `.control` 入面有
  `Description: The OpenSSL Project is ...`,掃佢會撞出冇版本、來源係文字檔嘅
  假 `openssl` 命中。

### 修正

- **證據引用錯檔案。** 原本用該元件**字母序第一個**檔案,唔一定係產生嗰句引文
  嘅檔案。實測中 OpenSSL 嘅版本引文嚟自 `/usr/bin/openssl`,文件卻指住一個 YAML
  設定檔。喺稽核文件裡面指錯檔案唔係外觀問題。

### 測試

106 個(由 101 增加)。新增五項,包括「有資料庫時唔可以掃已認領檔案」、
「永遠唔掃套件 metadata」、「模擬冇資料庫並以資料庫做 ground truth 核對版本」。

corpus 測試嘅「冇套件資料庫」分析改為每個 class 算一次 —— 逐個測試方法重算
令套件執行時間由 30 秒變 69 秒。

---

## v1.8.0

| | |
|---|---|
| Tag | `v1.8.0` |
| Build 日期 | 2026-09-14 |
| CPython | 3.12.7 embeddable, amd64(python.org 官方) |

Roadmap **Phase 2(第二階段)**:讀 rootfs 入面嘅二進位檔。

### 對真實韌體嘅效果

同一台 GL.iNet router,同 v1.7.0 比:

| | v1.7.0 | v1.8.0 |
|---|---|---|
| 元件數 | 366 | 366 |
| 指令集 | **未識別** | **MIPS (32-bit little-endian)** |
| 帶授權嘅元件 | 0 | **262** |
| 帶 CPE 嘅元件 | 0 | **54**(廠商自己聲明) |
| 套件間依賴邊 | 0 | **1268** |
| 分析時間 | 10.2 秒 | 11.4 秒 |

### Portable 版(免簽章,推薦交付)

| | |
|---|---|
| 檔案 | `dist-portable/fw2sbom-portable.zip` |
| 大小 | 11,221,328 bytes |
| SHA-256 | `5efad0a0e08992844c79e8f75b19b30b290f77e574f96baabac3ae4e6d4b6eed` |
| 內容 | 53 個檔案(多咗 `elf.py`) |
| Reproducible | 是 |

### 包入面屬於我哋嘅檔案

| 檔案 | SHA-256 |
|---|---|
| `fw2sbom.py` | `516f6262cf7772ab596a79d40549cff12cbce580cf774afb1cd4b18a9ca87c80` |
| `container.py` | `56972c5d6bb363b2d2c024e7d941f7ef80121ce3b5987353711da474a534ba82` |
| `squashfs.py` | `1e36e5b2504e32b123de66ff4b35d9229f6426fba51dcfe8a172b17450002486` |
| `elf.py` | `1ea84f0f4845e279d5d0805a170b0dc970e43f1b8122e914d47981c895de8ccf` |
| `service.py` | `08f4f58f72db7eb594918dad3d283959475a8f47ffd33bc4612791522c9abecc` |
| `evidence_report.py` | `5d22a065d38f2213ac9f7a4c310f135ca75bfa914e413b1f0ba14e43a65bbdcc` |
| `spdx_report.py` | `ba3f0a59854c530d849ca830d1492b551760d78f3de25bffa65575542b2c97aa` |
| `LICENSE-fw2sbom.txt` | `9d47d54f77f5293428d31103bb43035246593eb24d28795160dc03ad8c9e0021` |
| `THIRD-PARTY-NOTICES.txt` | `d91e52359c2f14dc8e2f982afc913b99367316dba03418143340a6138b22bf98` |

簽章包、圖片與 `Start-fw2sbom.bat` 與 v1.7.1 相同。

### 新增

- **`elf.py`** —— 唯讀 ELF reader,純 stdlib。讀 header、dynamic table 同幾個
  具名 section。真實 rootfs 467 個 ELF,0.68 秒,零警告。
- **指令集識別** —— Linux 映像冇向量表可以認,之前一律回報「未識別」。
  ELF header 直接講明。
- **真正嘅依賴圖** —— 兩個獨立來源:套件管理員聲明嘅 `Depends`,同 linker 實際
  寫入每個 binary 嘅 `DT_NEEDED`。前者係意圖,後者係實際連結嘅證據。用 opkg 嘅
  檔案清單將檔案層級嘅邊升去套件層級 —— 1268 條。兩者都冇嘅套件就冇出邊,
  唔會砌一條出嚟。
- **聲明授權** —— 讀 `.control` 嘅 `License:`,362 個套件入面 262 個有。
  CycloneDX `licenses` 欄位,標記 `license_source = package-database`。
- **廠商聲明嘅 CPE** —— OpenWrt 自己喺 `.control` 寫 `CPE-ID:`,54 個套件有,
  啱啱好係 CVE 相關嗰批(busybox、curl、dropbear、dnsmasq、iptables、openssl…)。
  轉成 CPE 2.3 並標記 `cpe_source = declared-in-package-database`。
  **呢個唔係之前取消咗嘅「產生 CPE」** —— 係讀取廠商已經聲明嘅識別碼。
- **Kernel module metadata** —— `.modinfo` 嘅 version / license / description。
  192 個 module,179 個聲明 GPL。

### 效能

SquashFS reader 加咗 fragment block 快取。細檔案打包喺共用嘅 fragment 入面,
逐個讀就會重複解壓同一個 block —— 讀 467 個 ELF 由 **12.01 秒減到 0.68 秒**。

### 測試

101 個(由 88 增加)。新增 `ElfReaderTest`(含截斷、非 ELF、荒謬 header 計數等
不可信輸入案例)同六項 corpus 測試。

---

## v1.7.1

| | |
|---|---|
| Tag | `v1.7.1` |
| Build 日期 | 2026-09-11 |
| CPython | 3.12.7 embeddable, amd64(python.org 官方) |

授權釐清。**分析行為完全冇變**,只係加咗授權檔並令佢哋隨套件一齊交付。

### Portable 版(免簽章,推薦交付)

| | |
|---|---|
| 檔案 | `dist-portable/fw2sbom-portable.zip` |
| 大小 | 11,212,984 bytes |
| SHA-256 | `0eff7d0d310e2d256b7209673acc1d4dffd9f6eab16df3e03b49a42879b6106b` |
| 內容 | 52 個檔案(多咗 `LICENSE-fw2sbom.txt`、`THIRD-PARTY-NOTICES.txt`) |
| Reproducible | 是 —— `.\scripts\build-portable.ps1` |

### PyInstaller 單檔 exe

**呢個版本冇 build。** 用 `pyinstaller fw2sbom-service.spec`。

### 包入面屬於我哋嘅檔案

| 檔案 | SHA-256 |
|---|---|
| `fw2sbom.py` | `d3387ff901d2d580c35f7bc77373b7516b5298f16cf33773ab90fad7c81b553e` |
| `container.py` | `322f3e638388c7e50122fa689c8b1c50c2e1458db71d799ac2cd30c5290ed510` |
| `squashfs.py` | `0ff94cf6468983c694ebdccd71a9c85799c5de21fe00674747311ffccaf92326` |
| `service.py` | `08f4f58f72db7eb594918dad3d283959475a8f47ffd33bc4612791522c9abecc` |
| `evidence_report.py` | `5d22a065d38f2213ac9f7a4c310f135ca75bfa914e413b1f0ba14e43a65bbdcc` |
| `spdx_report.py` | `ba3f0a59854c530d849ca830d1492b551760d78f3de25bffa65575542b2c97aa` |
| `LICENSE-fw2sbom.txt` | `9d47d54f77f5293428d31103bb43035246593eb24d28795160dc03ad8c9e0021` |
| `THIRD-PARTY-NOTICES.txt` | `d91e52359c2f14dc8e2f982afc913b99367316dba03418143340a6138b22bf98` |
| `onecra_logo.png` | `a870f4d03b9bdbcc4c6bbc0077c09872bfe49a627400338a46d42a72b4a0c589` |
| `onecra_icon.png` | `21b5280d2f905b5c7ccbcd1b8f284371f24e374e212f71a2838813f98b7596a1` |
| `Start-fw2sbom.bat` | `1c52c4f0c7d2cae205dc199475c8a666e20e180a7301b7354499c1106a7adee5` |

簽章包與 v1.7.0 相同,未變動。

### 新增

- **[LICENSE](LICENSE)** —— 專有授權,保留一切權利。Repo 公開只係因為 GitHub Pages
  要 serve 下載頁,唔等於開源。明確允許客戶**自由使用、發佈、再散布 fw2sbom
  產生嘅 SBOM 與報告** —— 產出物屬於使用者,Onecra 唔主張權利。亦明確允許
  **閱讀原始碼做評估、安全審查同稽核**:一個產供應鏈文件嘅工具,應該容許依賴
  嗰份文件嘅人檢查佢。
- **[THIRD-PARTY-NOTICES.md](THIRD-PARTY-NOTICES.md)** —— 我哋散布咗啲乜唔係自己寫。
  Runtime 依賴:冇。隨套件散布:CPython 3.12.7(PSF 授權,未修改)。
- 兩份檔案而家**隨 portable 套件一齊交付**,分別叫 `LICENSE-fw2sbom.txt` 同
  `THIRD-PARTY-NOTICES.txt`。

### 修正

- **套件入面本來只有 Python 嘅授權檔。** 客戶解壓見到 `LICENSE.txt`(PSF)擺喺
  我哋原始碼隔離,合理會以為成個嘢係 PSF 授權 —— 一個歧義,喺一個做合規嘅產品
  身上特別唔應該有。
- 打包腳本刻意將我哋嗰份改名為 `LICENSE-fw2sbom.txt`,**唔可以蓋過 Python 嗰份**。
  覆蓋掉自己再散布嘅軟體嘅授權檔,正正係呢個專案喺人哋韌體入面要捉嘅錯誤。
  腳本亦加咗一項檢查:`LICENSE.txt` 唔見咗就直接中止,因為冇佢我哋冇權散布
  嗰個直譯器。

---

## v1.7.0

| | |
|---|---|
| Tag | `v1.7.0` |
| Build 日期 | 2026-09-11 |
| CPython | 3.12.7 embeddable, amd64(python.org 官方) |

Roadmap **Phase 2(第一階段)**:Linux 裝置韌體。Router / gateway / NVR 由
「0 個元件」變成「完整套件清單」。

### 對真實韌體嘅效果

GL.iNet GL-MT300N-V2(Mango),OpenWrt 22.03.4,MIPS,14.6 MB:

| | v1.6.0 | v1.7.0 |
|---|---|---|
| 元件數 | **0** | **366** |
| 判定 | `opaque (compressed)` | 逐區段分析 |
| 帶精確版本 | 0 | 362 |
| 分析時間 | 6.7 秒 | 10.2 秒 |

搵到嘅嘢包括 OpenWrt 22.03.4、Linux 5.10.176、GCC 11.2.0、binutils 2.37,
加上 opkg 資料庫入面 359 個套件嘅精確版本 —— BusyBox 1.35.0、OpenSSL 1.1.1t、
dropbear 2022.82、curl 7.88.1、zlib 1.2.11、nginx 1.17.7、OpenVPN 2.5.7 等等。

### Portable 版(免簽章,推薦交付)

| | |
|---|---|
| 檔案 | `dist-portable/fw2sbom-portable.zip` |
| 大小 | 11,209,894 bytes |
| SHA-256 | `736095fff98937ad8571b923d72e9b89759ef4d5a192c6f50fca5348449d8543` |
| 內容 | 50 個檔案(多咗 `container.py`、`squashfs.py`、`toolchain.json`) |
| Reproducible | 是 —— `.\scripts\build-portable.ps1` |

### PyInstaller 單檔 exe

**呢個版本冇 build。** 用 `pyinstaller fw2sbom-service.spec`。

### 包入面屬於我哋嘅檔案

| 檔案 | SHA-256 |
|---|---|
| `fw2sbom.py` | `2693c306e15a2baa48fbc3de55af581f335e863c28d057a143f3641c0408c3d4` |
| `container.py` | `322f3e638388c7e50122fa689c8b1c50c2e1458db71d799ac2cd30c5290ed510` |
| `squashfs.py` | `0ff94cf6468983c694ebdccd71a9c85799c5de21fe00674747311ffccaf92326` |
| `service.py` | `08f4f58f72db7eb594918dad3d283959475a8f47ffd33bc4612791522c9abecc` |
| `evidence_report.py` | `5d22a065d38f2213ac9f7a4c310f135ca75bfa914e413b1f0ba14e43a65bbdcc` |
| `spdx_report.py` | `ba3f0a59854c530d849ca830d1492b551760d78f3de25bffa65575542b2c97aa` |
| `onecra_logo.png` | `a870f4d03b9bdbcc4c6bbc0077c09872bfe49a627400338a46d42a72b4a0c589` |
| `onecra_icon.png` | `21b5280d2f905b5c7ccbcd1b8f284371f24e374e212f71a2838813f98b7596a1` |
| `Start-fw2sbom.bat` | `1c52c4f0c7d2cae205dc199475c8a666e20e180a7301b7354499c1106a7adee5` |
| `signatures/linux.json` | `699af29a5c54c678820bfdf928b7ecbef211012b5bf9ada9b3cd94edfbbddba4` |
| `signatures/mcu-lib.json` | `167b56b5107e1eb4bc8474a812cea962b916e0c8de712d0af62668c4d37bce8d` |
| `signatures/mcu-rtos.json` | `b87ccae1c638bd469f2c6d6766c54fc800ec7cee669fa1eba93235f8446271e3` |
| `signatures/toolchain.json` | `ab1f9a59e1c7c1011cee3f9e5b38777b8135153ef4e14856730fd9ef1a4c2c08` |
| `signatures/vendor-nordic.json` | `fef65845009fb7cb2d1522ffd03dbc087d2c725a4c03af06cdf4ff11ccabad3c` |
| `signatures/vendor-st.json` | `fe10c9a08959248b3bb00e847c2c69bcd4bbe4c9d8c2bb7d37b0c842cbccaf0d` |

### 新增

- **`container.py`** —— 容器走訪:U-Boot legacy uImage 檔頭、任意位置嘅壓縮區段、
  SquashFS superblock。每個區段獨立分析,SBOM 記低成個 segment map。
  解壓支援 gzip / xz / lzma / bzip2(全部 stdlib)。**lzo / lz4 / zstd 會明確
  報告「未展開」並指名演算法**,唔會靜默跳過。
- **`squashfs.py`** —— 唯讀 SquashFS 4.0 reader,純 stdlib。真實 12 MB rootfs
  走訪 3274 個檔案用 0.02 秒。
- **套件資料庫解析** —— opkg / dpkg / apk。呢個係 Linux 韌體 SBOM 品質嘅主要
  來源:唔係從 binary 估版本,而係套件管理員自己嘅安裝紀錄。
  `fw2sbom:evidence_class = package-database`。
- **發行版識別** —— `/etc/openwrt_release`、`/etc/os-release`。
- **`scripts/fetch-corpus.py`** 同 corpus 測試 —— 跑喺真實廠商韌體上。
  合成 fixture 只證明解析器符合規格書;真實映像先證明佢扛得住廠商實際出貨嘅嘢。
  CI 有獨立 job 跑呢組。
- 新簽章包 `toolchain.json`:通用 `gcc` 同 `gnu-binutils`。

### 修正

- **`gcc-arm-none-eabi` 會喺任何 GCC 編譯嘅映像上命中**,包括 MIPS。佢最高權重
  嘅 pattern 係通用嘅 `GCC: (...) x.y.z`,同個名完全唔夾 —— 喺稽核文件入面報
  「MIPS router 用 arm-none-eabi 工具鏈」係一句錯嘅陳述。通用嗰部分已拆去新嘅
  `gcc` 簽章;`gcc-arm-none-eabi` 而家淨係認 ARM 專屬字串。

### 對不可信輸入嘅處理

SquashFS reader 對深度、entry 數、單檔大小同總解壓量都設上限,並做目錄迴圈
偵測。呢啲唔係理論問題:開發期間一個**正常**嘅 OpenWrt rootfs 就令早期版本
遞迴咗 1000 層(當時係另一個 bug),而惡意構造嘅映像更加唔可以令分析器當掉或
耗盡記憶體。任何讀唔到嘅地方都唔會拋例外 —— 記一筆警告、回報讀得到嘅部分、
喺 SBOM segment 屬性寫明。

### 測試

88 個(由 73 增加)。新增 container、SquashFS 同 corpus 三組。
`KnownGapTest`(斷言「壓縮 Linux 韌體搵唔到嘢」)如預期失效,已換成
`ContainerTest` 斷言相反嘅能力 —— 呢個就係 roadmap 項目完成嘅訊號。

---

## v1.6.0

| | |
|---|---|
| Tag | `v1.6.0` |
| Build 日期 | 2026-09-11 |
| CPython | 3.12.7 embeddable, amd64(python.org 官方) |

Roadmap **Phase 1(部分)**:SPDX 2.3 輸出與版本策略。CPE 相關工作已取消 ——
客戶的 CVE 平台自行由 SBOM 以 ENISA 通報 API 比對,唔需要 fw2sbom 產生 CPE。

### Portable 版(免簽章,推薦交付)

| | |
|---|---|
| 檔案 | `dist-portable/fw2sbom-portable.zip` |
| 大小 | 11,196,490 bytes |
| SHA-256 | `a1e601f74fa8b6aec5e6c86c251062e2f902ad85f943d5ecc6a7486438354177` |
| 內容 | 47 個檔案(多咗 `spdx_report.py`) |
| Reproducible | 是 —— `.\scripts\build-portable.ps1`,CI 每次 build 兩次對 hash |

### PyInstaller 單檔 exe

**呢個版本冇 build。** 用 `pyinstaller fw2sbom-service.spec`。

### 包入面屬於我哋嘅檔案

| 檔案 | SHA-256 |
|---|---|
| `fw2sbom.py` | `3931b822e78b03178d6ab9e6140ac2410a35a18642a95f28819eee1dc65f1378` |
| `service.py` | `d7885c3f946769b029e193482f243d13a27cae8b9a33aec4a262b244cbdecc70` |
| `evidence_report.py` | `5d22a065d38f2213ac9f7a4c310f135ca75bfa914e413b1f0ba14e43a65bbdcc` |
| `spdx_report.py` | `ba3f0a59854c530d849ca830d1492b551760d78f3de25bffa65575542b2c97aa` |
| `onecra_logo.png` | `a870f4d03b9bdbcc4c6bbc0077c09872bfe49a627400338a46d42a72b4a0c589` |
| `onecra_icon.png` | `21b5280d2f905b5c7ccbcd1b8f284371f24e374e212f71a2838813f98b7596a1` |
| `Start-fw2sbom.bat` | `1c52c4f0c7d2cae205dc199475c8a666e20e180a7301b7354499c1106a7adee5` |
| `signatures/linux.json` | `699af29a5c54c678820bfdf928b7ecbef211012b5bf9ada9b3cd94edfbbddba4` |
| `signatures/mcu-lib.json` | `14f0c30b948af6ff58e996f3b111c00c66c354cb7066081f2eda820c85a97e09` |
| `signatures/mcu-rtos.json` | `b87ccae1c638bd469f2c6d6766c54fc800ec7cee669fa1eba93235f8446271e3` |
| `signatures/vendor-nordic.json` | `fef65845009fb7cb2d1522ffd03dbc087d2c725a4c03af06cdf4ff11ccabad3c` |
| `signatures/vendor-st.json` | `fe10c9a08959248b3bb00e847c2c69bcd4bbe4c9d8c2bb7d37b0c842cbccaf0d` |

### 新增

- **SPDX 2.3 JSON 輸出**(`spdx_report.py`)。CLI `--format {cyclonedx,spdx,both}`;
  web UI 多咗一個下載連結。兩份文件由**同一次分析**產生,唔可能互相矛盾。
  9 份 fixture 嘅 SPDX 文件全部通過 SPDX 規格自己嘅 schema。
  SPDX 2.3 冇 confidence / evidence 對應欄位,所以嗰啲入 `comment` 同
  `annotations`,並且喺文件本身寫明「兩者不一致時以 CycloneDX 為準」。
- **`--firmware-version`**:SBOM 根 component 嘅版本之前恆為 `UNKNOWN`(程式入面
  個 hook 一直存在但冇人填)。冇咗佢,同一產品嘅唔同 release 喺下游分辨唔到。
- **`version_note`**:有啲元件係**結構上**攞唔到版本 —— 真實 nRF5 韌體入面 nrfx
  同 DFU 只留低 API symbol,STM32 HAL 嘅版本係數值巨集唔係字串。呢啲簽章而家帶
  一段說明「點解攞唔到」同「去邊度攞」,輸出成
  `fw2sbom:version_unavailable_reason`。
- 測試規則由「最多 9 個簽章冇版本 pattern」改成「**每個簽章要麼有版本 pattern,
  要麼有 version_note**」—— 後者冇辦法用一個假 regex 矇混。

### 修正 / 改善

- **nRF Connect SDK 版本由推論變精確**。個 boot banner
  (`*** Booting nRF Connect SDK v2.6.0 ***`)本身就帶版本,之前個 pattern 冇
  capture group,所以要靠 Zephyr fork tag 反查出 `2.6.x`、confidence 0.4、purl
  唔帶版本。而家係 `2.6.0`、confidence 0.97、purl 帶版本。
  Fork tag 推論路徑仍然保留(冇 banner 嘅映像先用),並有獨立測試。
- 測試由 56 增至 73。

### 唔會做(已與需求方確認)

CPE 2.3 產生與 purl 規範化**取消**。客戶嘅 CVE 平台自行由 SBOM 比對,
用 ENISA 嘅 CVE 通報 API,唔需要 fw2sbom 出 CPE。呢項原本係 roadmap Phase 1
嘅主要內容。

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
