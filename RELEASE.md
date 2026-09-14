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
