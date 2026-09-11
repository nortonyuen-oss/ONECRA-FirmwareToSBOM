# fw2sbom

Evidence-based **CycloneDX 1.6 / SPDX 2.3** SBOM generator for embedded firmware images
(`.bin`):Linux 裝置(router / gateway / NVR:uImage + 壓縮 kernel + SquashFS
rootfs)、ARM Cortex-M 映像、MCS-51(8051)映像(顯示控制器 / monitor scaler
韌體),以及廠商 **packetized / ISP-dump** 格式(自動去框)。
Designed to run out-of-the-box on Kali Linux (Python 3.9+, stdlib only — no pip
dependencies).

## 分析流程 (Pipeline)

0. **封包容器偵測與去框 (de-framing)** — 見下方〈封包化映像〉
0.5 **容器走訪與解壓** — uImage 檔頭、壓縮區段、SquashFS 檔案系統;每個區段
   各自分析,rootfs 內的套件資料庫直接讀出(見下方〈Linux 裝置韌體〉)
1. **Binary fingerprint 與指令集判定**
   - `file(1)` / libmagic 判讀(若系統有 `file` 指令,Kali 預設有)
   - SHA-256 / SHA-1 / MD5 hash
   - **ARM Cortex-M**:initial SP 是否指向典型 SRAM(0x2000xxxx 等)、reset
     vector 是否設 Thumb bit、slots 2–15 是否為合理 exception vectors
   - **MCS-51 (8051)**:0x0000 與 0x03+8k 的 LJMP 中斷向量表,加上核心 opcode
     佔比(LCALL / LJMP / MOV DPTR / MOVX / RET;均勻隨機只會佔 2.3%)
   - 兩者互斥判定,Cortex-M 先測(其向量表約束較強)
2. **Strings 萃取** — 可列印 ASCII 與 UTF-16LE 字串(含檔案 offset)
3. **Embedded standard data** — 結構化偵測(解析並驗證結構,非字串比對):
   VESA E-EDID 區塊(128 bytes、magic + checksum、PnP ID、EDID 版本、monitor
   name descriptor)、DDC/CI MCCS capability string(含 `mccs_ver(x.y)` 版本)
4. **Opacity 判定** — 熵值 / blank-flash run / byte 分佈檢定,區分「可分析的明文
   映像」與「加密或壓縮映像」;判定為 opaque 時,SBOM 會如實記錄「無法列舉」而
   不是含糊地回報「沒有元件」
5. **Signature matching** — 34 個常見嵌入式元件特徵,放在 `signatures/*.json`
   (見〈擴充 signature〉):
   Zephyr、FreeRTOS、mbed TLS、wolfSSL、lwIP、newlib、picolibc、GCC toolchain、
   MCUboot、littlefs、FatFs、CMSIS、TinyCrypt、OpenThread、NimBLE、TF-M、
   STM32 HAL、Nordic nrfx、nRF Connect SDK、Nordic SoftDevice Controller、MPSL、
   Nordic nRF5 SDK(舊版)BLE DFU bootloader、MicroPython,以及 Linux 側的
   BusyBox、OpenSSL、zlib、U-Boot、Linux kernel、Dropbear、OpenSSH、SQLite、
   libcurl、musl、glibc
6. **交付物輸出** — CycloneDX 1.6 JSON(必要時再加 SPDX 2.3 JSON)+ Excel
   證據報告(見下方〈交付物〉)。
   每個 component 帶有:
   - `evidence.identity`(`binary-analysis` technique、confidence 0–0.97、
     命中的 regex + 字串 + offset)
   - `evidence.occurrences`(在 firmware 內的位置)
   - `properties` 的 `fw2sbom:confidence_level`(high / medium / low)
   - 若字串含版本號則填入 `version` 與帶版本的 `purl`
   - metadata 明確標示 `fw2sbom:sbom_type = binary-derived` 與 disclaimer

> **注意**:這是 *binary-derived* SBOM。元件與版本判定為啟發式(evidence-based),
> 可能不完整或有誤;「沒偵測到」不代表「不存在」。confidence 上限刻意設為 0.97。

## 安裝

```bash
git clone <this-project>   # 或直接複製資料夾
cd fw2sbom
chmod +x fw2sbom.py
# 無需 pip 套件;requirements.txt 僅列出選用工具
```

## 使用方法

```bash
./fw2sbom.py <firmware.bin> [options]
```

| 參數 | 說明 |
|---|---|
| `input` | 要分析的 firmware 映像檔(raw `.bin`) |
| `-o, --output FILE` | SBOM 輸出路徑(預設 `<input>.cdx.json`) |
| `--format {cyclonedx,spdx,both}` | 輸出格式,預設 `cyclonedx`。`both` 由同一次分析產生兩份文件 |
| `--firmware-version VER` | 這份映像所屬的**產品**韌體版本,寫入 SBOM 根 component |
| `--signatures DIR` | 額外載入簽章包(可重複;亦看 `FW2SBOM_SIGNATURES`) |
| `-d, --out-dir DIR` | 一次輸出兩份交付物到 DIR:`<stem>_SBOM.cdx.json` 與 `<stem>_Evidence.xlsx` |
| `--evidence FILE` | 單獨指定 Excel 證據報告的輸出路徑 |
| `--min-str-len N` | strings 最小長度,預設 6(≥3) |
| `--dump-strings FILE` | 另存所有萃取字串(`offset<TAB>string`) |
| `--no-deframe` | 不偵測/不去除封包容器框架,直接分析原始位元組 |
| `--dump-payload FILE` | 另存去框後的 payload(可餵給 binwalk / IDA / Ghidra) |
| `--pretty` | JSON 縮排輸出 |
| `--fail-if-empty` | 未識別出任何元件時以 exit code 2 結束(適合 CI) |
| `-v, --verbose` | stderr 顯示分析過程 |
| `--version` | 顯示工具版本 |

**Exit codes**: `0` 成功、`1` 輸入/IO/參數錯誤、`2` `--fail-if-empty` 且無元件命中。

## 範例:分析一份 firmware

```bash
./fw2sbom.py firmware.bin -o firmware.sbom.json --pretty -v --dump-strings firmware.strings.txt
```

範例輸出(stderr 摘要):

```
[fw2sbom] 3 component(s) identified -> firmware.sbom.json
[fw2sbom]   mbedtls                version=3.4.0        confidence=0.9  (high)
[fw2sbom]   lwip                   version=2.1.3        confidence=0.97 (high)
[fw2sbom]   littlefs               version=2.8.0        confidence=0.97 (high)
```

SBOM 中單一 component 的 evidence 範例:

```json
{
  "type": "library",
  "name": "mbedtls",
  "version": "3.4.0",
  "purl": "pkg:github/Mbed-TLS/mbedtls@3.4.0",
  "evidence": {
    "identity": [{
      "field": "name",
      "confidence": 0.9,
      "methods": [{
        "technique": "binary-analysis",
        "confidence": 0.9,
        "value": "regex '[Mm]bed ?TLS[ /]v?([0-9]+\\.[0-9]+\\.[0-9]+)' matched 'mbed TLS 3.4.0' at offset 0x1a30"
      }]
    }],
    "occurrences": [{ "location": "firmware.bin", "additionalContext": "first match at offset 0x1a30" }]
  }
}
```

## 封包化映像 (Packetized / ISP-dump firmware)

部分廠商(觸控 IC、MCU ISP 工具等)交付的「韌體檔」其實不是平坦映像,而是燒錄
協定的逐包 dump:一段檔頭之後,是固定長度的記錄不斷重複:

```
[checksum][length][page][sequence][payload chunk]  × N
```

直接對這種檔案做 strings/signature 比對毫無意義 —— payload 每隔數十位元組就被框架
位元組切斷。fw2sbom 會自動偵測並去框,之後所有分析都在還原出的 payload 上進行。

偵測是**通用的,不依賴任何廠商 magic**:掃描 8–256 bytes 的候選 record stride,
要求同時存在「跨所有記錄皆固定的欄位」與「每筆 +1 的計數欄位」——隨機資料與一般
平坦映像不會同時滿足這兩個條件(已用合成測試韌體與 200 KB 隨機資料驗證無誤判)。
接著:

- **length byte 確認** — 若某固定欄位的值剛好等於 payload 寬度,即視為長度位元組,
  這是最強的框架確認證據
- **checksum 欄位驗證** — 以 sum8 / neg-sum8 / xor8 / CRC-8(0x07, 0x31, 0x1D)
  逐一驗證候選欄位;命中即可確定該欄位屬於框架而非 payload
- 若 checksum 演算法無法比對成功(廠商自訂或連 checksum 都被加密),則以位元組分佈
  離群度判斷;仍無法區分時,採用「框架在前」的常見慣例,並在 SBOM 的
  `fw2sbom:container_framing_resolution` 標為 `ambiguous`

去框結果會寫進 SBOM metadata(`fw2sbom:container_*`),包含 stride、檔頭長度、記錄
數、版面配置字串與涵蓋率。

## 加密 / 不透明映像 (Opaque payload)

payload 去框後會做 opacity 判定:

| 指標 | 說明 |
|---|---|
| Shannon entropy | ≥ 7.5 bits/byte 視為不透明,≥ 7.9 與密文無法區分 |
| 最長同值位元組 run | 明文映像必然有大片 `0x00`/`0xff` 空白 flash;run 極短是加密的強證據 |
| chi-square vs uniform | 真隨機約 255;數千代表分佈有偏,較像廠商自訂 block/stream cipher 而非 AES-CBC/GCM |
| 重複的 16-byte 對齊區塊 | ECB 模式或重複 keystream 的跡象 |
| 壓縮容器 magic | gzip / xz / lzma / lz4 / zstd / zip / squashfs / uImage |

判定為 opaque 時,SBOM **不會**只是空的:會產生一個 `firmware` 型別的 opaque
component(帶 payload 的 SHA-256/SHA-1/MD5、entropy 等 evidence,confidence 0.0),
並在 metadata 加上 `fw2sbom:opacity_disclaimer`,明確說明「內容加密,靜態分析無法
列舉元件,需向供應商索取明文映像或原廠 SBOM」。這在 CRA 供應鏈場景很重要:
「無法分析」與「沒有元件」必須是兩件不同的事。

範例(加密的觸控控制器韌體):

```
[fw2sbom] container: 36-byte records, 120-byte file header, 10319 records, 4B framing + 32B payload
[fw2sbom] container layout: [checksum/address?][const 0x20][page index][seq +1/record][payload x32]
[fw2sbom] container length byte: column 1 = 0x20 == payload width
[fw2sbom] de-framed 330208 payload bytes (41398 bytes of framing/header removed)
[fw2sbom] payload verdict: opaque (entropy 7.992 bits/byte)
[fw2sbom] payload is OPAQUE (opaque) - static component identification is not possible:
[fw2sbom]   - Shannon entropy 7.992 bits/byte
[fw2sbom]   - longest identical-byte run 3
[fw2sbom]   - no blank-flash runs (longest run 3); an unencrypted image always contains long 0x00/0xff stretches
[fw2sbom]   - 338 repeated 16-byte aligned block(s): possible ECB-mode or repeating-keystream encryption
[fw2sbom] recorded as a single opaque component; obtain a plaintext image or the vendor's SBOM to complete it
```

## Linux 裝置韌體 (router / gateway / NVR)

MCU 映像是一整塊平坦資料,掃字串就能找到所有東西。Linux 裝置映像不是:它是
一個開機檔頭、一段壓縮過的 kernel、再一個壓縮過的根檔案系統,而**所有值得寫進
SBOM 的東西都在壓縮區段裡面**。對原始位元組做字串掃描會得到零個元件 —— 這正是
本工具在 v1.6.0 對一台真實 router 給出的結果:判定正確(「compressed」),SBOM
完全是空的。

v1.7.0 起會走訪容器:

```
[fw2sbom] segment 0x00000000 U-Boot uImage header (Linux/mips) (expanded)
[fw2sbom] segment 0x00000040 Linux kernel (lzma) (expanded)
[fw2sbom] segment 0x0023ec0d SquashFS 4.0 (xz) (read)
[fw2sbom] distribution: OpenWrt 22.03.4 r20123-38ccc47687
[fw2sbom] 359 package(s) from /usr/lib/opkg/status (opkg), 359 with exact versions
[fw2sbom] 366 component(s) identified
```

| 來源 | 取得什麼 | Confidence |
|---|---|---|
| uImage 檔頭 | OS、架構、壓縮方式;OpenWrt 會把 kernel 版本寫進 name 欄位 | — |
| 解壓後的 kernel | `Linux version`、GCC、binutils 版本 | 0.9–0.97 |
| SquashFS rootfs | 檔案清單 | — |
| `/etc/openwrt_release`、`/etc/os-release` | 發行版名稱與版本 | 0.97 |
| **套件資料庫** | **每個已安裝套件的精確版本** | 0.97 |

最後一項是 Linux 韌體 SBOM 品質的主要來源。`/usr/lib/opkg/status`(以及 dpkg、
apk 的對應檔案)不是啟發式猜測,而是套件管理器自己的安裝紀錄。一份 14 MB 的
router 映像可以得到三百多個帶精確版本的元件。

### 支援與不支援

| | 狀態 |
|---|---|
| 容器 | U-Boot legacy uImage;任意位置的壓縮區段 |
| 解壓 | gzip、xz、lzma、bzip2(全部 stdlib) |
| 未支援解壓 | lzo、lz4、zstd —— **會明確報告「未展開」並指名演算法**,不會靜默跳過 |
| 檔案系統 | SquashFS 4.0(gzip / xz / lzma 壓縮) |
| 未支援檔案系統 | JFFS2、UBIFS、CramFS |
| 套件資料庫 | opkg、dpkg、apk |

### 對不可信輸入的處理

韌體來自客戶與供應商,不能假設它是善意的。SquashFS reader 對深度、entry 數、
單檔大小與總解壓量都設了上限,並且做目錄迴圈偵測 —— 一個惡意構造的映像不可以
讓分析器當掉、耗盡記憶體或無限遞迴。**任何一處讀不下去都不會拋例外**:會記錄
一筆警告、回報讀得到的部分,並在 SBOM 的 segment 屬性裡寫明哪裡讀不到。
「這個映像有一部分讀不了」本身是一項發現,traceback 不是。

## SBOM 格式:CycloneDX 與 SPDX

```bash
./fw2sbom.py firmware.bin --format both -d sbom_output/ --pretty
```

兩份文件由**同一次分析**產生,所以不可能互相矛盾。

| | CycloneDX 1.6 | SPDX 2.3 |
|---|---|---|
| 每個元件的 confidence | `evidence.identity[].confidence`(結構化) | `annotations`(純文字) |
| 命中的 regex / 字串 / offset | `evidence.identity[].methods[]`(結構化) | package `comment`(純文字) |
| purl | `purl` 欄位 | `externalRefs`(`referenceType: purl`) |
| 加密 payload | `firmware` 型別 component,confidence 0.0 | package,`versionInfo: NOASSERTION` + annotation |
| 沒有版本的原因 | `fw2sbom:version_unavailable_reason` | annotation |

CycloneDX 有為「binary-derived SBOM」而設的 `evidence` 物件,SPDX 2.3 沒有對應
欄位。所以 SPDX 版的證據只能放進 `comment` 與 `annotations` —— 人看得到,機器大
多看不到。**兩者不一致時以 CycloneDX 為準**,這句話也寫在 SPDX 文件本身的
`comment` 裡,拿著單一檔案的人不必猜。

之所以仍然輸出 SPDX:部分客戶與稽核方指名要它。一個他們吃得下的格式,勝過一個
更好但他們吃不下的格式。

## 交付物 (Deliverables)

```bash
./fw2sbom.py firmware.bin -d sbom_output/ --pretty
```

產出兩個檔案:

| 檔案 | 對象 | 內容 |
|---|---|---|
| `<stem>_SBOM.cdx.json` | 機器 / 供應鏈工具 | CycloneDX 1.6,每個 component 帶 evidence 與 confidence |
| `<stem>_SBOM.spdx.json` | 指名要 SPDX 的下游 | SPDX 2.3(`--format spdx` 或 `both`) |
| `<stem>_Evidence.xlsx` | 人 / 稽核 | 7 張工作表的證據與信心報告 |

Excel 報告的工作表:

| 工作表 | 內容 |
|---|---|
| **Summary** | 檔案識別(MD5/SHA-1/SHA-256/SHA-512)、大小、熵值、指令集、payload verdict、容器去框資訊、各項統計、SBOM 政策與限制聲明 |
| **Candidate Components** | 偵測到的元件 **以及所有掃描過但未命中的簽章**(status / confidence % / 是否進入 SBOM / offset / 證據) |
| **Evidence Register** | 逐條原始觀察:offset、證據、解讀、信心 %。包含被判定為誤報的弱 magic 命中 |
| **EDID Profiles** | 每個 EDID 區塊:廠商 PnP ID、product code、序號、週/年、EDID 版本、extension 數、monitor name、區塊 SHA-256(僅在偵測到 EDID 時出現) |
| **Bank Analysis** | 逐 64 KiB bank 的熵值、0xFF/0x00 佔比、字串數、SHA-256 |
| **Scan Coverage** | 掃描覆蓋率:每個 container/filesystem magic 與每個軟體簽章的 validated / raw hit / 狀態 |
| **CycloneDX Summary** | SBOM 的 specVersion、serialNumber、root bom-ref、各類 component 計數 |

### 為什麼要有負面證據

「掃描過 BusyBox、OpenSSL、U-Boot、Linux kernel … 全部未命中」本身就是一項發現;
沉默不是。CRA 供應鏈場景下,稽核方需要知道**你找過什麼**,而不只是**你找到什麼**。
同理,弱 magic 命中(例如 576 KB 檔案裡 2-byte JFFS2 magic 隨機撞中 4 次)會如實
列出並標記為「已驗證為誤報」,而不是默默丟棄。

### Excel 是用 stdlib 寫的

`.xlsx` 本質是一包 XML 的 zip,所以 `evidence_report.py` 用 `zipfile` 直接產生,
**不需要 openpyxl 或任何 pip 套件**。這保住了 fw2sbom「零依賴」的特性,PyInstaller
打包出來的單一 exe 也不會因此變大或需要額外 hidden-import。

## 8-bit MCU 韌體 (MCS-51 / 8051)

顯示控制器、monitor scaler、觸控 IC 等大量使用 8051 核心。這類映像有兩個特性會讓
只認 ARM 的工具給出誤導性結果:

- **沒有 Cortex-M 向量表**,舊版會回報「未偵測到」然後就無下文
- **熵值天生偏高**:密集的 8051 code(3-byte 指令、操作元變化大)常達 6.8–7.3
  bits/byte,會被單純的熵值門檻誤判成「packed / 部分壓縮」

fw2sbom 以中斷向量表 + opcode 佔比正面識別 MCS-51;**一旦指令集被正面識別,
opacity 判定即直接定為 plaintext**,不再依賴熵值門檻。

## 內嵌標準資料 (Embedded standard data)

不是所有可識別的東西都是連結進去的軟體函式庫。顯示控制器韌體內嵌大量**標準化
資料**,這些是靠解析與驗證結構本身找出來的,不是字串比對:

| 標準 | 偵測方式 | 產出 |
|---|---|---|
| VESA E-EDID | 128-byte 區塊、`00 FF FF FF FF FF FF 00` magic、checksum 必須為 0、PnP ID 需為合法大寫字母 | 區塊數、EDID 結構版本、PnP 廠商 ID、monitor name descriptor |
| VESA MCCS / DDC-CI | `prot(monitor)type(...)` capability string,版本取自 `mccs_ver(x.y)` | MCCS 版本、capability string 內容、display type |

這些以 CycloneDX `data` 型別輸出,並帶 `fw2sbom:evidence_class =
embedded-standard-data` 屬性,與 signature 命中的軟體元件明確區分——避免有人把
「內嵌 EDID 資料表」誤讀成「連結了某個 OSS 函式庫」。

範例(Realtek RTD279x monitor scaler 韌體,576 KB):

```
[fw2sbom] architecture: MCS-51 / 8051
[fw2sbom]   mcs-51: 8 LJMP interrupt vectors: RESET@0x0000->0x1b9e, INT0@0x0003->0x1c9e, ...
[fw2sbom]   mcs-51: core 8051 opcodes (LCALL/LJMP/MOV DPTR/MOVX/RET) are 18.0% of all bytes (uniform random would be 2.3%)
[fw2sbom] payload verdict: plaintext (entropy 6.830 bits/byte)
[fw2sbom] embedded standard: VESA E-EDID x10 (v1.4, vendors ACR, DEL, RTK, VSC)
[fw2sbom] embedded standard: VESA MCCS 2.2 capability string x2
[fw2sbom] 2 component(s) identified
[fw2sbom]   vesa-e-edid            version=1.4          confidence=0.95 (high) [embedded standard data]
[fw2sbom]   vesa-mccs              version=2.2          confidence=0.95 (high) [embedded standard data]
```

## Confidence 計算

`confidence = min(0.97, 最高權重命中 pattern + 0.05 × 額外命中 pattern 數)`
- `high` ≥ 0.8(通常含明確版本字串)
- `medium` ≥ 0.5(元件名稱/API symbol 命中)
- `low` < 0.5(弱特徵,僅供參考)

## 版本判定 (v1.1.0)

版本來源分兩種,SBOM 內以 `fw2sbom:version_source` 區分:

1. **exact-version-string** — binary 內有明確版本字串(如 NCS banner、`mbed TLS 3.4.0`),confidence 同元件本身,purl 帶版本。
2. **inferred** — 推論版本,confidence 固定 0.4,purl 不帶版本,evidence 註明推論依據:
   - Zephyr fork tag → NCS release 對照表(如 `v3.5.99-ncs1` → NCS `2.6.x`)
   - 命中字串內的 version-like token(無專屬 version pattern 時的 fallback)

沒有任何版本線索的元件維持 `fw2sbom:version = unknown`,**不臆測**。

有些元件是**結構上**不可能從 stripped 映像取得版本的 —— 例如 nrfx 只留下
`nrfx_spim_init` 之類的 API symbol,STM32 HAL 的版本是數值巨集而非字串。這類簽章
帶一個 `version_note` 說明「為什麼拿不到」與「去哪裡拿」,輸出成
`fw2sbom:version_unavailable_reason`:

```json
{ "name": "fw2sbom:version_unavailable_reason",
  "value": "nrfx ships as source inside the nRF5 SDK and nRF Connect SDK and emits no version banner; a compiled image contains only API symbol names (nrfx_spim_init, ...). Obtain the version from the vendor's west manifest or nrfx_glue.h." }
```

「我們找不到版本」與「這個元件從來不帶版本」是兩件不同的事,下游做 CVE 比對的人
需要分得清。測試強制每個簽章**要麼有版本擷取 pattern,要麼有 `version_note`** ——
這條規則沒辦法用一個假 regex 來矇混過去。

### 產品自己的版本

SBOM 根 component 的版本預設是 `UNKNOWN`,因為只有廠商可靠地知道它。用
`--firmware-version` 指定:

```bash
./fw2sbom.py firmware.bin --firmware-version "2.4.1"
```

不填的話,同一產品的不同 release 在下游系統裡分辨不出來。要補齊精確版本,最可靠的做法是向
供應商索取 build 產物(`build/zephyr/.config`、west manifest)後人工合併。

## 拖拉式服務 (Drag-and-drop service)

`service.py` 提供一個本機網頁介面,把 `fw2sbom.py` 的分析流程包成 HTTP service,
同樣是 stdlib only(不需要 pip 安裝任何套件),只綁定 `127.0.0.1`。

```bash
python3 service.py            # 預設監聽 http://127.0.0.1:8765/,自動開啟瀏覽器
FW2SBOM_PORT=9000 python3 service.py   # 自訂 port
```

打開頁面後,把 firmware 檔案拖進 drop zone(或點擊選檔),頁面會顯示架構、payload
verdict、封包容器資訊與辨識出的 component 清單(name / version / confidence /
level),並提供**兩個下載連結**:CycloneDX JSON 與 Excel 證據報告,與 CLI 的
`-d/--out-dir` 產出的內容完全相同(兩者共用同一個分析流程)。分析在記憶體中進行,
檔案內容不會寫入磁碟、也不會送到本機以外的地方。

服務若偵測到指定的 port 已被其他程式佔用,會直接報錯結束(exit code 1)而不是
靜默地啟動一個不會有人連到的實例——對雙擊執行的 exe 來說,這種沉默是最糟的失敗
方式。用 `FW2SBOM_PORT=<port>` 換 port。

### 打包成單一執行檔(給客戶用)

不想讓客戶自己裝 Python,可以用 [PyInstaller](https://pyinstaller.org/) 把
`service.py`(連同 `fw2sbom.py`)打包成一個獨立 `.exe`,客戶下載後雙擊就能跑,
不需要安裝 Python 或任何套件:

```bash
pip install pyinstaller
pyinstaller fw2sbom-service.spec
# 產出: dist/fw2sbom-service.exe
```

倉庫裡的 `fw2sbom-service.spec` **不是** PyInstaller 預設產生的那份,請用它而不要
自己下 `pyinstaller --onefile service.py` —— 它的 `datas` 帶了三樣必須一起進 exe
的東西:

| 檔案 | 少了會怎樣 |
|---|---|
| `signatures/` | exe 正常啟動,然後對每一份韌體都回報「找不到元件」 |
| `onecra_logo.png` | 頁首品牌圖不見 |
| `onecra_icon.png` | 瀏覽器分頁 favicon 不見 |

兩個 PNG 是執行時讀取後轉 base64 內嵌進 HTML 的;signature 包則由
`fw2sbom._resource_dir()` 從 `sys._MEIPASS` 讀回來。兩者都已處理好「一般執行」與
「PyInstaller 凍結後」兩種路徑。

簽章包缺席是最糟的失敗模式,因為它看起來像分析成功。要驗證打包結果:

```bash
dist/fw2sbom-service.exe --version    # 啟動時會印出載入了幾個簽章
```

- `--console` 保留終端機視窗,客戶可以看到「listening on http://127.0.0.1:8765/」
  這類訊息,關閉視窗(或 Ctrl+C)就會停止服務 —— 對資安工具而言,這種可見性
  比完全隱藏背景執行更值得信任。
- 執行檔啟動後會自動開啟瀏覽器到 `http://127.0.0.1:8765/`,行為與 `python
  service.py` 完全相同,一樣只綁定 `127.0.0.1`、分析全在本機記憶體完成。
- 只需把 `dist/fw2sbom-service.exe` 這一個檔案交給客戶即可;`build/` 目錄和
  `.spec` 檔是建置產物,不用一起發布。
- PyInstaller 打包出的執行檔是平台相依的(在 Windows 上打包只能給 Windows
  用戶);若客戶用 macOS/Linux,需要在對應平台上重新執行上述指令。

### 免簽章的 Portable 版(不用打包 exe)

PyInstaller 的 `.exe` 沒有數位簽章,客戶電腦的 Windows SmartScreen / 防毒軟體
可能直接攔下或跳警告,要真的解決得買 EV 程式碼簽章憑證。如果想避開這件事,
可以改發布「隨附 Python 直譯器的資料夾」,一樣不需要客戶自己裝 Python。

**這件事已經腳本化了**,不用手動做:

```powershell
.\scripts\build-portable.ps1
```

腳本會下載官方 embeddable CPython、比對 `scripts/python-embed.sha256` 裡釘住的
SHA-256(對不上就刪掉下載檔並中止)、把 fw2sbom 的檔案放到 `python.exe` 旁邊、
用打包好的直譯器自己跑一次 smoke test,最後輸出 `dist-portable/fw2sbom-portable.zip`
並印出要抄進 [RELEASE.md](RELEASE.md) 的 hash。

zip 是用 `scripts/make_deterministic_zip.py` 寫的(entry 排序、timestamp、壓縮
等級全部固定),所以**同一個 commit 重新打包會得到完全相同的 SHA-256** —— 客戶
手上那個檔案可以被獨立驗證,而不是只能相信我們的紀錄。

第一次在新機器上打包、或換 CPython 版本時,pin 檔裡可能還沒有對應的 hash,腳本
會警告並印出下載到的 SHA-256;去 python.org 的 release 頁對過之後,再用
`-PinHash` 記錄下來。

腳本實際做的事(手動重現時的步驟):

```bash
# 1) 下載官方 embeddable 版 Python(以 3.12.7 為例),解壓縮成一個資料夾,
#    跟 python.exe 放在同一層的 python312._pth 預設就含 "." (當前目錄),
#    不用另外修改
# 2) 把 service.py / fw2sbom.py / evidence_report.py /
#    onecra_logo.png / onecra_icon.png 複製到同一個資料夾(跟 python.exe 平行,
#    不要放進子資料夾 —— 這樣 ._pth 的 "." 才找得到它們)
# 3) 把 scripts/Start-fw2sbom.bat 一起複製進去
# 4) 整個資料夾壓成 zip
```

- `.bat` 裡呼叫直譯器**一定要用 `"%~dp0python.exe"` 這種絕對路徑**,不能寫裸的
  `python.exe`——如果客戶電腦上另外裝過 Python 並加進 PATH,裸檔名會被系統 PATH
  上的那個 Python 搶先解析到,兩邊的 `pythonXY.dll` 版本對不上,`import socket`
  就會噴 `Module use of pythonXXX.dll conflicts with this version of Python`。
  用完整路徑可以完全避開這個問題。
- 整個資料夾(python.exe + 一堆 .pyd/.dll + 我們的 4 個 .py/.png + `.bat`)大約
  20 MB,壓縮成 zip 給客戶,解壓縮後雙擊 `.bat` 就是「one click」——不會有
  SmartScreen「未知發行者」警告,因為裡面沒有我們自己編譯/連結出的 exe。
- 行為與 `python service.py` 和 PyInstaller 版完全一致:只綁定
  `127.0.0.1`、自動開瀏覽器、`--console` 式保留視窗可見分析過程、
  port 被佔用時會明確報錯而不是靜默失敗。
- 這個 embeddable Python 是官方從 python.org 發佈、可自由重新散布的版本,不含
  pip / tkinter,但 fw2sbom 全部依賴都是 stdlib,不受影響。

## 擴充 signature

簽章庫放在 `signatures/*.json`,依生態系分包(`mcu-rtos`、`mcu-lib`、
`vendor-nordic`、`vendor-st`、`linux`),與分析程式碼分離 —— 更新簽章不用動
`fw2sbom.py`,客戶也可以自己加。每個包長這樣:

```json
{
  "pack": "linux",
  "description": "Userland and kernel components of Linux-based firmware",
  "signatures": [
    {
      "name": "busybox",
      "supplier": "BusyBox",
      "type": "application",
      "purl": "pkg:generic/busybox",
      "description": "BusyBox multi-call userspace utilities",
      "patterns": [
        { "regex": "BusyBox v([0-9]+\\.[0-9]+\\.[0-9]+)", "weight": 0.95, "vgroup": 1 },
        { "regex": "BusyBox is a multi-call binary", "weight": 0.8 }
      ]
    }
  ]
}
```

- `weight` 介於 0 到 1;`vgroup` 是版本號的 capture group 編號(選填,但**沒有
  版本號的元件無法對應 CVE**,新增簽章時盡量補一個帶 `vgroup` 的 pattern)
- `purl` 存不帶版本的基底,版本在命中時才接上去
- 載入時會驗證:regex 能不能編譯、`weight` 範圍、`vgroup` 是否超出 group 數、
  `type` 是不是合法的 CycloneDX 型別。有問題會直接報錯,不會默默略過

加自己的包而不動到內建的:

```bash
./fw2sbom.py firmware.bin --signatures /path/to/my-packs/
FW2SBOM_SIGNATURES=/path/to/my-packs ./fw2sbom.py firmware.bin
```

同名簽章由後載入的包覆蓋(這就是客製化內建簽章的方法);同一個目錄裡重複定義
同一個名字則是錯誤。**完全找不到任何簽章包時工具會直接報錯結束**,而不是產生
一份空的 SBOM —— 「資料庫沒送到」不可以長得像「這份韌體沒有元件」。

## 測試

```bash
python -m unittest discover -s tests -v
```

測試用的韌體映像是跑的時候即時合成的(`tests/make_fixtures.py`,固定 seed,
每次產出 byte-identical),不進倉庫。

另外有一組 **corpus 測試**,跑在真實的廠商韌體上(GL.iNet GL-MT300N-V2,
OpenWrt 22.03.4,MIPS)。合成 fixture 只能證明解析器符合規格書;真實映像才能
證明它扛得住廠商實際出貨的東西 —— 而那正是韌體解析通常出事的地方。映像不進
倉庫,用以下指令取得,沒有它時這組測試會 skip:

```bash
python scripts/fetch-corpus.py
```
涵蓋:架構判定、去框(含框架在後的已知
限制)、opacity 判定、簽章比對與版本擷取、EDID/MCCS 結構解析、SBOM 結構與
bom-ref 一致性、Excel 報告、service 的記憶體存放區。

另外有一組**針對已知缺口**的測試(`KnownGapTest`):它們斷言的是「今天做不到」
的行為,例如壓縮過的 Linux router 映像目前找不到任何元件。這些測試**應該在對應
的 roadmap 項目完成時失敗** —— 那次失敗就是功能完成的訊號,不是 regression。

要把輸出對官方 CycloneDX 1.6 schema 驗證(CI 會做):

```bash
pip install jsonschema
python tests/fetch_schema.py
python -m unittest discover -s tests
```

schema 沒抓下來或沒裝 `jsonschema` 時,該項測試會 skip 而不是假裝通過。

## 限制

- 萃取 ASCII 與 UTF-16LE 字串;不做反組譯、不做 code-similarity(FLIRT/BinDiff
  類)比對
- 容器走訪目前只認 U-Boot legacy uImage;FIT、TRX 與各家廠商自訂檔頭尚未支援
- 檔案系統只支援 SquashFS 4.0;JFFS2 / UBIFS / CramFS 會被偵測到但讀不出內容
- 不做逐個 ELF 的分析(`.comment`、`NEEDED` 依賴);目前 rootfs 的元件全部來自
  套件資料庫,沒有資料庫的映像只會得到檔案清單
- 指令集判定僅涵蓋 ARM Cortex-M 與 MCS-51;其他架構(RISC-V、Xtensa、8051 以外
  的 8-bit 核心)會回報「未識別」,分析仍會繼續但少了架構這條證據
- 8051 韌體通常由 Keil C51 等專有工具鏈編譯、內容多為廠商自有程式碼,不一定含
  可識別的第三方元件;此時「僅偵測到內嵌標準資料」是正確結果,不是分析失敗
- 版本字串可被移除或竄改;加密/壓縮映像需先解開(工具會判定並標記為 opaque,
  但不會嘗試破解廠商加密)
- 框架在**後**的封包格式(`[payload][checksum][length][page][seq]`)去框後會少掉
  第一個 payload chunk:第一組框架之前的那段資料無法與檔頭區分
- 對 ELF/HEX 輸入會警告(請先 `arm-none-eabi-objcopy -O binary app.elf app.bin`)

## 專案結構

```
fw2sbom/
├── fw2sbom.py              # 主程式(CLI)
├── evidence_report.py      # Excel 證據報告產生器(stdlib-only xlsx writer)
├── spdx_report.py          # SPDX 2.3 JSON 輸出(由 CycloneDX 文件轉換)
├── container.py            # 容器走訪、解壓、套件資料庫解析
├── squashfs.py             # 唯讀 SquashFS 4.0 reader(stdlib only)
├── service.py              # 拖拉式本機網頁服務(localhost drag-and-drop UI)
├── onecra_logo.png         # 頁首品牌 logo(service.py 內嵌用)
├── onecra_icon.png         # 瀏覽器分頁 favicon(service.py 內嵌用)
├── signatures/             # 簽章庫(依生態系分包的 JSON)
│   ├── mcu-rtos.json
│   ├── mcu-lib.json
│   ├── vendor-nordic.json
│   ├── vendor-st.json
│   └── linux.json
├── tests/
│   ├── make_fixtures.py          # 合成測試韌體產生器(固定 seed,可重現)
│   ├── test_fw2sbom.py           # regression 測試(stdlib unittest)
│   └── fetch_schema.py           # 抓官方 CycloneDX schema 供驗證用
├── scripts/
│   ├── build-portable.ps1        # 打包免簽章 portable 版(驗 hash + smoke test)
│   ├── make_deterministic_zip.py # 可重現的 zip writer(固定排序/timestamp)
│   ├── Start-fw2sbom.bat         # portable 版的啟動器(會被複製進包裡)
│   ├── fetch-corpus.py           # 下載 corpus 測試用的真實廠商韌體
│   └── python-embed.sha256       # 釘住的官方 CPython embeddable hash
├── .github/workflows/ci.yml      # Linux + Windows 測試、schema 驗證、可重現打包
├── fw2sbom-service.spec    # PyInstaller 設定(datas 帶 signatures/ 與 PNG)
├── pyproject.toml
├── RELEASE.md              # 每個交付 build 的 hash / commit / CPython 版本紀錄
├── README.md
└── requirements.txt
```
