# 第三方元件

fw2sbom 的職責就是把「這個韌體裡面有什麼」講清楚。如果連自己帶了什麼都說不明白,
那就沒有立場要求別人做得更好。這份檔案列出我們散布的東西裡面,哪些不是我們寫的。

## 執行時期依賴

**沒有。** fw2sbom 的原始碼只用 Python 標準函式庫,不需要任何 pip 套件。

## 隨 portable 套件散布的元件

| 元件 | 版本 | 授權 | 套件裡的位置 |
|---|---|---|---|
| CPython(embeddable 版) | 3.12.7 | PSF License Agreement Version 2 | `LICENSE.txt` |

CPython 由 Python Software Foundation 發佈,是 python.org 官方提供、可自由重新
散布的 Windows embeddable 版本,我們**未做任何修改**。PSF 授權要求散布時保留授權
聲明,因此 `LICENSE.txt` 原樣留在套件內。

套件裡有兩份授權檔,不要混淆:

| 檔案 | 涵蓋範圍 |
|---|---|
| `LICENSE.txt` | CPython(PSF 授權) |
| `LICENSE-fw2sbom.txt` | fw2sbom 本身(專有,見 [LICENSE](LICENSE)) |

打包流程與可重現性說明在 [RELEASE.md](RELEASE.md)。

## 開發與測試才會用到的東西

以下**不隨產品散布**,只在開發與測試時取得:

| 元件 | 用途 | 取得方式 |
|---|---|---|
| CycloneDX JSON schemas | 驗證我們輸出的 SBOM | `python tests/fetch_schema.py`(不進版控) |
| SPDX 2.3 JSON schema | 同上 | 同上 |
| `jsonschema` | 跑上述驗證 | `pip install jsonschema`,僅測試用 |
| PyInstaller | 打包單檔 exe(非必要交付方式) | `pip install pyinstaller` |
| GL.iNet GL-MT300N-V2 韌體 | corpus 測試的真實映像 | `python scripts/fetch-corpus.py`(不進版控) |

## 簽章庫

`signatures/*.json` 裡面是我們自己寫的比對樣式。它們**引用**了許多開源專案的名稱
與版本字串格式(BusyBox、OpenSSL、Zephyr 等),但不包含那些專案的任何程式碼。

## 產出物

fw2sbom 產生的 SBOM 與證據報告屬於使用者。Onecra 不主張任何權利。
