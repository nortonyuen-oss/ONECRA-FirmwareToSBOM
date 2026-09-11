# 官網 (site/)

fw2sbom 的下載頁。純靜態 —— 一個 HTML 檔加兩張圖,沒有建置步驟、沒有 JavaScript、
沒有外部請求(除了 Google Fonts)。任何一台 web server 都能直接放。

```
site/
├── index.html            # 整頁,CSS 內嵌
├── onecra_logo.png       # 頁首
├── onecra_icon.png       # favicon
└── downloads/            # 放 zip 的地方(不進 git)
    └── fw2sbom-portable-1.7.0.zip
```

## 部署

1. 把 portable zip 複製進 `downloads/`,**檔名要帶版本號**:

   ```bash
   cp dist-portable/fw2sbom-portable.zip site/downloads/fw2sbom-portable-1.7.0.zip
   ```

   下載連結刻意用相對路徑,所以整個 `site/` 目錄原樣上傳就能運作,不需要改任何
   設定。要改放到別的網域或 CDN,就把 `index.html` 裡那個 `href` 換成絕對網址。

2. 把整個 `site/` 目錄上傳到 web server 的根目錄(或任何子路徑,相對連結都成立)。

3. 確認 server 用 `application/zip` 提供 `.zip`,並且**不要**對它做 gzip 轉碼 ——
   否則使用者下載到的檔案雜湊會對不上頁面公佈的那個。

## 每次發版要改的四個地方

頁面上的版本與雜湊是寫死的,因為它們是這一版的事實,不應該從別處動態拉。
發新版時改 `index.html` 這幾處:

| 位置 | 內容 |
|---|---|
| `<header>` 的 `.ver` | 版本號與日期 |
| `.dl-btn` 的 `href` 與 `.sub` | 檔名與大小 |
| `.dl` 的 `<dl>` | 版本、CPython 版本、檔案數 |
| `.hash` 與 `<pre>` 與 footer | **SHA-256**(三處都要改) |

數字全部抄自 [RELEASE.md](../RELEASE.md) 對應版本那一節,那是唯一的真實來源。

## 為什麼雜湊那麼顯眼

這個套件沒有數位簽章 —— 這是刻意的:裡面不含任何我們自己編譯或連結出來的執行檔,
只有 python.org 官方的直譯器加我們的 Python 原始碼,所以 Windows SmartScreen
不會跳「未知發行者」。代價是使用者沒有簽章可以驗,只剩雜湊。

對一個產 SBOM 的供應鏈工具來說,把自己的雜湊藏在頁尾小字裡是說不過去的,所以它
和下載按鈕並排。旁邊那句「可重現」也不是修辭:同一個 commit 重新打包會得到位元組
完全相同的 zip,任何人都能自己算出這個雜湊,不必相信我們的紀錄。
