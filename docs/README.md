# 官網 (docs/)

fw2sbom 的下載頁,由 **GitHub Pages** 從 `master` 分支的 `/docs` 目錄發佈:

<https://nortonyuen-oss.github.io/ONECRA-FirmwareToSBOM/>

純靜態 —— 一個 HTML 檔加兩張圖,沒有建置步驟、沒有 JavaScript、沒有外部請求
(除了 Google Fonts)。

```
docs/
├── index.html            # 下載頁,CSS 與那一小段 JS 都內嵌
├── changelog.html        # 版本說明,一版一則
├── onecra_logo.png       # 頁首
├── onecra_icon.png       # favicon
├── .nojekyll             # 關掉 Jekyll:這裡沒有東西需要它處理
└── downloads/
    └── fw2sbom-portable-1.18.0.zip      # 只保留最新一版
```

## 為什麼 zip 在版控裡

倉庫其他地方的規矩是「build 產物不進 git」(見 [.gitignore](../.gitignore))。
這裡是唯一的例外,而且是被迫的:**GitHub Pages 只能提供倉庫裡實際存在的檔案**。
要讓下載連結在 Pages 上運作,zip 就必須 commit。

代價是每出一版,倉庫永久增加約 11 MB。如果哪天太肥,替代方案是把 zip 改放
GitHub Releases(不進 git 歷史)然後把頁面上的 `href` 指過去 —— 但那樣就不能
再用相對路徑,而且 release asset 在私有倉庫需要登入才能下載。

## 開啟 Pages(只需做一次)

GitHub 倉庫 → **Settings** → **Pages** → Source 選 **Deploy from a branch** →
分支 `master`、資料夾 `/docs` → **Save**。約一分鐘後網址就會生效。

> **注意:**免費個人帳戶的 GitHub Pages **只支援公開倉庫**。這個倉庫因此要保持
> public。如果之後要轉 private,Pages 會停止服務,屆時需要另開一個公開倉庫只放
> 下載頁,或改用自己的 web server。

## 下載計數器

GitHub Pages 提供靜態檔案,不留存取紀錄,所以**頁面本身無法計算下載次數**。
唯一真實的數字是 GitHub 對 **release asset** 維護的 `download_count`,由它的
伺服器統計。

`index.html` 底部那段 JS 因此把兩件事綁在一起做,或者兩件都不做:

- 如果最新的 release 有一個檔名**正好等於頁面公佈的那個** asset,下載按鈕會改
  指向它,並顯示累計下載次數。
- 否則按鈕維持指向 `downloads/` 裡的副本,而且**不顯示任何數字**。

這個綁定是刻意的:顯示一個不屬於按鈕所服務檔案的計數,比不顯示更糟。同理,
API 失敗、被限流、離線或倉庫轉私有時,計數器只是不出現 —— 不會顯示 `0`。
整段 JS 是漸進增強:關掉 JavaScript 的瀏覽器看到的頁面與現在完全一樣。

### 要讓計數器真的動起來

用 [`scripts/publish-release.ps1`](../scripts/publish-release.ps1):

```powershell
$env:GITHUB_TOKEN = "ghp_..."     # 需要 repo 權限;用完可以撤銷
.\scripts\publish-release.ps1
```

腳本會從 `fw2sbom.py` 讀版本、把 `dist-portable/fw2sbom-portable.zip` 以
`fw2sbom-portable-<版本>.zip` 上傳、release notes 直接取自 [RELEASE.md](../RELEASE.md)
對應那一節,最後**把檔案下載回來重算雜湊確認一致**才算成功。

兩道保險:

- RELEASE.md 那一節若**沒有提到**你正要上傳的那個雜湊,腳本會拒絕發佈 ——
  避免 release notes 與實際檔案講的是兩回事。
- Token 只從 `$env:GITHUB_TOKEN` 讀,用於兩次 API 呼叫,**不會被印出、記錄或寫檔**。

要手動做也可以:倉庫頁 → Releases → Draft a new release → tag 選 `v1.8.0` →
拖 zip 進附件區並**改名成 `fw2sbom-portable-1.8.0.zip`**(檔名必須與頁面上的
一致,否則按鈕不會改指向)→ Publish。

發佈後重新整理下載頁,按鈕自動改指向 release asset,計數器出現。

### 發佈之後:停止把 zip 放進 git

這一步**必須排在第一個 release 發佈之後**。現在就刪掉 `docs/downloads/` 裡的
zip,線上那個下載按鈕會立刻 404 —— 它目前服務的就是那份檔案。

確認 release 存在、按鈕已經改指向之後:

```bash
git rm -r --cached docs/downloads
rm -rf docs/downloads
echo "docs/downloads/" >> .gitignore
```

然後把 `index.html` 按鈕的 `href` 直接寫成 release 的 URL
(`https://github.com/<owner>/<repo>/releases/latest/download/fw2sbom-portable-<版本>.zip`),
JS 那段就只剩下顯示計數的工作。

這會省掉每版約 11 MB 永久留在 git 歷史裡的成本(見上一節)。**已經 commit 過的
那幾份不會因此消失** —— 它們留在歷史裡,要真的移除得改寫歷史,不值得為了體積做。
這一步只是讓它停止繼續長。

## 版本說明 (changelog.html)

一版一則,最新的在最上面。內容抄自 [RELEASE.md](../RELEASE.md),但寫給客戶看:
說這一版對他們的韌體有什麼實際差別,而不是列出改了哪些檔案。修正的項目用紅色
左邊界標出來 —— 客戶最需要知道的是「我之前那份報告會不會是錯的」。

發新版時在 `<div class="releases">` 最上面插一則,並把前一則的
`<span class="tag current">目前版本</span>` 移到新的那一則。

## 每次發版要改的地方

版本與雜湊是寫死在頁面上的,因為它們是那一版的事實,不該從別處動態拉。
發新版時:

1. 把新的 zip 複製進來,**檔名帶版本號**:

   ```bash
   cp dist-portable/fw2sbom-portable.zip docs/downloads/fw2sbom-portable-1.9.0.zip
   git rm docs/downloads/fw2sbom-portable-1.8.0.zip
   ```

2. 改 `index.html` 這四處:

   | 位置 | 內容 |
   |---|---|
   | `<header>` 的 `.ver` | 版本號與日期 |
   | `.dl-btn` 的 `href` 與 `.sub` | 檔名與大小 |
   | `.dl` 的 `<dl>` | 版本、CPython 版本、檔案數 |
   | `.hash` 與 `<footer>` | **SHA-256(兩處:完整與縮寫)** |
   | `<script>` 的 `ASSET` 常數 | 檔名,**必須與按鈕一致** |
   | `changelog.html` | 新增一則,並移動「目前版本」標籤 |
   | `<pre>` 的指令範例 | 檔名 |

   數字全部抄自 [RELEASE.md](../RELEASE.md) 對應版本那一節 —— 那是唯一的真實來源。

3. Commit 並 push。Pages 會自動重新發佈。

## 為什麼雜湊那麼顯眼

這個套件沒有數位簽章 —— 這是刻意的:裡面不含任何我們自己編譯或連結出來的執行檔,
只有 python.org 官方的直譯器加我們的 Python 原始碼,所以 Windows SmartScreen
不會跳「未知發行者」。代價是使用者沒有簽章可以驗,只剩雜湊。

對一個產 SBOM 的供應鏈工具來說,把自己的雜湊藏在頁尾小字裡是說不過去的,所以它
和下載按鈕並排。旁邊那句「可重現」也不是修辭:同一個 commit 重新打包會得到位元組
完全相同的 zip,任何人都能自己算出這個雜湊,不必相信我們的紀錄。
