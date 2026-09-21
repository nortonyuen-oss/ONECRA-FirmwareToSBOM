# 官網 (docs/)

fw2sbom 的下載頁,由 **GitHub Pages** 從 `master` 分支的 `/docs` 目錄發佈:

<https://nortonyuen-oss.github.io/ONECRA-FirmwareToSBOM/>

純靜態 —— 兩個 HTML 檔加兩張圖,沒有建置步驟。唯一的外部請求是 Google Fonts,
以及顯示下載次數時對 GitHub API 的一次查詢。

```
docs/
├── index.html            # 下載頁,CSS 與那一小段 JS 都內嵌
├── changelog.html        # 版本說明,一版一則
├── onecra_logo.png       # 頁首
├── onecra_icon.png       # favicon
└── .nojekyll             # 關掉 Jekyll:這裡沒有東西需要它處理
```

zip **不在** `docs/` 裡:下載按鈕直接指向 GitHub release 的 asset(見下文)。

## 為什麼 zip 不在版控裡

倉庫的規矩是「build 產物不進 git」。v1.19.0 以前下載頁是例外:GitHub Pages 只能
提供倉庫裡實際存在的檔案,所以 zip 必須 commit,每出一版倉庫就永久增加約 11 MB。

自 **v1.20.0** 起,zip 改放 **GitHub Releases**(不進 git 歷史),下載按鈕直接指向
release asset:

```
https://github.com/nortonyuen-oss/ONECRA-FirmwareToSBOM/releases/download/v<版本>/fw2sbom-portable-<版本>.zip
```

`docs/downloads/` 已加入 [.gitignore](../.gitignore)。**以前 commit 過的那幾份仍
留在 git 歷史裡** —— 要真的移除得改寫歷史,不值得為了體積做;這一步只是讓它停止
繼續長。

代價:**每次發版都一定要發佈 release**,否則按鈕沒有東西可下載。而且 release
asset 在私有倉庫需要登入才能下載 —— 這個倉庫本來就因為 Pages 而保持 public。

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

`index.html` 底部那段 JS 只在 release 裡**確實有一個檔名正好等於頁面公佈的那個**
asset 時才顯示累計下載次數。API 失敗、被限流或離線時,計數器只是不出現 —— 不會
顯示 `0`。整段 JS 是漸進增強:關掉 JavaScript 的瀏覽器照樣能下載,只是沒有數字。

## 發佈 release:`scripts/publish-release.ps1`

```powershell
$env:GITHUB_TOKEN = "ghp_..."     # classic token,public_repo 權限;用完可以撤銷
.\scripts\publish-release.ps1
```

請在**自己的 PowerShell 視窗**執行。腳本會從 `fw2sbom.py` 讀版本、把
`dist-portable/fw2sbom-portable.zip` 以 `fw2sbom-portable-<版本>.zip` 上傳、
release notes 直接取自 [RELEASE.md](../RELEASE.md) 對應那一節,最後**把檔案下載
回來重算雜湊確認一致**才算成功。

兩道保險:

- RELEASE.md 那一節若**沒有提到**你正要上傳的那個雜湊,腳本會拒絕發佈 ——
  避免 release notes 與實際檔案講的是兩回事。
- Token 只從 `$env:GITHUB_TOKEN` 讀,**不會被印出、記錄或寫檔**。

加 `-Draft` 可以先建草稿看過再按 Publish。

## 版本說明 (changelog.html)

一版一則,最新的在最上面。內容抄自 [RELEASE.md](../RELEASE.md),但寫給客戶看:
說這一版對他們的韌體有什麼實際差別,而不是列出改了哪些檔案。修正的項目用紅色
左邊界標出來 —— 客戶最需要知道的是「我之前那份報告會不會是錯的」。

發新版時在 `<div class="releases">` 最上面插一則,並把前一則的
`<span class="tag current">目前版本</span>` 移到新的那一則。

## 每次發版的步驟

版本與雜湊是寫死在頁面上的,因為它們是那一版的事實,不該從別處動態拉。
**次序很重要**:Pages 發佈的是 `master`,所以 master 必須在 release asset
存在**之後**才 push,否則會有一段時間下載按鈕 404。

1. Commit 程式碼,build(`scripts/build-portable.ps1`),確認 fresh clone
   重新打包雜湊一致。

2. 在 [RELEASE.md](../RELEASE.md) 新增一節,再改 `index.html` 這幾處:

   | 位置 | 內容 |
   |---|---|
   | `<header>` 的 `.ver` | 版本號與日期 |
   | `.dl-btn` 的 `href` 與 `.sub` | **release asset 的 URL**(tag 與檔名都帶版本)、檔名與大小 |
   | `.dl` 的 `<dl>` | 版本、CPython 版本、檔案數 |
   | `.hash` 與 `<footer>` | **SHA-256(兩處:完整與縮寫)** |
   | `<script>` 的 `ASSET` 常數 | 檔名,**必須與按鈕一致** |
   | `changelog.html` | 新增一則,並移動「目前版本」標籤 |
   | `<pre>` 的指令範例 | 檔名 |

   數字全部抄自 RELEASE.md 對應版本那一節 —— 那是唯一的真實來源。

3. Commit、打 tag,**只 push tag**:

   ```bash
   git tag -a v1.21.0 -m "fw2sbom v1.21.0 - ..."
   git push origin v1.21.0
   ```

4. 執行 `scripts/publish-release.ps1`(見上一節),等它確認雜湊一致。

5. **最後才 push master**:

   ```bash
   git push origin master
   ```

   Pages 自動重新發佈,按鈕指向剛發佈的 asset。

## 為什麼雜湊那麼顯眼

這個套件沒有數位簽章 —— 這是刻意的:裡面不含任何我們自己編譯或連結出來的執行檔,
只有 python.org 官方的直譯器加我們的 Python 原始碼,所以 Windows SmartScreen
不會跳「未知發行者」。代價是使用者沒有簽章可以驗,只剩雜湊。

對一個產 SBOM 的供應鏈工具來說,把自己的雜湊藏在頁尾小字裡是說不過去的,所以它
和下載按鈕並排。旁邊那句「可重現」也不是修辭:同一個 commit 重新打包會得到位元組
完全相同的 zip,任何人都能自己算出這個雜湊,不必相信我們的紀錄。
