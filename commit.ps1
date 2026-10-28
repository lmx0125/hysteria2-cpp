# ============================================================================
#  hysteria2-cpp 一键提交脚本（PowerShell 5.1+）
#
#  用法：
#    commit.bat                    双击运行：默认信息提交并推送
#    commit.bat "feat: xxx"        自定义提交信息
#    .\commit.ps1 -NoPush          只提交、不推送
#
#  行为：
#    git add -A（.gitignore 生效，build/ 等构建产物不会进来）
#    -> 有改动则 commit -> 有本地领先提交则 push origin <当前分支>
# ============================================================================
param(
    [Parameter(Position = 0)][string]$Message = "",
    [switch]$NoPush
)

Set-Location -LiteralPath $PSScriptRoot

function Fail([string]$text) {
    Write-Host "[commit] 失败: $text" -ForegroundColor Red
    exit 1
}

if (-not (Test-Path -LiteralPath ".git")) {
    Fail "当前目录不是 git 仓库: $PSScriptRoot"
}

$branch = (git symbolic-ref -q --short HEAD) -join ''
if (-not $branch) {
    Fail "当前处于 detached HEAD，请先切换到分支"
}

# 1) 暂存全部改动（排除项由 .gitignore / .git/info/exclude 决定）
git add -A
if ($LASTEXITCODE -ne 0) { Fail "git add -A 出错" }

$staged = @(git diff --cached --name-only | Where-Object { $_ -ne '' })
if ($staged.Count -gt 0) {
    if (-not $Message) {
        $Message = "chore: sync $(Get-Date -Format 'yyyy-MM-dd HH:mm')"
    }
    git commit -m $Message
    if ($LASTEXITCODE -ne 0) { Fail "git commit 出错" }
    Write-Host "[commit] 已提交 $($staged.Count) 个文件: $Message" -ForegroundColor Green
} else {
    Write-Host "[commit] 工作区没有改动" -ForegroundColor DarkGray
}

if ($NoPush) {
    Write-Host "[commit] -NoPush: 跳过推送" -ForegroundColor Yellow
    exit 0
}

# 2) 有本地领先提交就推送
$upstream = (git for-each-ref --format="%(upstream:short)" "refs/heads/$branch") -join ''
if ($upstream) {
    $ahead = [int](git rev-list --count "$upstream..$branch")
    if ($ahead -le 0) {
        Write-Host "[commit] 远端已是最新，无需推送" -ForegroundColor DarkGray
        exit 0
    }
}

Write-Host "[commit] 推送 origin/$branch ..." -ForegroundColor Cyan
git push origin $branch
if ($LASTEXITCODE -ne 0) {
    Fail "git push 出错（若弹出 Git Credential Manager 窗口，完成 GitHub 登录后重跑本脚本即可）"
}
Write-Host "[commit] 全部完成" -ForegroundColor Green
