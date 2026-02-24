# Bastion Codex weekly runner + publisher
$ErrorActionPreference = "Stop"

# --- Paths ---
$BastionRoot = "C:\dev\bastion\bastion-codex"
$VaultPath   = "C:\dev\bastion\Bastion-Threat-Brain"
$AstroRoot   = "C:\Users\Kevin's Laptop\OneDrive\Documents\GitHub\personal-portfolio"
$AstroBlogSubdir = "src\content\blog"

# --- Logging ---
$LogDir = Join-Path $BastionRoot "logs"
New-Item -ItemType Directory -Force -Path $LogDir | Out-Null
$LogFile = Join-Path $LogDir ("weekly-run-" + (Get-Date -Format "yyyy-MM-dd") + ".log")

Start-Transcript -Path $LogFile -Append

try {
    Write-Host "[INFO] Starting Bastion Codex weekly run..."

    # --- Set env vars for this run ---
    $env:BASTION_OBSIDIAN_VAULT    = $VaultPath
    $env:BASTION_ASTRO_SITE_ROOT   = $AstroRoot
    $env:BASTION_ASTRO_BLOG_SUBDIR = $AstroBlogSubdir

    # --- Run Bastion Codex pipeline in venv ---
    Set-Location $BastionRoot
    & "$BastionRoot\.venv\Scripts\python.exe" "$BastionRoot\orchestrator\ti_run.py" --weekly

    # --- Health checks (fail closed) ---
    $Derived7d = Join-Path $BastionRoot "data\derived\trends_7d.json"
    if (!(Test-Path $Derived7d)) { throw "Missing trends_7d.json. Aborting publish." }

    $trend = Get-Content $Derived7d -Raw | ConvertFrom-Json
    if ($trend.total_items -le 0) { throw "trends_7d total_items is 0. Aborting publish." }

    # Ensure the Astro blog folder has a freshly updated file (last 30 minutes; OneDrive can lag)
    $blogDir = Join-Path $AstroRoot $AstroBlogSubdir
    $recent = Get-ChildItem $blogDir -Filter "bastion-codex-weekly-*.md" |
        Sort-Object LastWriteTime -Descending |
        Select-Object -First 1

    if ($null -eq $recent) { throw "No weekly blog post found. Aborting publish." }

    $mins = (New-TimeSpan -Start $recent.LastWriteTime -End (Get-Date)).TotalMinutes
    if ($mins -gt 30) { throw "Latest blog post not updated recently ($([int]$mins)m). Aborting publish." }

    Write-Host "[OK] Health checks passed."

    # --- Commit + push new blog post to website repo ---
    Set-Location $AstroRoot

    $changes = git status --porcelain
    if ([string]::IsNullOrWhiteSpace($changes)) {
        Write-Host "[INFO] No changes detected in Astro repo. Skipping commit/push."
        return
    }

    git add .
    $today = (Get-Date).ToString("yyyy-MM-dd")
    git commit -m "Bastion Codex weekly brief ($today)"
    git push

    Write-Host "[OK] Weekly brief published to GitHub."
}
finally {
    Stop-Transcript | Out-Null
}