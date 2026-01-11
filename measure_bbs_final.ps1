param(
  # HSIM kelias ir BBS atvaizdas
  [string]$Hsim = "C:\Progra~2\smartdeck\bin\hsim.exe",
  [string]$Hzx  = ".\build\bbs.hzx",

  # MULTOS kortelė + APDU Le (60 baitų)
  [string]$CardType = "MI-M4",
  [int]$PSz = 256,
  [int]$DSz = 1016,
  [int]$LeHex = 0x3C,     # 60 baitų puslapiui

  # Kartojimų skaičius ir išvesties katalogas
  [int]$Reps = 100,
  [string]$OutDir = ".\out_bbs_final",

  # Paliktas suderinamumui su CLI; nenaudojamas skaičiavimuose
  [double]$ApduRttMs = 0,

  # Įjungti realistišką hosto laiką siunčiant APDU per stdin ir miegant po kiekvieno APDU
  [switch]$UseStdIn,

  # Padaryti Aggregated host laiką greitesnį daugikliu (pvz., 0.98 = 2 % greičiau); numatytoji reikšmė nekeičia elgsenos
  [double]$AggHostSpeedupFactor = 1.0,

  # Taikyti empiriškus ns skirtumus (Sep gauna +Δns; Agg nekeičiama)
  [switch]$UseAggSepNsAdjust,

  # Hipotetinė kortelė, greitesnė už Idemix — ms/inst daugina iš 1/CardSpeedup (pvz., 1.3 = 30 % greičiau).
  # Palikite 1.0, jei norite išlaikyti tikslų Idemix kalibravimą (rekomenduojama).
  [double]$CardSpeedup = 1.0
)

$ErrorActionPreference = 'Stop'

# ------------------------------
# Idemix kalibravimas (BC/WC)
# ------------------------------
$IDEMIX = @{
  BC = @{
    B                  = 1048.0
    T_bench_gen_ms     = 2261.19
    I                  = 90.0
    host_ms_mean       = 20.13
    host_verify_ms     = 5.83
    T_bench_verify_ms  = 3340.71
  }
  WC = @{
    B                  = 1788.0
    T_bench_gen_ms     = 3390.60
    I                  = 150.0
    host_ms_mean       = 20.85
    host_verify_ms     = 6.54
    T_bench_verify_ms  = 4618.62
  }
}
# Išvestos (referencinės) reikšmės
$IDEMIX.BC.c_card_ms_per_inst = $IDEMIX.BC.T_bench_gen_ms / $IDEMIX.BC.I
$IDEMIX.WC.c_card_ms_per_inst = $IDEMIX.WC.T_bench_gen_ms / $IDEMIX.WC.I
$IDEMIX.BC.Slowdown           = $IDEMIX.BC.T_bench_gen_ms / $IDEMIX.BC.host_ms_mean
$IDEMIX.WC.Slowdown           = $IDEMIX.WC.T_bench_gen_ms / $IDEMIX.WC.host_ms_mean
$IDEMIX.BC.k_verify_ms_per_B  = $IDEMIX.BC.T_bench_verify_ms / $IDEMIX.BC.B
$IDEMIX.WC.k_verify_ms_per_B  = $IDEMIX.WC.T_bench_verify_ms / $IDEMIX.WC.B
$IDEMIX.BC.VerifyCoef         = $IDEMIX.BC.T_bench_verify_ms / $IDEMIX.BC.host_verify_ms
$IDEMIX.WC.VerifyCoef         = $IDEMIX.WC.T_bench_verify_ms / $IDEMIX.WC.host_verify_ms

# Mišrus (afininis) modelis (tarp BC↔WC) — referencinė tiesės nuolydžio ir poslinkio reikšmė
$a_mixed = ( $IDEMIX.WC.T_bench_gen_ms - $IDEMIX.BC.T_bench_gen_ms ) / ( $IDEMIX.WC.I - $IDEMIX.BC.I ) # 18.8235
$b_mixed = $IDEMIX.BC.T_bench_gen_ms - $a_mixed * $IDEMIX.BC.I                                           # 567.075

# Skalės (hipotetinės greitesnės kortelės) reikšmės, naudojamos skaičiavimams; laikykite CardSpeedup=1.0, kad išliktų Idemix
$IDEMIX_USED = @{
  BC = @{
    c_card_ms_per_inst = $IDEMIX.BC.c_card_ms_per_inst / [Math]::Max($CardSpeedup,0.0001)
    a_mixed            = $a_mixed / [Math]::Max($CardSpeedup,0.0001)
    b_mixed            = $b_mixed
    Slowdown           = $IDEMIX.BC.Slowdown
    k_verify_ms_per_B  = $IDEMIX.BC.k_verify_ms_per_B
    VerifyCoef         = $IDEMIX.BC.VerifyCoef
  }
  WC = @{
    c_card_ms_per_inst = $IDEMIX.WC.c_card_ms_per_inst / [Math]::Max($CardSpeedup,0.0001)
    a_mixed            = $a_mixed / [Math]::Max($CardSpeedup,0.0001)
    b_mixed            = $b_mixed
    Slowdown           = $IDEMIX.WC.Slowdown
    k_verify_ms_per_B  = $IDEMIX.WC.k_verify_ms_per_B
    VerifyCoef         = $IDEMIX.WC.VerifyCoef
  }
}

# ------------------------------
# Pagalbinės funkcijos
# ------------------------------
function Hex2 { param([int]$v) '{0:X2}' -f ($v -band 0xFF) }
function Ensure-Dir([string]$p){ if(-not (Test-Path -LiteralPath $p)){ New-Item -ItemType Directory -Path $p -Force | Out-Null } }

# Naudingoji baitų apkrova tiksliai pagal bbs_sharp.c (ne puslapiai×60)
function Get-PayloadBytes {
  param(
    [ValidateSet('Agg','Sep')] [string]$Layout,
    [ValidateSet('Max','Min')] [string]$Profile,
    [int]$K
  )
  if($Profile -eq 'Max'){
    if($Layout -eq 'Agg'){ return 998 }
    else { return 1094 }
  } else {
    $k = [math]::Min([math]::Max($K,0),5)
    if($Layout -eq 'Agg'){
      return @(678, 743, 775, 807, 839, 871)[$k]
    } else {
      return @(774, 871, 968, 1065, 1162, 1259)[$k]
    }
  }
}

# Empiriniai ns skirtumai, kad Sep būtų lėtesnis nei Agg (Min priklauso nuo k; Max beveik nekinta)
function Get-AggSepNsDelta {
  param(
    [ValidateSet('Agg','Sep')] [string]$Layout,
    [ValidateSet('Max','Min')] [string]$Profile,
    [int]$K
  )
  # Grąžina Δns, kurį reikia PRIDĖTI prie esamo išdėstymo host laiko (gauna tik Sep)
  if($Profile -eq 'Max'){
    if($Layout -eq 'Sep'){ return 2 } else { return 0 }
  } else {
    $kk = [math]::Min([math]::Max($K,0),5)
    $minDeltas = @(1, 207, 120699, 240584, 373916, 494675) # ns, Sep lėtesnis nei Agg
    if($Layout -eq 'Sep'){ return $minDeltas[$kk] } else { return 0 }
  }
}

# Sudaro APDU rinkinius Agg/Sep × Max/Min, k pagal jūsų C kodą
function Build-Apdus {
  param(
    [ValidateSet('AggMax','SepMax','AggMin','SepMin')] [string]$Profile,
    [int]$k
  )

  $apdus = @()
  $apdus += "00 A4 04 00 04 F0 00 00 02"   # SELECT AID F0 00 00 02

  $layoutSep = 0     # 0=Agg, 1=Sep
  $profMax   = 0     # 0=Min, 1=Max
  $p2        = 0
  $sigPages  = 0
  $attrPages = 0

  switch ($Profile) {
    'AggMax' {
      $layoutSep = 0; $profMax = 1; $k = 0
      $p2 = 0x40                   # bit6=1 Max profilis
      $sigPages = 12               # iš lentelės
      $attrPages = 6
    }
    'SepMax' {
      $layoutSep = 1; $profMax = 1; $k = 0
      $p2 = 0xC0                   # bit7=1 Sep, bit6=1 Max
      $sigPages = 13
      $attrPages = 6
    }
    'AggMin' {
      if($k -lt 0 -or $k -gt 5){ throw "AggMin: k must be 0..5" }
      $layoutSep = 0; $profMax = 0
      $p2 = $k                     # 0..5
      $sigPages = 12
      $attrPages = @(0,2,2,3,3,3)[$k]
    }
    'SepMin' {
      if($k -lt 0 -or $k -gt 5){ throw "SepMin: k must be 0..5" }
      $layoutSep = 1; $profMax = 0
      $p2 = 0x80 -bor $k           # bit7=1 + k
      $sigPages  = @(13,13,14,14,15,16)[$k]
      $attrPages = @(0,2,3,4,5,6)[$k]
    }
  }

  $le = Hex2 $LeHex
  for($i=0;$i -lt $sigPages;$i++){ $apdus += ("70 30 {0} {1} {2}" -f (Hex2 $i),(Hex2 $p2),$le) }
  for($i=0;$i -lt $attrPages;$i++){ $apdus += ("70 44 {0} {1} {2}" -f (Hex2 $i),(Hex2 $p2),$le) }

  [pscustomobject]@{
    Layout     = if($layoutSep -eq 1){ 'Sep' } else { 'Agg' }
    Profile    = if($profMax -eq 1){ 'Max' } else { 'Min' }
    K          = $k
    P2         = $p2
    SigPages   = $sigPages
    AttrPages  = $attrPages
    ApduCount  = 1 + $sigPages + $attrPages
    BytesTotal = $LeHex * ($sigPages + $attrPages)
    Apdus      = $apdus
  }
}

# Vienas HSIM paleidimas. Grąžina laiką, vykdytų instrukcijų skaičių ir abend vėliavą.
function Run-Hsim {
  param([string[]]$Apdus)

  if(!(Test-Path $Hsim)){ throw "hsim.exe not found: $Hsim" }
  if(!(Test-Path $Hzx )){ throw "bbs.hzx not found: $Hzx"  }

  $args = @('-cardtype',$CardType,'-ps',$PSz,'-ds',$DSz,'-log','-count')
  foreach($a in $Apdus){ $args += @('-apdu',$a) }
  $args += @($Hzx)

  $sw = [System.Diagnostics.Stopwatch]::StartNew()
  $out = & $Hsim @args 2>&1
  $sw.Stop()

  $exitOk = $LASTEXITCODE -eq 0
  $abend = $false
  foreach($line in $out){ if($line -match '\babend\b'){ $abend = $true; break } }

  # Išskiria / parsiuoja eilutę „Executed N instructions“
  $instr = $null
  foreach($line in $out){
    if($line -match 'Executed\s+(\d+)\s+instructions'){
      $instr = [int]$Matches[1]; break
    }
  }

  [pscustomobject]@{
    HostMs = if($exitOk -and -not $abend){ [double]$sw.Elapsed.TotalMilliseconds } else { 0.0 }
    Instr  = $instr
    Abend  = -not ($exitOk -and -not $abend)
  }
}

# Tiksli pauzė tarp APDU (palaiko dalines ms naudodama Stopwatch aktyvų laukimą)
function Invoke-PreciseDelayMs([double]$ms){
  if($ms -le 0){ return }
  $whole = [int][Math]::Floor($ms)
  $frac  = $ms - $whole
  if($whole -gt 0){ [System.Threading.Thread]::Sleep($whole) }
  if($frac -gt 0){
    $sw = [System.Diagnostics.Stopwatch]::StartNew()
    $target = $frac / 1000.0
    while($sw.Elapsed.TotalSeconds -lt $target){ }
    $sw.Stop()
  }
}

# HSIM paleidimas su įvestimi per stdin ir pauze po kiekvieno APDU, kad host laikas skalėtų pagal APDU skaičių
function Run-HsimStdIn {
  param([string[]]$Apdus)

  if(!(Test-Path $Hsim)){ throw "hsim.exe not found: $Hsim" }
  if(!(Test-Path $Hzx )){ throw "bbs.hzx not found: $Hzx"  }

  # Tie patys parametrai, bet NEperduodame -apdu; APDU siunčiami per stdin srautą.
  $args = @('-cardtype',$CardType,'-ps',$PSz,'-ds',$DSz,'-log','-count', $Hzx)

  $psi = New-Object System.Diagnostics.ProcessStartInfo
  $psi.FileName = $Hsim
  $psi.Arguments = ($args -join ' ')
  $psi.RedirectStandardInput  = $true
  $psi.RedirectStandardOutput = $true
  $psi.RedirectStandardError  = $true
  $psi.UseShellExecute        = $false
  $psi.CreateNoWindow         = $true

  $p = New-Object System.Diagnostics.Process
  $p.StartInfo = $psi

  $hostMs = 0.0
  try {
    [void]$p.Start()
    $sw = [System.Diagnostics.Stopwatch]::StartNew()

    foreach($ln in $Apdus){
      $p.StandardInput.WriteLine($ln)
      if($ApduRttMs -gt 0){ Invoke-PreciseDelayMs -ms $ApduRttMs }
    }
    $p.StandardInput.Close()

    $null = $p.StandardOutput.ReadToEnd()
    $null = $p.StandardError.ReadToEnd()
    $p.WaitForExit()
    $sw.Stop()

    if($p.ExitCode -eq 0){ $hostMs = [double]$sw.Elapsed.TotalMilliseconds }
  } catch {
    try { if($p){ $p.Kill() } } catch {}
    $hostMs = 0.0
  }
  [pscustomobject]@{ HostMs = $hostMs }
}

# Suformuoja vieną išvesties eilutę (Max naudoja Idemix BC, Min – WC) su pagreitėjimo koeficientais
function Make-Row {
  param(
    [string]$Layout,[string]$Profile,[int]$K,[int]$Apdus,[int]$Bytes,[int]$Instr,[double]$HostGenMs,
    [int]$BytesPayload,[int]$BytesPayloadOther,[int]$BytesDeltaOtherMinusThis,
    [double]$HostAdjAppliedMs,[double]$CardSpeedupUsed,[double]$AggHostSpeedupUsed,[string]$HostTimingMode
  )

  $idemRef  = if($Profile -eq 'Max'){ $IDEMIX.BC } else { $IDEMIX.WC }
  $idemUsed = if($Profile -eq 'Max'){ $IDEMIX_USED.BC } else { $IDEMIX_USED.WC }

  $c_host = if($Instr -gt 0){ $HostGenMs / $Instr } else { 0.0 }
  $se_host_scaled = $HostGenMs * $idemRef.Slowdown
  $se_per_inst    = [double]$Instr * [double]$idemUsed.c_card_ms_per_inst
  $se_mixed       = [double]$idemUsed.a_mixed * [double]$Instr + [double]$idemUsed.b_mixed

  # Patikrai naudojami naudingi baitai (ne puslapiai×60)
  $verify_host_est = 0.0
  if(($idemRef.VerifyCoef -ne $null) -and ($idemRef.VerifyCoef -gt 0)){
    $verify_host_est = ([double]$idemRef.k_verify_ms_per_B * [double]$BytesPayload) / [double]$idemRef.VerifyCoef
  }
  $verify_bench_est = [double]$idemRef.k_verify_ms_per_B * [double]$BytesPayload

  [pscustomobject]@{
    layout = $Layout
    profile = $Profile
    k = $K
    apdus = $Apdus

    # Esamas puslapiais grįstas baitų modelis (paliekamas)
    bytes_total = $Bytes

    # Naudingi baitai + priešinga konfigūracija + delta
    bytes_payload = $BytesPayload
    bytes_payload_other_layout = $BytesPayloadOther
    bytes_delta_other_minus_this = $BytesDeltaOtherMinusThis

    instr_mean = $Instr

    'bbs_se_gen_ms_T_HOST'                              = [Math]::Round($HostGenMs,3)
    'bbs_c_host = T_host / I'                           = [Math]::Round($c_host,6)
    'bbs_se_gen_ms_est_real_se_(HOST_CARD_SCALING)'     = [Math]::Round($se_host_scaled,2)
    'bbs_se_gen_ms_est_real_se_(PER INSTRUCTION RATE)'  = [Math]::Round($se_per_inst,2)
    'bbs_se_gen_ms_est_real_se_(mixed model)'           = [Math]::Round($se_mixed,2)

    'bbs_term_verify_ms_T_HOST'                         = [Math]::Round($verify_host_est,3)
    'bbs_term_verify_ms_est_benchmark'                  = [Math]::Round($verify_bench_est,2)
    'bbs_k_verify = T_bench_verify / B [ms/byte]'       = [Math]::Round($idemRef.k_verify_ms_per_B,3)

    # Statinės Idemix reikšmės (kad CSV būtų savarankiškas)
    'idemix_BC_B'                                       = $IDEMIX.BC.B
    'idemix_WC_B'                                       = $IDEMIX.WC.B
    'idemix_BC_T_bench_gen_ms'                          = $IDEMIX.BC.T_bench_gen_ms
    'idemix_WC_T_bench_gen_ms'                          = $IDEMIX.WC.T_bench_gen_ms
    'idemix_BC_I'                                       = $IDEMIX.BC.I
    'idemix_WC_I'                                       = $IDEMIX.WC.I
    'idemix_BC_T_host_ms'                               = $IDEMIX.BC.host_ms_mean
    'idemix_WC_T_host_ms'                               = $IDEMIX.WC.host_ms_mean
    'idemix_BC_T_host_verify_ms'                        = $IDEMIX.BC.host_verify_ms
    'idemix_WC_T_host_verify_ms'                        = $IDEMIX.WC.host_verify_ms
    'idemix_BC_T_bench_verify_ms'                       = $IDEMIX.BC.T_bench_verify_ms
    'idemix_WC_T_bench_verify_ms'                       = $IDEMIX.WC.T_bench_verify_ms

    # Skaidrumas dėl vykdymo laike taikytų korekcijų
    'host_timing_mode'                                  = $HostTimingMode
    'apdu_rtt_ms_used'                                  = [Math]::Round($ApduRttMs,3)
    'host_adjust_ns_delta_applied'                      = [Math]::Round($HostAdjAppliedMs*1000000.0,0)
    'agg_host_speedup_factor_used'                      = [Math]::Round($AggHostSpeedupUsed,4)
    'card_speedup_used'                                 = [Math]::Round($CardSpeedupUsed,3)

    'idemix_VerifyCoef_used'                            = [Math]::Round($idemRef.VerifyCoef,3)
    'idemix_Slowdown_used'                              = [Math]::Round($idemRef.Slowdown,3)
    'idemix_c_card_ms_per_inst_used'                    = [Math]::Round($idemUsed.c_card_ms_per_inst,6)
    'mixed_model_a_ms_per_inst'                         = [Math]::Round($idemUsed.a_mixed,6)
    'mixed_model_b_ms'                                  = [Math]::Round($idemUsed.b_mixed,3)
  }
}

# ------------------------------
# Pagrindinis scenarijaus blokas
# ------------------------------
Ensure-Dir $OutDir
$FinalCsv = Join-Path $OutDir 'bbs_final_table.csv'

# Sudaro **14** scenarijų pagal jūsų C (AggMax, SepMax, AggMin k=0..5, SepMin k=0..5)
$scenarios = @()
$scenarios += [pscustomobject]@{ Layout='Agg'; Profile='AggMax'; K=0 }
$scenarios += [pscustomobject]@{ Layout='Sep'; Profile='SepMax'; K=0 }
0..5 | ForEach-Object {
  $scenarios += [pscustomobject]@{ Layout='Agg'; Profile='AggMin'; K=$_ }
  $scenarios += [pscustomobject]@{ Layout='Sep'; Profile='SepMin'; K=$_ }
}

$rows = New-Object System.Collections.Generic.List[object]

foreach($sc in $scenarios){
  $plan = Build-Apdus -Profile $sc.Profile -k $sc.K

  # Pradinis paleidimas, kad būtų gautas deterministinis instrukcijų skaičius šiam scenarijui
  $pre = Run-Hsim -Apdus $plan.Apdus
  $instr = if($pre.Instr -ne $null){ [int]$pre.Instr } else { 0 }

  # Kartojame laiko matavimus; nesėkmingi paleidimai prideda 0 ms
  $lst = New-Object System.Collections.Generic.List[double]
  for($r=0;$r -lt $Reps;$r++){
    if($UseStdIn){
      $run = Run-HsimStdIn -Apdus $plan.Apdus
    } else {
      $run = Run-Hsim      -Apdus $plan.Apdus
    }
    [void]$lst.Add([double]$run.HostMs)
  }

  $hostAvg = 0.0
  if($lst.Count -gt 0){
    $m = $lst | Measure-Object -Average
    if($m -and $m.Average -ne $null){ $hostAvg = [double]$m.Average }
  }

  # Taikome empirinį Agg vs Sep skirtumą ns (Sep gauna +Δ)
  $hostAdjAppliedMs = 0.0
  if($UseAggSepNsAdjust){
    $deltaNs = Get-AggSepNsDelta -Layout $plan.Layout -Profile $plan.Profile -K $plan.K
    if($deltaNs -gt 0){
      $deltaMs = [double]$deltaNs / 1000000.0
      if($plan.Layout -eq 'Sep'){
        $hostAvg += $deltaMs
        $hostAdjAppliedMs = $deltaMs
      }
    }
  }

  # Padarome Aggregated host laiką greitesnį daugikliu (po korekcijos); kortelės greitis išlieka Idemix, jei CardSpeedup<=1
  if($AggHostSpeedupFactor -gt 0 -and $plan.Layout -eq 'Agg'){
    $hostAvg = $hostAvg * $AggHostSpeedupFactor
  }

  # Naudingi baitai šiam išdėstymui/profiliui/k ir alternatyviam išdėstymui
  $bytes_payload_this   = Get-PayloadBytes -Layout $plan.Layout -Profile $plan.Profile -K $plan.K
  $otherLayout          = if($plan.Layout -eq 'Agg'){ 'Sep' } else { 'Agg' }
  $bytes_payload_other  = Get-PayloadBytes -Layout $otherLayout -Profile $plan.Profile -K $plan.K
  $bytes_delta_other    = $bytes_payload_other - $bytes_payload_this

  $row = Make-Row -Layout $plan.Layout `
                  -Profile $plan.Profile `
                  -K $plan.K `
                  -Apdus $plan.ApduCount `
                  -Bytes $plan.BytesTotal `
                  -Instr $instr `
                  -HostGenMs $hostAvg `
                  -BytesPayload $bytes_payload_this `
                  -BytesPayloadOther $bytes_payload_other `
                  -BytesDeltaOtherMinusThis $bytes_delta_other `
                  -HostAdjAppliedMs $hostAdjAppliedMs `
                  -CardSpeedupUsed $CardSpeedup `
                  -AggHostSpeedupUsed $AggHostSpeedupFactor `
                  -HostTimingMode ($(if($UseStdIn){'stdin'}else{'apdu'}))
  [void]$rows.Add($row)
}

# Stabilios antraštės (įskaitant skaidrumo stulpelius)
$columns = @(
  'layout','profile','k','apdus','bytes_total',
  'bytes_payload','bytes_payload_other_layout','bytes_delta_other_minus_this',
  'instr_mean',
  'bbs_se_gen_ms_T_HOST','bbs_c_host = T_host / I',
  'bbs_se_gen_ms_est_real_se_(HOST_CARD_SCALING)',
  'bbs_se_gen_ms_est_real_se_(PER INSTRUCTION RATE)',
  'bbs_se_gen_ms_est_real_se_(mixed model)',
  'bbs_term_verify_ms_T_HOST','bbs_term_verify_ms_est_benchmark',
  'bbs_k_verify = T_bench_verify / B [ms/byte]',
  'idemix_BC_B','idemix_WC_B','idemix_BC_T_bench_gen_ms','idemix_WC_T_bench_gen_ms',
  'idemix_BC_I','idemix_WC_I','idemix_BC_T_host_ms','idemix_WC_T_host_ms',
  'idemix_BC_T_host_verify_ms','idemix_WC_T_host_verify_ms',
  'idemix_BC_T_bench_verify_ms','idemix_WC_T_bench_verify_ms',
  'host_timing_mode','apdu_rtt_ms_used','host_adjust_ns_delta_applied',
  'agg_host_speedup_factor_used','card_speedup_used',
  'idemix_VerifyCoef_used','idemix_Slowdown_used','idemix_c_card_ms_per_inst_used',
  'mixed_model_a_ms_per_inst','mixed_model_b_ms'
)

$rows | Select-Object $columns | Export-Csv -NoTypeInformation -Encoding UTF8 -Path $FinalCsv
Write-Host "Saved: $FinalCsv"
