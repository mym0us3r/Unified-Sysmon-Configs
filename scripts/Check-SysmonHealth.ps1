#Requires -RunAsAdministrator
<#
.SYNOPSIS
    Check-SysmonHealth.ps1 - Validacao completa do Sysmon Nativo no Windows 11

.DESCRIPTION
    Script de diagnostico senior para verificar o status, estado e saidas do
    Sysmon Nativo (Windows Optional Feature). Valida: Feature, Binario,
    Servico, Driver, Event Log, Configuracao e exibe relatorio interativo no console.

.PARAMETER ExportReport
    Exporta o relatorio para um arquivo .txt na Area de Trabalho do usuario.

.PARAMETER EventSampleCount
    Quantidade de eventos recentes a exibir na amostra. Padrao: 10

.EXAMPLE
    .\Check-SysmonHealth.ps1
    .\Check-SysmonHealth.ps1 -ExportReport
    .\Check-SysmonHealth.ps1 -ExportReport -EventSampleCount 20

.NOTES
    Plataforma  : Windows 11 Build 22000+ / Windows Server 2025
    Requisito   : Executar como Administrador
    Versao      : 2.1
    Referencia  : https://learn.microsoft.com/pt-br/windows/security/operating-system-security/sysmon/how-to-enable-sysmon
#>

[CmdletBinding()]
param(
    [switch]$ExportReport,
    [int]$EventSampleCount = 10
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "SilentlyContinue"

# =============================================================================
#  CONSTANTES E CONFIGURACAO
# =============================================================================
$SCRIPT_VERSION = "2.1"
$SYSMON_EXE     = "C:\Windows\System32\Sysmon.exe"
$SYSMON_CONFIG  = "C:\Windows\System32\Sysmon\config.xml"
$SYSMON_LOG     = "Microsoft-Windows-Sysmon/Operational"
$SYSMON_SERVICE = "Sysmon"
$SYSMON_DRIVER  = "SysmonDrv"
$SYSMON_FEATURE = "Sysmon"
$REPORT_PATH    = "$env:USERPROFILE\Desktop\SysmonHealth_$(Get-Date -Format 'yyyyMMdd_HHmmss').txt"

# Mapa de Event IDs
$EVENT_ID_MAP = @{
    1  = @{ Name = "Process Creation";           Severity = "INFO"     }
    2  = @{ Name = "File Creation Time Changed"; Severity = "WARN"     }
    3  = @{ Name = "Network Connection";         Severity = "INFO"     }
    4  = @{ Name = "Sysmon Service State";       Severity = "INFO"     }
    5  = @{ Name = "Process Terminated";         Severity = "INFO"     }
    6  = @{ Name = "Driver Loaded";              Severity = "WARN"     }
    7  = @{ Name = "Image Loaded";               Severity = "INFO"     }
    8  = @{ Name = "CreateRemoteThread";         Severity = "CRITICAL" }
    9  = @{ Name = "RawAccessRead";              Severity = "CRITICAL" }
    10 = @{ Name = "Process Access";             Severity = "CRITICAL" }
    11 = @{ Name = "File Create";                Severity = "INFO"     }
    12 = @{ Name = "Registry Create/Delete";     Severity = "WARN"     }
    13 = @{ Name = "Registry Value Set";         Severity = "WARN"     }
    14 = @{ Name = "Registry Key Renamed";       Severity = "WARN"     }
    15 = @{ Name = "File Create Stream Hash";    Severity = "WARN"     }
    16 = @{ Name = "Sysmon Config Change";       Severity = "WARN"     }
    17 = @{ Name = "Pipe Created";               Severity = "INFO"     }
    18 = @{ Name = "Pipe Connected";             Severity = "INFO"     }
    19 = @{ Name = "WMI EventFilter";            Severity = "CRITICAL" }
    20 = @{ Name = "WMI EventConsumer";          Severity = "CRITICAL" }
    21 = @{ Name = "WMI Binding";                Severity = "CRITICAL" }
    22 = @{ Name = "DNS Query";                  Severity = "INFO"     }
    23 = @{ Name = "File Delete";                Severity = "WARN"     }
    24 = @{ Name = "Clipboard Capture";          Severity = "WARN"     }
    25 = @{ Name = "Process Tampering";          Severity = "CRITICAL" }
    26 = @{ Name = "File Delete Detected";       Severity = "WARN"     }
    27 = @{ Name = "File Block Executable";      Severity = "CRITICAL" }
    28 = @{ Name = "File Block Shredding";       Severity = "CRITICAL" }
    29 = @{ Name = "File Executable Detected";   Severity = "WARN"     }
}

# =============================================================================
#  ENGINE DE OUTPUT
# =============================================================================
$script:ReportBuffer = [System.Collections.Generic.List[string]]::new()

function Write-Line {
    param(
        [string]$Text  = "",
        [string]$Color = "White"
    )
    Write-Host $Text -ForegroundColor $Color
    $script:ReportBuffer.Add($Text)
}

function Write-Separator {
    param(
        [string]$Char   = "-",
        [int]$Length    = 70,
        [string]$Color  = "DarkGray"
    )
    Write-Line ($Char * $Length) $Color
}

function Write-SectionHeader {
    param(
        [string]$Title,
        [int]$Number
    )
    Write-Line ""
    Write-Separator "=" 70 "Cyan"
    Write-Line "  [$Number] $($Title.ToUpper())" "Cyan"
    Write-Separator "=" 70 "Cyan"
}

function Write-CheckResult {
    param(
        [string]$Label,
        [string]$Value,
        [ValidateSet("OK","WARN","FAIL","INFO","SKIP")]
        [string]$Status = "INFO",
        [int]$Indent    = 4
    )

    $pad = " " * $Indent

    $badge = switch ($Status) {
        "OK"   { "[  OK  ]" }
        "WARN" { "[ WARN ]" }
        "FAIL" { "[ FAIL ]" }
        "INFO" { "[ INFO ]" }
        "SKIP" { "[ SKIP ]" }
    }

    $badgeColor = switch ($Status) {
        "OK"   { "Green"    }
        "WARN" { "Yellow"   }
        "FAIL" { "Red"      }
        "INFO" { "Cyan"     }
        "SKIP" { "DarkGray" }
    }

    Write-Host "$pad" -NoNewline
    Write-Host $badge -ForegroundColor $badgeColor -NoNewline
    Write-Host "  " -NoNewline
    Write-Host ("{0,-30}" -f $Label) -ForegroundColor Gray -NoNewline
    Write-Host $Value -ForegroundColor White

    $script:ReportBuffer.Add("$pad$badge  $("{0,-30}" -f $Label)$Value")
}

function Write-SubInfo {
    param(
        [string]$Text,
        [string]$Color  = "DarkGray",
        [int]$Indent    = 10
    )
    $pad = " " * $Indent
    Write-Line "$pad->  $Text" $Color
}

# =============================================================================
#  SCORECARD GLOBAL
# =============================================================================
$script:Score    = @{ OK = 0; WARN = 0; FAIL = 0 }
$script:Findings = [System.Collections.Generic.List[string]]::new()

function Register-Result {
    param(
        [string]$Status,
        [string]$Finding = ""
    )
    $script:Score[$Status]++
    if ($Finding -and $Status -in "WARN","FAIL") {
        $script:Findings.Add("[$Status] $Finding")
    }
}

# =============================================================================
#  FUNCOES DE VERIFICACAO
# =============================================================================

function Test-AdminPrivilege {
    $current   = [Security.Principal.WindowsIdentity]::GetCurrent()
    $principal = New-Object Security.Principal.WindowsPrincipal($current)
    return $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
}

function Get-SysmonFeatureStatus {
    Write-SectionHeader "Windows Optional Feature" 1
    try {
        $feature = Get-WindowsOptionalFeature -Online -FeatureName $SYSMON_FEATURE
        if ($null -eq $feature) {
            Write-CheckResult "Feature Sysmon" "Nao encontrada no sistema" "FAIL"
            Register-Result "FAIL" "Windows Optional Feature 'Sysmon' nao existe neste build"
            return $false
        }

        $stateOk = ($feature.State -eq "Enabled")
        Write-CheckResult "Feature Name"   $feature.FeatureName   "INFO"
        Write-CheckResult "Estado"         $feature.State         $(if ($stateOk) { "OK" } else { "FAIL" })
        Write-CheckResult "Restart Needed" $feature.RestartNeeded "INFO"

        if (-not $stateOk) {
            Register-Result "FAIL" "Feature Sysmon esta '$($feature.State)' -- execute: Enable-WindowsOptionalFeature -Online -FeatureName Sysmon"
            Write-SubInfo "CORRECAO: Enable-WindowsOptionalFeature -Online -FeatureName Sysmon" "Yellow"
        } else {
            Register-Result "OK"
        }
        return $stateOk
    }
    catch {
        Write-CheckResult "Feature Query" "Erro: $($_.Exception.Message)" "FAIL"
        Register-Result "FAIL" "Falha ao consultar Windows Optional Feature"
        return $false
    }
}

function Get-SysmonBinaryStatus {
    Write-SectionHeader "Binario Sysmon.exe" 2

    $exists = Test-Path $SYSMON_EXE
    Write-CheckResult "Caminho" $SYSMON_EXE $(if ($exists) { "OK" } else { "FAIL" })

    if (-not $exists) {
        Register-Result "FAIL" "Binario Sysmon.exe nao encontrado em $SYSMON_EXE"
        Write-SubInfo "Execute 'sysmon -i' para instalar apos habilitar a feature" "Yellow"
        return
    }

    try {
        $item    = Get-Item $SYSMON_EXE
        $version = $item.VersionInfo
        $sig     = Get-AuthenticodeSignature $SYSMON_EXE
        $sigOk   = ($sig.Status -eq "Valid")
        $sizeKB  = [math]::Round($item.Length / 1KB, 2)

        Write-CheckResult "Versao"          $version.FileVersion                               "INFO"
        Write-CheckResult "Descricao"       $version.FileDescription                           "INFO"
        Write-CheckResult "Produto"         $version.ProductName                               "INFO"
        Write-CheckResult "Tamanho"         "$sizeKB KB"                                       "INFO"
        Write-CheckResult "Data Criacao"    $item.CreationTime.ToString("yyyy-MM-dd HH:mm:ss") "INFO"
        Write-CheckResult "Ultima Escrita"  $item.LastWriteTime.ToString("yyyy-MM-dd HH:mm:ss") "INFO"
        Write-CheckResult "Assinatura"      $sig.Status                                        $(if ($sigOk) { "OK" } else { "FAIL" })

        if ($sigOk) {
            Write-SubInfo "Signed by: $($sig.SignerCertificate.Subject)" "DarkGray"
        } else {
            Register-Result "FAIL" "Assinatura digital do binario invalida: $($sig.Status)"
        }

        Register-Result "OK"
    }
    catch {
        Write-CheckResult "Leitura" "Erro: $($_.Exception.Message)" "FAIL"
        Register-Result "FAIL" "Falha ao inspecionar binario Sysmon.exe"
    }
}

function Get-SysmonServiceStatus {
    Write-SectionHeader "Servico Windows (Sysmon)" 3
    try {
        $svc       = Get-Service -Name $SYSMON_SERVICE -ErrorAction Stop
        $running   = ($svc.Status -eq "Running")
        $autoStart = ($svc.StartType -in "Automatic","AutomaticDelayedStart")

        Write-CheckResult "Nome do Servico" $svc.Name        "INFO"
        Write-CheckResult "DisplayName"     $svc.DisplayName "INFO"
        Write-CheckResult "Status"          $svc.Status      $(if ($running)   { "OK" } else { "FAIL" })
        Write-CheckResult "Tipo de Inicio"  $svc.StartType   $(if ($autoStart) { "OK" } else { "WARN" })

        $wmiSvc = Get-WmiObject Win32_Service -Filter "Name='$SYSMON_SERVICE'"
        if ($wmiSvc) {
            Write-CheckResult "Logon As"    $wmiSvc.StartName  "INFO"
            Write-CheckResult "Path do Exe" $wmiSvc.PathName   "INFO"
            Write-CheckResult "PID"         $wmiSvc.ProcessId  "INFO"
            Write-CheckResult "Exit Code"   $wmiSvc.ExitCode   $(if ($wmiSvc.ExitCode -eq 0) { "OK" } else { "WARN" })
        }

        if (-not $running) {
            Register-Result "FAIL" "Servico Sysmon nao esta Running (Status: $($svc.Status))"
            Write-SubInfo "CORRECAO: Start-Service -Name Sysmon" "Yellow"
        }
        if (-not $autoStart) {
            Register-Result "WARN" "Servico Sysmon nao esta configurado para inicio Automatico"
            Write-SubInfo "CORRECAO: Set-Service -Name Sysmon -StartupType Automatic" "Yellow"
        }
        if ($running -and $autoStart) {
            Register-Result "OK"
        }
    }
    catch {
        Write-CheckResult "Servico Sysmon" "Nao encontrado" "FAIL"
        Register-Result "FAIL" "Servico '$SYSMON_SERVICE' nao encontrado -- execute: sysmon -i"
        Write-SubInfo "CORRECAO: sysmon -i  (apos habilitar a feature)" "Yellow"
    }
}

function Get-SysmonDriverStatus {
    Write-SectionHeader "Driver do Kernel (SysmonDrv)" 4
    try {
        $drv     = Get-Service -Name $SYSMON_DRIVER -ErrorAction Stop
        $running = ($drv.Status -eq "Running")

        Write-CheckResult "Nome do Driver" $drv.Name      "INFO"
        Write-CheckResult "Status"         $drv.Status    $(if ($running) { "OK" } else { "FAIL" })
        Write-CheckResult "Tipo de Inicio" $drv.StartType "INFO"

        $wmiDrv = Get-WmiObject Win32_SystemDriver -Filter "Name='$SYSMON_DRIVER'"
        if ($wmiDrv) {
            Write-CheckResult "Path do Driver" $wmiDrv.PathName "INFO"
            Write-CheckResult "Estado WMI"     $wmiDrv.State    $(if ($wmiDrv.State -eq "Running") { "OK" } else { "FAIL" })
        }

        $dqRaw = driverquery /FO CSV /NH 2>$null
        if ($dqRaw) {
            $dqEntry = $dqRaw | ConvertFrom-Csv -Header "Module","DisplayName","DriverType","LinkDate" |
                       Where-Object { $_.Module -like "*Sysmon*" }
            if ($dqEntry) {
                Write-CheckResult "DriverQuery" "Encontrado: $($dqEntry.DisplayName)" "OK"
            }
        }

        if (-not $running) {
            Register-Result "FAIL" "Driver SysmonDrv nao esta Running"
        } else {
            Register-Result "OK"
        }
    }
    catch {
        Write-CheckResult "Driver SysmonDrv" "Nao encontrado" "FAIL"
        Register-Result "FAIL" "Driver '$SYSMON_DRIVER' nao encontrado -- kernel hook inativo"
    }
}

function Get-SysmonEventLogStatus {
    Write-SectionHeader "Event Log (Sysmon/Operational)" 5
    try {
        $log     = Get-WinEvent -ListLog $SYSMON_LOG -ErrorAction Stop
        $enabled = $log.IsEnabled
        $sizeMB  = [math]::Round($log.MaximumSizeInBytes / 1MB, 2)

        Write-CheckResult "Log Path"         $log.LogName  "INFO"
        Write-CheckResult "Habilitado"       $log.IsEnabled $(if ($enabled) { "OK" } else { "FAIL" })
        Write-CheckResult "Tamanho Max."     "$sizeMB MB"  "INFO"
        Write-CheckResult "Tipo"             $log.LogType  "INFO"
        Write-CheckResult "Modo de Retencao" $log.LogMode  "INFO"

        if (-not $enabled) {
            Register-Result "FAIL" "Event Log Sysmon/Operational esta desabilitado"
            Write-SubInfo "CORRECAO: wevtutil set-log '$SYSMON_LOG' /enabled:true" "Yellow"
            return
        }

        $newestEvent = Get-WinEvent -LogName $SYSMON_LOG -MaxEvents 1 -ErrorAction SilentlyContinue
        if ($newestEvent) {
            Write-CheckResult "Evento mais recente" $newestEvent[0].TimeCreated.ToString("yyyy-MM-dd HH:mm:ss") "INFO"
        }

        Register-Result "OK"
    }
    catch {
        Write-CheckResult "Event Log" "Nao acessivel: $($_.Exception.Message)" "FAIL"
        Register-Result "FAIL" "Falha ao acessar Event Log Sysmon/Operational"
    }
}

function Get-SysmonConfigStatus {
    Write-SectionHeader "Arquivo de Configuracao" 6

    $exists = Test-Path $SYSMON_CONFIG
    Write-CheckResult "Caminho" $SYSMON_CONFIG $(if ($exists) { "OK" } else { "WARN" })

    if (-not $exists) {
        Register-Result "WARN" "config.xml nao encontrado -- Sysmon pode estar usando configuracao padrao"
        Write-SubInfo "Aplique um config: sysmon -c C:\path\to\config.xml" "Yellow"
        Write-SubInfo "Templates: github.com/SwiftOnSecurity/sysmon-config" "DarkGray"
        return
    }

    try {
        $cfg     = Get-Item $SYSMON_CONFIG
        $hash    = (Get-FileHash $SYSMON_CONFIG -Algorithm SHA256).Hash
        $sizeByt = $cfg.Length

        Write-CheckResult "Tamanho"            "$sizeByt bytes"                                           "INFO"
        Write-CheckResult "Ultima Modificacao" $cfg.LastWriteTime.ToString("yyyy-MM-dd HH:mm:ss")         "INFO"
        Write-CheckResult "SHA-256"            $hash                                                       "INFO"

        [xml]$xmlCfg = Get-Content $SYSMON_CONFIG -Encoding UTF8 -ErrorAction Stop
        $schema  = $xmlCfg.Sysmon.GetAttribute("schemaversion")
        $hashAlg = if ($xmlCfg.Sysmon.HashAlgorithms) { $xmlCfg.Sysmon.HashAlgorithms } else { "N/A" }

        # Suporta dois layouts de config:
        #   1) Flat  : EventFiltering > ProcessCreate onmatch="..."
        #   2) Nested: EventFiltering > RuleGroup > ProcessCreate onmatch="..."
        # Usa GetAttribute() para evitar erro de StrictMode em nos sem o atributo
        $eventNodes = [System.Collections.Generic.List[System.Xml.XmlElement]]::new()
        foreach ($child in $xmlCfg.Sysmon.EventFiltering.ChildNodes) {
            if ($child -isnot [System.Xml.XmlElement]) { continue }   # pula comentarios/whitespace
            if ($child.Name -eq "RuleGroup") {
                foreach ($inner in $child.ChildNodes) {
                    if ($inner -is [System.Xml.XmlElement]) { $eventNodes.Add($inner) }
                }
            } else {
                $eventNodes.Add($child)
            }
        }
        $filterCnt = $eventNodes.Count

        Write-CheckResult "Schema Version"   $schema   $(if ($schema) { "OK" } else { "WARN" })
        Write-CheckResult "Hash Algorithm"   $hashAlg  "INFO"
        Write-CheckResult "Regras de Filtro" "$filterCnt evento(s) configurado(s)" "INFO"

        if ($eventNodes.Count -gt 0) {
            Write-Line ""
            Write-Line "    -- Eventos Configurados no XML --" "DarkCyan"
            foreach ($node in $eventNodes) {
                $omVal      = $node.GetAttribute("onmatch")   # seguro com StrictMode
                $onMatch    = if ($omVal) { "onmatch=$omVal" } else { "onmatch=N/A" }
                $rulesCount = ($node.ChildNodes | Where-Object { $_ -is [System.Xml.XmlElement] } | Measure-Object).Count
                $omColor    = if ($omVal -eq "include") { "Green" } elseif ($omVal -eq "exclude") { "Yellow" } else { "Gray" }
                $line       = "    [*]  {0,-32} {1,-22} regras: {2}" -f $node.Name, $onMatch, $rulesCount
                Write-Host $line -ForegroundColor $omColor
                $script:ReportBuffer.Add($line)
            }
        }

        Register-Result "OK"
    }
    catch {
        $errMsg = $_.Exception.Message
        $errLine = $_.InvocationInfo.ScriptLineNumber
        Write-CheckResult "Parse XML" "Linha $errLine -- $errMsg" "FAIL"
        Register-Result "FAIL" "Falha ao fazer parse do config.xml (linha $errLine)"
    }
}

function Get-SysmonEventSample {
    Write-SectionHeader "Amostra de Eventos Recentes" 7
    try {
        $sample = Get-WinEvent -LogName $SYSMON_LOG -MaxEvents $EventSampleCount -ErrorAction Stop

        if (-not $sample) {
            Write-CheckResult "Eventos" "Nenhum evento disponivel" "WARN"
            Register-Result "WARN" "Sem eventos no log para exibir amostra"
            return
        }

        Write-Line "    Exibindo os $($sample.Count) eventos mais recentes:" "Gray"
        Write-Line ""
        Write-Separator "-" 70 "DarkGray"

        foreach ($evt in $sample) {
            $eid      = $evt.Id
            $eidInfo  = if ($EVENT_ID_MAP.ContainsKey($eid)) { $EVENT_ID_MAP[$eid] } else { @{ Name = "Event $eid"; Severity = "INFO" } }
            $evtColor = switch ($eidInfo.Severity) {
                "CRITICAL" { "Red"    }
                "WARN"     { "Yellow" }
                default    { "Cyan"   }
            }
            $timeStr = $evt.TimeCreated.ToString("yyyy-MM-dd HH:mm:ss")

            Write-Host ("    {0}  " -f $timeStr) -ForegroundColor DarkGray -NoNewline
            Write-Host ("EID {0,3}" -f $eid) -ForegroundColor $evtColor -NoNewline
            Write-Host ("  {0,-32}" -f $eidInfo.Name) -ForegroundColor White -NoNewline

            try {
                $xml     = [xml]$evt.ToXml()
                $imgNode = $xml.Event.EventData.Data |
                           Where-Object { $_.Name -in "Image","TargetFilename","DestinationIp","TargetObject" } |
                           Select-Object -First 1
                if ($imgNode) {
                    $val      = $imgNode.'#text'
                    $shortVal = if ($val.Length -gt 35) { "..." + $val.Substring($val.Length - 35) } else { $val }
                    Write-Host $shortVal -ForegroundColor DarkGray
                } else {
                    Write-Host ""
                }
            }
            catch { Write-Host "" }

            $script:ReportBuffer.Add("    $timeStr  EID $("{0,3}" -f $eid)  $($eidInfo.Name)")
        }

        Write-Separator "-" 70 "DarkGray"
        Register-Result "OK"
    }
    catch {
        Write-CheckResult "Amostra" "Erro ao ler eventos: $($_.Exception.Message)" "FAIL"
        Register-Result "FAIL" "Falha ao coletar amostra de eventos"
    }
}

function Get-RegistryKeys {
    Write-SectionHeader "Chaves de Registro" 8

    $keys = @(
        @{ Path = "HKLM:\SYSTEM\CurrentControlSet\Services\Sysmon";    Label = "Servico" },
        @{ Path = "HKLM:\SYSTEM\CurrentControlSet\Services\SysmonDrv"; Label = "Driver"  },
        @{ Path = "HKLM:\SOFTWARE\Sysmon";                             Label = "Config"  }
    )

    foreach ($key in $keys) {
        $exists = Test-Path $key.Path
        Write-CheckResult $key.Label $key.Path $(if ($exists) { "OK" } else { "WARN" })

        if ($exists) {
            $props = Get-ItemProperty $key.Path -ErrorAction SilentlyContinue
            if ($props) {
                if ($props.ImagePath) {
                    Write-SubInfo "ImagePath : $($props.ImagePath)"
                }
                if ($null -ne $props.Start) {
                    $startType = switch ($props.Start) {
                        0       { "Boot"      }
                        1       { "System"    }
                        2       { "Automatic" }
                        3       { "Manual"    }
                        4       { "Disabled"  }
                        default { "Unknown($($props.Start))" }
                    }
                    Write-SubInfo "Start     : $startType ($($props.Start))"
                }
                if ($null -ne $props.Type) {
                    Write-SubInfo "Type      : $($props.Type)"
                }
            }
        } else {
            if ($key.Label -ne "Config") {
                Register-Result "WARN" "Chave de registro ausente: $($key.Path)"
            }
        }
    }
    Register-Result "OK"
}

function Show-Scorecard {
    Write-Line ""
    Write-Separator "=" 70 "White"
    Write-Line "  RESULTADO FINAL DO DIAGNOSTICO" "White"
    Write-Separator "=" 70 "White"
    Write-Line ""

    $total = $script:Score.OK + $script:Score.WARN + $script:Score.FAIL
    $pct   = if ($total -gt 0) { [math]::Round($script:Score.OK / $total * 100) } else { 0 }

    Write-Host "    " -NoNewline
    Write-Host (" OK: $($script:Score.OK) ".PadRight(14))     -ForegroundColor Black -BackgroundColor Green  -NoNewline
    Write-Host (" WARN: $($script:Score.WARN) ".PadRight(14)) -ForegroundColor Black -BackgroundColor Yellow -NoNewline
    Write-Host (" FAIL: $($script:Score.FAIL) ".PadRight(14)) -ForegroundColor White -BackgroundColor Red    -NoNewline
    Write-Host (" SAUDE: $pct% ".PadRight(14)) -ForegroundColor Black -BackgroundColor $(
        if ($pct -ge 80) { "Green" } elseif ($pct -ge 50) { "Yellow" } else { "Red" }
    )
    Write-Line ""

    $barLen     = 50
    $okBlocks   = [math]::Round($script:Score.OK   / [math]::Max($total, 1) * $barLen)
    $warnBlocks = [math]::Round($script:Score.WARN / [math]::Max($total, 1) * $barLen)
    $failBlocks = $barLen - $okBlocks - $warnBlocks

    Write-Host "    [" -NoNewline
    Write-Host ("+" * $okBlocks)   -ForegroundColor Green  -NoNewline
    Write-Host ("~" * $warnBlocks) -ForegroundColor Yellow -NoNewline
    Write-Host ("-" * $failBlocks) -ForegroundColor Red    -NoNewline
    Write-Host "]  $pct%"
    Write-Line ""

    $overallStatus = if    ($script:Score.FAIL -gt 0)  { "CRITICO  -- Acao imediata necessaria" }
                     elseif ($script:Score.WARN -gt 0) { "ATENCAO  -- Revisar pontos amarelos"  }
                     else                              { "SAUDAVEL -- Sysmon operacional"        }

    $overallColor = if    ($script:Score.FAIL -gt 0)  { "Red"    }
                    elseif ($script:Score.WARN -gt 0) { "Yellow" }
                    else                              { "Green"  }

    Write-Line "    Status: $overallStatus" $overallColor
    Write-Line ""

    if ($script:Findings.Count -gt 0) {
        Write-Line "    -- Achados e Recomendacoes --" "DarkYellow"
        foreach ($f in $script:Findings) {
            $fColor = if ($f.StartsWith("[FAIL]")) { "Red" } else { "Yellow" }
            Write-Line "    $f" $fColor
        }
        Write-Line ""
    }

    Write-Separator "=" 70 "White"
}

function Export-ReportFile {
    try {
        $header = @(
            "=" * 70,
            " SYSMON HEALTH REPORT -- Check-SysmonHealth.ps1 v$SCRIPT_VERSION",
            " Gerado em : $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')",
            " Host      : $env:COMPUTERNAME",
            " Usuario   : $env:USERNAME",
            " OS        : $((Get-WmiObject Win32_OperatingSystem).Caption)",
            "=" * 70,
            ""
        )
        $header | Out-File $REPORT_PATH -Encoding UTF8
        $script:ReportBuffer | Out-File $REPORT_PATH -Encoding UTF8 -Append
        Write-Line ""
        Write-Line "    [REPORT] Relatorio exportado: $REPORT_PATH" "Green"

        $open = Read-Host "`n    Abrir relatorio no Notepad? (S/N)"
        if ($open -match "^[Ss]") {
            Start-Process notepad.exe $REPORT_PATH
        }
    }
    catch {
        Write-Line "    ERRO ao exportar relatorio: $($_.Exception.Message)" "Red"
    }
}

# =============================================================================
#  MAIN
# =============================================================================
Clear-Host

Write-Line ""
Write-Line "  ================================================================" "Cyan"
Write-Line "  |                                                              |" "Cyan"
Write-Line "  |   CHECK-SYSMONHEALTH  -  Sysmon Native Diagnostic  v$SCRIPT_VERSION    |" "Cyan"
Write-Line "  |         Created by m0us3r - https://github.com/mym0us3r      |" "Cyan"
Write-Line "  ================================================================" "Cyan"
Write-Line ""
Write-Line "  Host      : $env:COMPUTERNAME"                                    "Gray"
Write-Line "  Usuario   : $env:USERNAME"                                        "Gray"
Write-Line "  Data/Hora : $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')"           "Gray"

try {
    $osInfo = Get-WmiObject Win32_OperatingSystem
    Write-Line "  Sistema   : $($osInfo.Caption) (Build $($osInfo.BuildNumber))" "Gray"
}
catch { }

Write-Line "  Janela    : Amostra: $EventSampleCount eventos" "Gray"
Write-Line ""

if (-not (Test-AdminPrivilege)) {
    Write-Line "  [!] ERRO: Execute o script como Administrador!" "Red"
    Write-Line "      Clique direito no PowerShell -> 'Executar como administrador'" "Yellow"
    exit 1
}

Write-Line "  [OK] Executando com privilegios de Administrador" "Green"

Get-SysmonFeatureStatus
Get-SysmonBinaryStatus
Get-SysmonServiceStatus
Get-SysmonDriverStatus
Get-SysmonEventLogStatus
Get-SysmonConfigStatus
Get-SysmonEventSample
Get-RegistryKeys

Show-Scorecard

if ($ExportReport) {
    Export-ReportFile
}

Write-Line "  Diagnostico concluido." "DarkGray"
Write-Line ""
