param(
    [string]$Image = "floating-ip:1.0.2-hardening-test"
)

$ErrorActionPreference = "Stop"
$identifier = [Guid]::NewGuid().ToString("N").Substring(0, 10)
$prefix = "fip-vrrp-$identifier"
$nodeA = "$prefix-a"
$nodeB = "$prefix-b"
$networkName = ""
$tempRoot = [IO.Path]::GetFullPath([IO.Path]::GetTempPath())
$tempPath = [IO.Path]::GetFullPath((Join-Path $tempRoot "floating-ip-vrrp-$identifier"))
if (-not $tempPath.StartsWith($tempRoot, [StringComparison]::OrdinalIgnoreCase) -or
    -not ([IO.Path]::GetFileName($tempPath)).StartsWith("floating-ip-vrrp-")) {
    throw "La ruta temporal del laboratorio no es segura"
}

function Invoke-Docker {
    param([string[]]$DockerArgs, [switch]$AllowFailure)
    $previousPreference = $ErrorActionPreference
    $ErrorActionPreference = "Continue"
    try {
        $output = (& docker @DockerArgs 2>&1 | Out-String).Trim()
        $code = $LASTEXITCODE
    } finally {
        $ErrorActionPreference = $previousPreference
    }
    if ($code -ne 0 -and -not $AllowFailure) {
        $shownArgs = @($DockerArgs | ForEach-Object {
            if ($_.StartsWith("LAB_CONFIG_B64=")) { "LAB_CONFIG_B64=<redacted>" } else { $_ }
        })
        throw "Falló docker $($shownArgs -join ' ')`n$output"
    }
    return $output
}

function Wait-Condition {
    param([string]$Description, [scriptblock]$Check, [int]$Seconds = 35)
    $deadline = [DateTime]::UtcNow.AddSeconds($Seconds)
    while ([DateTime]::UtcNow -lt $deadline) {
        try {
            if (& $Check) { return }
        } catch {
            # El contenedor puede seguir arrancando.
        }
        Start-Sleep -Seconds 1
    }
    throw "Tiempo agotado esperando $Description"
}

function Test-Vip {
    param([string]$Container, [string]$Vip)
    $addresses = Invoke-Docker -DockerArgs @(
        "exec", $Container, "ip", "-4", "-o", "addr", "show", "dev", "eth0"
    ) -AllowFailure
    return $addresses.Contains(" $Vip/")
}

function Test-ExclusiveVip {
    param([string]$Expected, [string]$Vip)
    $a = Test-Vip -Container $nodeA -Vip $Vip
    $b = Test-Vip -Container $nodeB -Vip $Vip
    return (($Expected -eq $nodeA -and $a -and -not $b) -or
            ($Expected -eq $nodeB -and $b -and -not $a))
}

function New-DivergentVridConfig {
    param([byte[]]$Content, [int]$Previous, [int]$New)
    $utf8 = New-Object Text.UTF8Encoding($false, $true)
    $text = $utf8.GetString($Content)
    $pattern = "(?m)^([ \t]*virtual_router_id[ \t]+)$Previous([ \t]*(?:#[^\r\n]*)?\r?)$"
    $regex = [regex]::new($pattern)
    $matches = $regex.Matches($text)
    if ($matches.Count -ne 1) {
        throw "Se esperaba una directiva virtual_router_id $Previous; se encontraron $($matches.Count)"
    }
    $changed = $regex.Replace($text, {
        param($match)
        return $match.Groups[1].Value + $New + $match.Groups[2].Value
    }, 1)
    return ,$utf8.GetBytes($changed)
}

function Test-ExactBytes {
    param([byte[]]$Left, [byte[]]$Right)
    return [Collections.StructuralComparisons]::StructuralEqualityComparer.Equals($Left, $Right)
}

function Set-AtomicKeepalivedConfig {
    param([string]$Container, [byte[]]$Content)
    $encoded = [Convert]::ToBase64String($Content)
    $code = @'
import base64
import os
import stat
import tempfile

ruta = "/datos/keepalived.conf"
contenido = base64.b64decode(os.environ.pop("LAB_CONFIG_B64"), validate=True)
estado = os.lstat(ruta)
if not stat.S_ISREG(estado.st_mode) or stat.S_ISLNK(estado.st_mode):
    raise RuntimeError("keepalived.conf no es un fichero regular")
modo = stat.S_IMODE(estado.st_mode)
descriptor, temporal = tempfile.mkstemp(prefix=".keepalived.conf.", dir="/datos")
try:
    os.fchmod(descriptor, modo)
    with os.fdopen(descriptor, "wb") as fichero:
        descriptor = -1
        fichero.write(contenido)
        fichero.flush()
        os.fsync(fichero.fileno())
    os.replace(temporal, ruta)
    temporal = ""
    descriptor_directorio = os.open("/datos", os.O_RDONLY | os.O_DIRECTORY)
    try:
        os.fsync(descriptor_directorio)
    finally:
        os.close(descriptor_directorio)
    estado_final = os.lstat(ruta)
    if not stat.S_ISREG(estado_final.st_mode) or estado_final.st_mode & 0o111:
        raise RuntimeError("keepalived.conf quedo ejecutable o dejo de ser regular")
    with open(ruta, "rb") as fichero:
        if fichero.read() != contenido:
            raise RuntimeError("keepalived.conf no coincide byte a byte")
finally:
    if descriptor >= 0:
        os.close(descriptor)
    if temporal:
        try:
            os.unlink(temporal)
        except FileNotFoundError:
            pass
'@
    $encodedCode = [Convert]::ToBase64String([Text.Encoding]::UTF8.GetBytes($code))
    $launcher = "import base64;exec(base64.b64decode('$encodedCode'))"
    Invoke-Docker -DockerArgs @(
        "exec", "--env", "LAB_CONFIG_B64=$encoded", $Container,
        "python3", "-c", $launcher
    ) | Out-Null
}

function Invoke-KeepalivedReload {
    param([string]$Container)
    Invoke-Docker -DockerArgs @("kill", "--signal", "HUP", $Container) | Out-Null
}

function Test-DashboardCarriers {
    param(
        [string]$Container, [string]$Vip, [string[]]$Expected,
        [bool]$Duplicate
    )
    $code = "import json,sys;sys.path.insert(0,'/opt/panel');import servidor;d=json.load(open('/datos/pool.json',encoding='utf-8'));print(json.dumps(servidor.cuadro(d),sort_keys=True,separators=(',',':')))"
    $raw = Invoke-Docker -DockerArgs @(
        "exec", $Container, "python3", "-c", $code
    )
    $dashboard = $raw | ConvertFrom-Json
    $rows = @($dashboard.direcciones | Where-Object { $_.ip -eq $Vip })
    if ($rows.Count -ne 1 -or [bool]$rows[0].duplicada -ne $Duplicate) {
        return $false
    }
    $actual = @($rows[0].portadores | ForEach-Object { [string]$_ } | Sort-Object)
    $wanted = @($Expected | Sort-Object)
    return @(Compare-Object -ReferenceObject $wanted -DifferenceObject $actual).Count -eq 0
}

function New-Base64UrlSecret {
    $bytes = New-Object byte[] 48
    $generator = [Security.Cryptography.RandomNumberGenerator]::Create()
    try {
        $generator.GetBytes($bytes)
    } finally {
        $generator.Dispose()
    }
    return ([Convert]::ToBase64String($bytes)).Replace("+", "-").Replace("/", "_").TrimEnd("=")
}

function New-InitialConfig {
    param([string]$DataPath, [string]$SecretPath, [string]$Node, [string]$NodeTable)
    $code = "import json,sys;sys.path.insert(0,'/opt/panel');import local,plan;d=json.load(open('/datos/pool.json',encoding='utf-8'));open('/datos/keepalived.conf','w',encoding='utf-8').write(plan.generar_conf(d,local.YO,local.NODOS,retardo=2))"
    Invoke-Docker -DockerArgs @(
        "run", "--rm", "--entrypoint", "python3",
        "--mount", "type=bind,source=$DataPath,target=/datos",
        "--mount", "type=bind,source=$SecretPath,target=/run/secrets/fip_vrrp_auth,readonly",
        "--env", "FIP_NODO=$Node", "--env", "FIP_NODOS=$NodeTable",
        "--env", "FIP_VIP_PREFIX=24",
        "--env", "FIP_VRRP_AUTH_PASS_FILE=/run/secrets/fip_vrrp_auth",
        $Image, "-c", $code
    ) | Out-Null
}

function Start-LabNode {
    param(
        [string]$Name, [string]$Ip, [string]$Peer, [string]$DataPath,
        [string]$SecretsPath, [string]$Node, [string]$NodeTable
    )
    Invoke-Docker -DockerArgs @(
        "run", "--detach", "--name", $Name, "--network", $networkName, "--ip", $Ip,
        "--init", "--read-only", "--pids-limit", "256", "--cap-drop", "ALL",
        "--cap-add", "NET_ADMIN", "--cap-add", "NET_BROADCAST", "--cap-add", "NET_RAW",
        "--cap-add", "SETGID",
        "--security-opt", "no-new-privileges:true",
        "--tmpfs", "/run:rw,nosuid,noexec,size=32m",
        "--tmpfs", "/tmp:rw,nosuid,noexec,size=32m",
        "--mount", "type=bind,source=$DataPath,target=/datos",
        "--mount", "type=bind,source=$(Join-Path $SecretsPath 'vrrp-auth.txt'),target=/run/secrets/fip_vrrp_auth,readonly",
        "--mount", "type=bind,source=$(Join-Path $SecretsPath 'session-secret.txt'),target=/run/secrets/fip_session_secret,readonly",
        "--mount", "type=bind,source=$(Join-Path $SecretsPath 'cluster-token.txt'),target=/run/secrets/fip_cluster_token,readonly",
        "--env", "FIP_APP_VERSION=1.0.2", "--env", "FIP_NODO=$Node",
        "--env", "FIP_NODOS=$NodeTable", "--env", "FIP_PARES=http://${Peer}:6060",
        "--env", "FIP_PUERTO=6060", "--env", "FIP_VIP_PREFIX=24",
        "--env", "FIP_DATOS=/datos", "--env", "FIP_CONF=/datos/keepalived.conf",
        "--env", "FIP_RETARDO=2",
        "--env", "FIP_VRRP_AUTH_PASS_FILE=/run/secrets/fip_vrrp_auth",
        "--env", "FIP_SESSION_SECRET_FILE=/run/secrets/fip_session_secret",
        "--env", "FIP_CLUSTER_TOKEN_FILE=/run/secrets/fip_cluster_token",
        $Image
    ) | Out-Null
}

try {
    [IO.Directory]::CreateDirectory($tempPath) | Out-Null
    $secretsPath = Join-Path $tempPath "secrets"
    $dataA = Join-Path $tempPath "data-a"
    $dataB = Join-Path $tempPath "data-b"
    foreach ($path in @($secretsPath, $dataA, $dataB)) {
        [IO.Directory]::CreateDirectory($path) | Out-Null
    }

    $subnet = $null
    foreach ($octet in 247..220) {
        $candidate = "172.31.$octet.0/24"
        $candidateName = "$prefix-net"
        Invoke-Docker -DockerArgs @(
            "network", "create", "--driver", "bridge", "--subnet", $candidate, $candidateName
        ) -AllowFailure | Out-Null
        if ($LASTEXITCODE -eq 0) {
            $networkName = $candidateName
            $subnet = "172.31.$octet"
            break
        }
    }
    if (-not $networkName) { throw "No se encontró una subred /24 libre" }

    $ipA = "$subnet.10"
    $ipB = "$subnet.11"
    $vip = "$subnet.100"
    $nodeTable = "node-a:${ipA}:eth0:150,node-b:${ipB}:eth0:100"

    [IO.File]::WriteAllText((Join-Path $secretsPath "vrrp-auth.txt"), "LabVRRP7`n")
    [IO.File]::WriteAllText((Join-Path $secretsPath "session-secret.txt"),
        ((New-Base64UrlSecret) + "`n"))
    [IO.File]::WriteAllText((Join-Path $secretsPath "cluster-token.txt"),
        ((New-Base64UrlSecret) + "`n"))

    $now = [DateTime]::UtcNow.ToString("yyyy-MM-ddTHH:mm:ssZ")
    $pool = [ordered]@{
        version = 1; actualizado = $now; dhcp_desde = 200; mantenimiento = @()
        direcciones = @([ordered]@{
            ip = $vip; vrid = 77; estado = "en_uso"; servicio = "panel"
            descripcion = "Servicio sano del laboratorio VRRP"; puertos = @(6060)
            chequeo = [ordered]@{ puerto = 6060; ruta = "/api/health" }
            preferente = "node-a"; notas = "dato efímero de prueba"; creada = $now
        })
        reclamaciones = [ordered]@{}
    }
    $poolJson = ($pool | ConvertTo-Json -Depth 8) + "`n"
    [IO.File]::WriteAllText((Join-Path $dataA "pool.json"), $poolJson)
    [IO.File]::WriteAllText((Join-Path $dataB "pool.json"), $poolJson)

    New-InitialConfig -DataPath $dataA -SecretPath (Join-Path $secretsPath "vrrp-auth.txt") -Node "node-a" -NodeTable $nodeTable
    New-InitialConfig -DataPath $dataB -SecretPath (Join-Path $secretsPath "vrrp-auth.txt") -Node "node-b" -NodeTable $nodeTable
    Start-LabNode -Name $nodeA -Ip $ipA -Peer $ipB -DataPath $dataA -SecretsPath $secretsPath -Node "node-a" -NodeTable $nodeTable
    Start-LabNode -Name $nodeB -Ip $ipB -Peer $ipA -DataPath $dataB -SecretsPath $secretsPath -Node "node-b" -NodeTable $nodeTable

    foreach ($container in @($nodeA, $nodeB)) {
        Wait-Condition -Description "salud HTTP de $container" -Check {
            $health = Invoke-Docker -DockerArgs @(
                "exec", $container, "curl", "--fail", "--silent", "http://127.0.0.1:6060/api/health"
            ) -AllowFailure
            return $health.StartsWith("{")
        }
        $processes = Invoke-Docker -DockerArgs @(
            "exec", $container, "sh", "-c",
            "pgrep -x keepalived >/dev/null && pgrep -f '/opt/panel/servidor.py' >/dev/null && echo ok"
        )
        if ($processes -ne "ok") { throw "Faltan procesos en $container" }
    }

    Wait-Condition -Description "VIP exclusiva en node-a" -Check {
        Test-ExclusiveVip -Expected $nodeA -Vip $vip
    }
    Write-Output "VIP_INITIAL_OK=$vip@node-a"

    Invoke-Docker -DockerArgs @("exec", $nodeA, "sh", "-c", "touch /run/floating-ip/drenar/panel") | Out-Null
    Wait-Condition -Description "traspaso por drenaje a node-b" -Check {
        Test-ExclusiveVip -Expected $nodeB -Vip $vip
    }
    Write-Output "VIP_DRAIN_FAILOVER_OK=node-b"

    Invoke-Docker -DockerArgs @("exec", $nodeA, "sh", "-c", "rm /run/floating-ip/drenar/panel") | Out-Null
    Wait-Condition -Description "recuperación preemptiva en node-a" -Check {
        Test-ExclusiveVip -Expected $nodeA -Vip $vip
    }
    Write-Output "VIP_PREEMPT_RECOVERY_OK=node-a"

    $configB = Join-Path $dataB "keepalived.conf"
    [byte[]]$originalConfigB = [IO.File]::ReadAllBytes($configB)
    [byte[]]$divergentConfigB = New-DivergentVridConfig `
        -Content $originalConfigB -Previous 77 -New 78
    $mutationAttempted = $false
    try {
        $mutationAttempted = $true
        Set-AtomicKeepalivedConfig -Container $nodeB -Content $divergentConfigB
        if (-not (Test-ExactBytes -Left ([IO.File]::ReadAllBytes($configB)) -Right $divergentConfigB)) {
            throw "La configuracion divergente no quedo escrita byte a byte"
        }
        Invoke-KeepalivedReload -Container $nodeB
        Wait-Condition -Description "split-brain real con la VIP en ambos nodos" -Check {
            (Test-Vip -Container $nodeA -Vip $vip) -and
                (Test-Vip -Container $nodeB -Vip $vip)
        }
        Wait-Condition -Description "deteccion de split-brain por servidor.cuadro" -Check {
            Test-DashboardCarriers -Container $nodeA -Vip $vip `
                -Expected @("node-a", "node-b") -Duplicate $true
        }
        Write-Output "VIP_SPLIT_BRAIN_DETECTED_OK=node-a,node-b"
    } finally {
        if ($mutationAttempted) {
            Set-AtomicKeepalivedConfig -Container $nodeB -Content $originalConfigB
            if (-not (Test-ExactBytes -Left ([IO.File]::ReadAllBytes($configB)) -Right $originalConfigB)) {
                throw "No se restauraron los bytes exactos de keepalived.conf"
            }
            Invoke-KeepalivedReload -Container $nodeB
            Wait-Condition -Description "recuperacion exclusiva tras restaurar el VRID" -Check {
                Test-ExclusiveVip -Expected $nodeA -Vip $vip
            }
            Wait-Condition -Description "cuadro sano tras restaurar el VRID" -Check {
                Test-DashboardCarriers -Container $nodeA -Vip $vip `
                    -Expected @("node-a") -Duplicate $false
            }
            if (-not (Test-ExactBytes -Left ([IO.File]::ReadAllBytes($configB)) -Right $originalConfigB)) {
                throw "keepalived.conf cambio despues de la recuperacion"
            }
            Write-Output "VIP_SPLIT_BRAIN_RECOVERY_OK=node-a"
        }
    }

    Invoke-Docker -DockerArgs @("stop", "--time", "5", $nodeA) | Out-Null
    Wait-Condition -Description "traspaso tras caída de node-a" -Check {
        Test-Vip -Container $nodeB -Vip $vip
    }
    Write-Output "VIP_NODE_FAILURE_OK=node-b"
    Write-Output "SECURE_VRRP_LAB_OK"
} catch {
    foreach ($container in @($nodeA, $nodeB)) {
        $logs = Invoke-Docker -DockerArgs @("logs", "--tail", "80", $container) -AllowFailure
        if ($logs -and -not $logs.Contains("No such container")) { Write-Warning "$container`n$logs" }
    }
    throw
} finally {
    foreach ($container in @($nodeA, $nodeB)) {
        Invoke-Docker -DockerArgs @("rm", "--force", $container) -AllowFailure | Out-Null
    }
    if ($networkName -eq "$prefix-net") {
        Invoke-Docker -DockerArgs @("network", "rm", $networkName) -AllowFailure | Out-Null
    }
    if ((Test-Path -LiteralPath $tempPath) -and
        $tempPath.StartsWith($tempRoot, [StringComparison]::OrdinalIgnoreCase) -and
        ([IO.Path]::GetFileName($tempPath)).StartsWith("floating-ip-vrrp-")) {
        Remove-Item -LiteralPath $tempPath -Recurse -Force
    }
}
