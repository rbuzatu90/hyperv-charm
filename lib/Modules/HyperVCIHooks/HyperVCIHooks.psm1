#
# Copyright 2015-2016 Cloudbase Solutions Srl
#

$ErrorActionPreference = 'Stop'

Import-Module JujuUtils
Import-Module JujuHooks
Import-Module JujuLogging
Import-Module JujuHelper
Import-Module JujuWindowsUtils
Import-Module ADCharmUtils

$NEUTRON_GIT           = "https://github.com/openstack/neutron.git"
$NOVA_GIT              = "https://github.com/openstack/nova.git"
$NETWORKING_HYPERV_GIT = "https://github.com/openstack/networking-hyperv.git"
$COMPUTE_HYPERV_GIT    = "https://github.com/openstack/compute-hyperv.git"

$OPENSTACK_DIR  = Join-Path $env:SystemDrive "OpenStack"
$PYTHON_DIR     = Join-Path $env:SystemDrive "Python27"
$LIB_DIR        = Join-Path $PYTHON_DIR "lib\site-packages"
$BUILD_DIR      = Join-Path $OPENSTACK_DIR "build"
$INSTANCES_DIR  = Join-Path $OPENSTACK_DIR "Instances"
$BIN_DIR        = Join-Path $OPENSTACK_DIR "bin"
$CONFIG_DIR     = Join-Path $OPENSTACK_DIR "etc"
$LOG_DIR        = Join-Path $OPENSTACK_DIR "log"
$SERVICE_DIR    = Join-Path $OPENSTACK_DIR "service"
$FILES_DIR      = Join-Path ${env:CHARM_DIR} "files"
$OVS_DIR        = "${env:ProgramFiles}\Cloudbase Solutions\Open vSwitch"
$OVS_VSCTL      = Join-Path $OVS_DIR "bin\ovs-vsctl.exe"
$env:OVS_RUNDIR = Join-Path $env:ProgramData "openvswitch"
$OVS_EXT_NAME   = "Open vSwitch Extension"

function Get-TemplatesDir {
    return (Join-Path (Get-JujuCharmDir) "templates")
}


function Get-DevStackContext {
    $requiredCtx =  @{
        "devstack_ip" = $null;
        "password"    = $null;
        "rabbit_user" = $null;
    }
    $ctx = Get-JujuRelationContext -Relation 'devstack' -RequiredContext $requiredCtx

    # Required context not found
    if(!$ctx.Count) {
        return @{}
    }

    return $ctx
}


function Get-SystemContext {
    $systemCtxt = @{
        "instances_path"      = Join-Path $OPENSTACK_DIR "Instances";
        "interfaces_template" = Join-Path $CONFIG_DIR "interfaces.template";
        "policy_file"         = Join-Path $CONFIG_DIR "policy.json";
        "mkisofs_exe"         = Join-Path $BIN_DIR "mkisofs.exe";
        "log_directory"       = $LOG_DIR;
        "qemu_img_exe"        = Join-Path $BIN_DIR "qemu-img.exe";
        "vswitch_name"        = Get-JujuVMSwitchName
        "local_ip"            = (Get-CharmState -Namespace "novahyperv" -Key "local_ip");
        "etc_directory"       = $CONFIG_DIR;
        "bin_directory"       = $BIN_DIR;
    }
    return $systemCtxt
}


function Get-CharmServices {
    $services = @{
        'nova' = @{
            'description'  = "OpenStack nova Compute Service";
            'binary' = Join-Path $PYTHON_DIR "Scripts\nova-compute.exe";
            'config' = Join-Path $CONFIG_DIR "nova.conf";
            'template' = Join-Path (Get-TemplatesDir) "nova.conf";
            'service_name' = 'nova-compute';
            "context_generators" = @(
                @{
                    "generator" = "Get-DevStackContext";
                    "relation"  = "devstack";
                },
                @{
                    "generator" = "Get-SystemContext";
                    "relation"  = "system";
                }
            );
        };
        'neutron' = @{
            'description' = "OpenStack Neutron Hyper-V Agent Service";
            'binary' = (Join-Path $PYTHON_DIR "Scripts\neutron-hyperv-agent.exe");
            'config' = (Join-Path $CONFIG_DIR "neutron_hyperv_agent.conf");
            'template' = Join-Path (Get-TemplatesDir) "neutron_hyperv_agent.conf";
            'service_name' = "neutron-hyperv-agent";
            "context_generators" = @(
                @{
                    "generator" = "Get-DevStackContext";
                    "relation"  = "devstack";
                },
                @{
                    "generator" = "Get-SystemContext";
                    "relation"  = "system";
                }
            );
        };
        'neutron-ovs' = @{
            'description' = "OpenStack Neutron Open vSwitch Agent Service";
            'binary' = (Join-Path $PYTHON_DIR "Scripts\neutron-openvswitch-agent.exe");
            'config' = (Join-Path $CONFIG_DIR "ml2_conf.ini");
            'template' = Join-Path (Get-TemplatesDir) "ml2_conf.ini";
            'service_name' = "neutron-openvswitch-agent";
            "context_generators" = @(
                @{
                    "generator" = "Get-DevStackContext";
                    "relation"  = "devstack";
                },
                @{
                    "generator" = "Get-SystemContext";
                    "relation"  = "system";
                }
            );
        }
    }
    return $services
}


function Write-ConfigFile {
    param (
        [Parameter(Mandatory=$true)]
        [string]$ServiceName
    )
    $JujuCharmServices = Get-CharmServices
    $should_restart = $true
    $service = $JujuCharmServices[$ServiceName]
    if (!$service){
        Write-JujuWarning "No such service $ServiceName. Not generating config"
        return $false
    }
    $config = gc $service["template"]
    # populate config with variables from context
    
    $incompleteContexts = [System.Collections.Generic.List[object]](New-Object "System.Collections.Generic.List[object]")
    $allContexts = [System.Collections.Generic.List[object]](New-Object "System.Collections.Generic.List[object]")

    foreach ($context in $service['context_generators']){
        Write-JujuInfo ("Getting context for {0}" -f $context["relation"])
        $allContexts.Add($context["relation"])
        $ctx = & $context["generator"]
        Write-JujuInfo ("Got {0} context: {1}" -f @($context["relation"], $ctx.Keys))
        if (!$ctx.Count){
            # Context is empty. Probably peer not ready
            Write-JujuWarning "Context for $context is EMPTY"
            $incompleteContexts.Add($context["relation"])
            $should_restart = $false
            continue
        }
        foreach ($val in $ctx.GetEnumerator()) {
            $regex = "{{[\s]{0,}" + $val.Name + "[\s]{0,}}}"
            $config = $config -Replace $regex,$val.Value
        }
    }
    Set-IncompleteStatusContext -ContextSet $allContexts -Incomplete $incompleteContexts
    # Any variables not available in context we remove
    $config = $config -Replace "{{[\s]{0,}[a-zA-Z0-9_-]{0,}[\s]{0,}}}",""
    Set-Content $service["config"] $config
    # Restart-Service $service["service"]
    return $should_restart
}


function Set-IncompleteStatusContext {
    Param(
        [array]$ContextSet=@(),
        [array]$Incomplete=@()
    )
    $status = Get-JujuStatus -Full
    $currentIncomplete = @()
    if($status["message"]){
        $msg = $status["message"].Split(":")
        if($msg.Count -ne 2){
            return
        }
        if($msg[0] -eq "Incomplete contexts") {
            $currentIncomplete = $msg[1].Split(", ")
        }
    }
    $newIncomplete = [System.Collections.Generic.List[object]](New-Object "System.Collections.Generic.List[object]")
    if(!$Incomplete){
        foreach($i in $currentIncomplete) {
            if ($i -in $ContextSet){
                continue
            }
            $newIncomplete.Add($i)
        }
    } else {
        foreach($i in $currentIncomplete) {
            if($i -in $ContextSet -and !($i -in $Incomplete)){
                continue
            } else {
                $newIncomplete.Add($i)
            }
        }
        foreach($i in $Incomplete) {
            if ($i -in $newIncomplete) {
                continue
            }
            $newIncomplete.Add($i)
        }
    }
    if($newIncomplete){
        $msg = "Incomplete contexts: {0}" -f ($newIncomplete -Join ", ")
        Set-JujuStatus -Status blocked -Message $msg
    } else {
        Set-JujuStatus -Status waiting -Message "Contexts are complete"
    }
}


# Returns an HashTable with the download URL, the checksum (with the hashing
# algorithm) for a specific package. The URL config option for that package
# is parsed. In case the checksum is not specified, 'CHECKSUM' and
# 'HASHING_ALGORITHM' fields will be $null.
function Get-URLChecksum {
    Param(
        [string]$URLConfigKey
    )

    $url = Get-JujuCharmConfig -Scope $URLConfigKey
    if ($url.contains('#')) {
        $urlSplit = $url.split('#')
        $algorithm = $urlSplit[1]
        if (!$algorithm.contains('=')) {
            Throw ("Invalid algorithm format! " +
                   "Use the format: <hashing_algorithm>=<checksum>")
        }

        $validHashingAlgorithms = @('SHA1', 'SHA256', 'SHA384', 'SHA512',
                                    'MACTripleDES', 'MD5', 'RIPEMD160')
        $algorithmSplit = $algorithm.split('=')
        $hashingAlgorithm = $algorithmSplit[0]
        if ($hashingAlgorithm -notin $validHashingAlgorithms) {
            Throw ("Invalid hashing algorithm format! " +
                   "Valid formats are: " + $validHashingAlgorithms)
        }

        $checksum = $algorithmSplit[1]
        return @{ 'URL' = $urlSplit[0];
                  'CHECKSUM' = $checksum;
                  'HASHING_ALGORITHM' = $hashingAlgorithm }
    }

    return @{ 'URL' = $url;
              'CHECKSUM' = $null;
              'HASHING_ALGORITHM' = $null }
}


function Start-DownloadFile {
    Param(
        [Parameter(Mandatory=$True)]
        [System.Uri]$Uri,
        [string]$OutFile,
        [switch]$SkipIntegrityCheck=$false
    )

    if(!$OutFile) {
        $OutFile = $Uri.PathAndQuery.Substring($Uri.PathAndQuery.LastIndexOf("/") + 1)
        if(!$OutFile) {
            throw "The ""OutFile"" parameter needs to be specified"
        }
    }

    $webClient = New-Object System.Net.WebClient
    Start-ExecuteWithRetry { $webClient.DownloadFile($Uri, $OutFile) }

    if(!$SkipIntegrityCheck) {
        $fragment = $Uri.Fragment.Trim('#')
        if (!$fragment){
            return
        }
        $details = $fragment.Split("=")
        $algorithm = $details[0]
        $hash = $details[1]
        if($algorithm -in @("SHA1", "SHA256", "SHA384", "SHA512", "MACTripleDES", "MD5", "RIPEMD160")){
            Test-FileIntegrity -File $OutFile -Algorithm $algorithm -ExpectedHash $hash
        } else {
            Throw "Hash algorithm $algorithm not recognized."
        }
    }
}


# Returns the full path of the package after it is downloaded using
# the URL parameter (a checksum may optionally be specified). The
# package is cached on the disk until the installation successfully finishes.
# If the hook fails, on the second run this function will return the cached
# package path if checksum is given and it matches.
function Get-PackagePath {
    Param(
        [Parameter(Mandatory=$True)]
        [string]$URL,
        [string]$Checksum="",
        [string]$HashingAlgorithm=""
    )

    $packagePath = Join-Path $env:TEMP $URL.Split('/')[-1]
    if (Test-Path $packagePath) {
        if ($Checksum -and $HashingAlgorithm) {
            if (Test-FileIntegrity -File $packagePath -Algorithm $HashingAlgorithm -ExpectedHash $Checksum) {
                return $packagePath
            }
        }
        Remove-Item -Recurse -Force -Path $packagePath
    }

    if ($Checksum -and $HashingAlgorithm) {
        Start-DownloadFile -Uri "$URL#$HashingAlgorithm=$Checksum" -OutFile $packagePath
    } else {
        Start-DownloadFile -Uri $URL -OutFile $packagePath -SkipIntegrityCheck
    }

    return $packagePath
}


# Installs a package after it is downloaded from the Internet and checked for
# integrity with SHA1 checksum. Accepts as parameters: an URL, an optional
# 'Checksum' with its 'HashingAlgorithm' and 'ArgumentList' which can be passed
# if the installer requires unattended installation.
# Supported packages formats are: '.exe' and '.msi'
function Install-Package {
    Param(
        [string]$URL,
        [string]$Checksum="",
        [string]$HashingAlgorithm="",
        [array]$ArgumentList
    )

    Write-JujuLog "Installing package '$URL'"

    $packageFormat = $URL.Split('.')[-1]
    $acceptedFormats = @('msi', 'exe')
    if ($packageFormat -notin $acceptedFormats) {
        Throw ("Cannot install the package found at this URL: $URL " +
               "Unsupported installer format.")
    }

    $installerPath = Get-PackagePath $URL $Checksum $HashingAlgorithm
    $stat = Start-Process -FilePath $installerPath -ArgumentList $ArgumentList `
                          -PassThru -Wait
    if ($stat.ExitCode -ne 0) {
        throw "Package '$URL' failed to install."
    }
    Remove-Item $installerPath

    Write-JujuLog "Finished installing package."
}


function Start-GitClonePull {
    Param(
        [string]$Path,
        [string]$URL,
        [string]$Branch="master"
    )

    if (!(Test-Path -Path $Path)) {
        Start-ExecuteWithRetry {
            Start-ExternalCommand -ScriptBlock { git clone $URL $Path } `
                                  -ErrorMessage "Git clone failed"
        }
        Start-ExternalCommand -ScriptBlock { git checkout $Branch } `
                              -ErrorMessage "Git checkout failed"
    } else {
        pushd $Path
        try {
            $gitPath = Join-Path $Path ".git"
            if (!(Test-Path -Path $gitPath)) {
                Remove-Item -Recurse -Force *
                Start-ExecuteWithRetry {
                    Start-ExternalCommand -ScriptBlock { git clone $URL $Path } `
                                          -ErrorMessage "Git clone failed"
                }
            } else {
                Start-ExecuteWithRetry {
                    Start-ExternalCommand -ScriptBlock { git fetch --all } `
                                          -ErrorMessage "Git fetch failed"
                }
            }
            Start-ExecuteWithRetry {
                Start-ExternalCommand -ScriptBlock { git checkout $Branch } `
                                      -ErrorMessage "Git checkout failed"
            }
            Get-ChildItem . -Include *.pyc -Recurse | foreach ($_) { Remove-Item $_.fullname }
            Start-ExternalCommand -ScriptBlock { git reset --hard } `
                                  -ErrorMessage "Git reset failed"
            Start-ExternalCommand -ScriptBlock { git clean -f -d } `
                                  -ErrorMessage "Git clean failed"
            Start-ExecuteWithRetry {
                Start-ExternalCommand -ScriptBlock { git pull } `
                                      -ErrorMessage "Git pull failed"
            }
        } finally {
            popd
        }
    }
}


function Install-OpenStackProjectFromRepo {
    Param(
        [string]$ProjectPath
    )

    Start-ExternalCommand -ScriptBlock { pip install -e $ProjectPath } `
                          -ErrorMessage "Failed to install $ProjectPath from repo."
}


function Start-GerritGitPrep {
    Param(
        [Parameter(Mandatory=$True)]
        [string]$ZuulUrl,
        [Parameter(Mandatory=$True)]
        [string]$GerritSite,
        [Parameter(Mandatory=$True)]
        [string]$ZuulRef,
        [Parameter(Mandatory=$True)]
        [string]$ZuulChange,
        [Parameter(Mandatory=$True)]
        [string]$ZuulProject,
        [string]$GitOrigin,
        [string]$ZuulNewrev
    )

    if (!$ZuulRef -or !$ZuulChange -or !$ZuulProject) {
        Throw "ZUUL_REF ZUUL_CHANGE ZUUL_PROJECT are mandatory"
    }
    if (!$ZuulUrl) {
        Throw "The zuul site name (eg 'http://zuul.openstack.org/p') must be the first argument."
    }
    if (!$GerritSite) {
        Throw "The gerrit site name (eg 'https://review.openstack.org') must be the second argument."
    }
    if (!$GitOrigin -or !$ZuulNewrev) {
        $GitOrigin="$GerritSite/p"
    }

    Write-JujuLog "Triggered by: $GerritSite/$ZuulChange"

    if (!(Test-Path -Path $BUILD_DIR -PathType Container)) {
        mkdir $BUILD_DIR
    }

    $projectDir = Join-Path $BUILD_DIR $ZuulProject
    if (!(Test-Path -Path $projectDir -PathType Container)) {
        mkdir $projectDir
        try {
            Start-ExternalCommand -ScriptBlock { git clone "$GitOrigin/$ZuulProject" $projectDir } `
                                  -ErrorMessage "Failed to clone $GitOrigin/$ZuulProject"
        } catch {
            rm -Recurse -Force $projectDir
            Throw $_
        }
    }

    pushd $projectDir

    Start-ExternalCommand { git remote set-url origin "$GitOrigin/$ZuulProject" } `
        -ErrorMessage "Failed to set origin: $GitOrigin/$ZuulProject"

    try {
        Start-ExternalCommand { git remote update } -ErrorMessage "Failed to update remote"
    } catch {
        Write-JujuLog "The remote update failed, so garbage collecting before trying again."
        Start-ExternalCommand { git gc } -ErrorMessage "Failed to run git gc."
        Start-ExternalCommand { git remote update } -ErrorMessage "Failed to update remote"
    }

    Start-ExternalCommand { git reset --hard } -ErrorMessage "Failed to git reset"
    try {
        Start-ExternalCommand { git clean -x -f -d -q } -ErrorMessage "Failed to git clean"
    } catch {
        sleep 1
        Start-ExternalCommand { git clean -x -f -d -q } -ErrorMessage "Failed to git clean"
    }

    echo "Before doing git checkout:"
    echo "Git branch output:"
    Start-ExternalCommand { git branch } -ErrorMessage "Failed to show git branch."
    echo "Git log output:"
    Start-ExternalCommand { git log -10 --pretty=format:"%h - %an, %ae, %ar : %s" } `
        -ErrorMessage "Failed to show git log."

    $ret = echo "$ZuulRef" | Where-Object { $_ -match "^refs/tags/" }
    if ($ret) {
        Start-ExternalCommand { git fetch --tags "$ZuulUrl/$ZuulProject" } `
            -ErrorMessage "Failed to fetch tags from: $ZuulUrl/$ZuulProject"
        Start-ExternalCommand { git checkout $ZuulRef } `
            -ErrorMessage "Failed to fetch tags to: $ZuulRef"
        Start-ExternalCommand { git reset --hard $ZuulRef } `
            -ErrorMessage "Failed to hard reset to: $ZuulRef"
    } elseif (!$ZuulNewrev) {
        Start-ExternalCommand { git fetch "$ZuulUrl/$ZuulProject" $ZuulRef } `
            -ErrorMessage "Failed to fetch: $ZuulUrl/$ZuulProject $ZuulRef"
        Start-ExternalCommand { git checkout FETCH_HEAD } `
            -ErrorMessage "Failed to checkout FETCH_HEAD"
        Start-ExternalCommand { git reset --hard FETCH_HEAD } `
            -ErrorMessage "Failed to hard reset FETCH_HEAD"
    } else {
        Start-ExternalCommand { git checkout $ZuulNewrev } `
            -ErrorMessage "Failed to checkout $ZuulNewrev"
        Start-ExternalCommand { git reset --hard $ZuulNewrev } `
            -ErrorMessage "Failed to hard reset $ZuulNewrev"
    }

    try {
        Start-ExternalCommand { git clean -x -f -d -q } -ErrorMessage "Failed to git clean"
    } catch {
        sleep 1
        Start-ExternalCommand { git clean -x -f -d -q } -ErrorMessage "Failed to git clean"
    }

    if (Test-Path .gitmodules) {
        Start-ExternalCommand { git submodule init } -ErrorMessage "Failed to init submodule"
        Start-ExternalCommand { git submodule sync } -ErrorMessage "Failed to sync submodule"
        Start-ExternalCommand { git submodule update --init } -ErrorMessage "Failed to update submodule"
    }

    echo "Final result:"
    echo "Git branch output:"
    Start-ExternalCommand { git branch } -ErrorMessage "Failed to show git branch."
    echo "Git log output:"
    Start-ExternalCommand { git log -10 --pretty=format:"%h - %an, %ae, %ar : %s" } `
        -ErrorMessage "Failed to show git log."

    popd
}


function Install-Nova {
    Write-JujuLog "Installing nova"

    $openstackBuild = Join-Path $BUILD_DIR "openstack"
    Start-ExecuteWithRetry {
        Install-OpenStackProjectFromRepo "$openstackBuild\nova"
    }
    $novaBin = (Get-CharmServices)['nova']['binary']
    if (!(Test-Path $novaBin)) {
        Throw "$novaBin was not found."
    }

    Write-JujuLog "Copying default config files"
    $defaultConfigFiles = @('rootwrap.d', 'api-paste.ini', 'cells.json',
                            'policy.json','rootwrap.conf')
    foreach ($config in $defaultConfigFiles) {
        Copy-Item -Recurse -Force "$openstackBuild\nova\etc\nova\$config" $CONFIG_DIR
    }
    Copy-Item -Force (Join-Path (Get-TemplatesDir) "interfaces.template") $CONFIG_DIR
}

function Install-ComputeHyperV {
    Write-JujuLog "Installing compute-hyperv"

    $openstackBuild = Join-Path $BUILD_DIR "openstack"
    Start-ExecuteWithRetry {
        Install-OpenStackProjectFromRepo "$openstackBuild\compute-hyperv"
    }
}

function Install-Neutron {
    Write-JujuLog "Installing neutron"

    $openstackBuild = Join-Path $BUILD_DIR "openstack"
    Start-ExecuteWithRetry {
        Install-OpenStackProjectFromRepo "$openstackBuild\neutron"
    }
}


function Install-NetworkingHyperV {
    Write-JujuLog "Installing networking-hyperv"

    $openstackBuild = Join-Path $BUILD_DIR "openstack"
    Start-ExecuteWithRetry {
        Install-OpenStackProjectFromRepo "$openstackBuild\networking-hyperv"
    }
    $neutronBin = (Get-CharmServices)['neutron']['binary']
    if (!(Test-Path $neutronBin)) {
        Throw "$neutronBin was not found."
    }
}


function Install-OVS {
    param(
        [Parameter(Mandatory=$true)]
        [string]$InstallerPath
    )

    Write-JujuInfo "Running OVS install"
    $ovs = Get-ManagementObject -Class Win32_Product | Where-Object {$_.Name -match "open vswitch"}
    if ($ovs){
        Write-JujuInfo "OVS is already installed"
        return $true
    }

    $hasInstaller = Test-Path $InstallerPath
    if($hasInstaller -eq $false){
        $InstallerPath = Get-OVSInstaller
    }
    Write-JujuInfo "Installing from $InstallerPath"
    $ret = Start-Process -FilePath msiexec.exe -ArgumentList "INSTALLDIR=`"$OVS_DIR`"","/qb","/l*v","$env:APPDATA\ovs-log.txt","/i","$InstallerPath" -Wait -PassThru
    if($ret.ExitCode) {
        Throw "Failed to install OVS: $LASTEXITCODE"
    }
    Remove-Item $InstallerPath
    return $true
}


function Get-OVSInstaller {
    $urlChecksum = Get-URLChecksum "ovs-installer-url"
    $location = Get-PackagePath $urlChecksum['URL'] $urlChecksum['CHECKSUM'] `
                                $urlChecksum['HASHING_ALGORITHM']
    return $location
}


function Check-OVSPrerequisites {
    try {
        $ovsdbSvc = Get-Service "ovsdb-server"
        $ovsSwitchSvc = Get-Service "ovs-vswitchd"
    } catch {
        $InstallerPath = Get-OVSInstaller
        Install-OVS $InstallerPath
    }
    if(!(Test-Path $OVS_VSCTL)){
        Throw "Could not find ovs-vsctl.exe in location: $OVS_VSCTL"
    }
}


function Enable-OVSExtension {
    $ext = Get-OVSExtStatus
    if (!$ext){
       Throw "Cannot enable OVS extension. Not installed"
    }
    if (!$ext.Enabled) {
        Enable-VMSwitchExtension $OVS_EXT_NAME $ext.SwitchName
    }
    return $true
}


function Get-OVSExtStatus {
    $br = Get-JujuVMSwitchName
    Write-JujuInfo "Switch name is $br"
    $ext = Get-VMSwitchExtension -VMSwitchName $br -Name $OVS_EXT_NAME

    if (!$ext){
        Write-JujuInfo "Open vSwitch extension not installed"
        return $null
    }

    return $ext
}


function Enable-Service {
    Param(
        [Parameter(Mandatory=$true)]
        [string]$ServiceName
    )

    Get-Service $ServiceName | Set-Service -StartupType Automatic
}


function Set-HyperVMACS {
    $b1 = "0x{0:x}" -f (get-random -minimum 1 -maximum 255)
    $b2 = "0x{0:x}" -f (get-random -minimum 1 -maximum 255)
    $reg = "HKLM:\Software\Microsoft\Windows NT\CurrentVersion\Virtualization"
    set-ItemProperty -path $reg -name minimummacaddress -type binary -value ([byte[]](0x00,0x15,0x5d,$b1,$b2,0x00))
    set-ItemProperty -path $reg -name maximummacaddress -type binary -value ([byte[]](0x00,0x15,0x5d,$b1,$b2,0xff))
}


function Enable-OVS {
    $ovs_pip = "ovs==2.6.0.dev1"
    Start-ExternalCommand { pip install -U $ovs_pip } -ErrorMessage "Failed to install $ovs_pip"
    
    Start-ExternalCommand { cmd.exe /c "sc triggerinfo ovs-vswitchd start/strcustom/6066F867-7CA1-4418-85FD-36E3F9C0600C/VmmsWmiEventProvider" } -ErrorMessage "Failed to modify ovs-vswitchd service."
    Start-ExternalCommand { cmd.exe /c "sc config ovs-vswitchd start=demand" } -ErrorMessage "Failed to modify ovs-vswitchd service."

    Enable-OVSExtension

    Enable-Service "ovsdb-server"
    #Enable-Service "ovs-vswitchd"

    Start-Service "ovsdb-server"
    #Start-Service "ovs-vswitchd"
}


function Ensure-InternalOVSInterfaces {
    $ifIndex = Get-CharmState -Namespace "novahyperv" -Key "dataNetworkIfindex"
    $lip = Get-CharmState -Namespace "novahyperv" -Key "local_ip"
    $ifName = (Get-NetAdapter -ifindex $ifIndex).Name

    $br_mac = "55-55-" + ((Get-NetAdapter -ifindex $ifIndex).MACAddress).split("-", 3)[2] 

    Invoke-JujuCommand -Command @($ovs_vsctl, "--may-exist", "add-br", "juju-br")
    Get-NetAdapter -name "juju-br" | Set-NetAdapter -MACAddress $br_mac -Confirm:$false
    Invoke-JujuCommand -Command @($ovs_vsctl, "--may-exist", "add-port", "juju-br", $ifName)

    Restart-Service "ovs-vswitchd"
    Enable-NetAdapter -Name "juju-br" -Confirm:$false

    $count = 0
    while ($count -lt 60) {
        if ((get-netipaddress | ? interfacealias -eq "juju-br" | ? addressfamily -eq "ipv4").SuffixOrigin -eq "Dhcp") {
            $lip = (get-netipaddress | ? interfacealias -eq "juju-br" | ? addressfamily -eq "ipv4").IPAddress
            Set-CharmState -Namespace "novahyperv" -Key "local_ip" -Value $lip
            return
        }
        $count += 1
        Start-Sleep -Seconds 1
    }
}
 

function Get-CherryPicksObject {
    $cfgOption = Get-JujuCharmConfig -Scope 'cherry-picks'
    if (!$cfgOption) {
        return @{}
    }
    $ret = @{
        'nova' = @();
        'networking-hyperv' = @();
        'compute-hyperv' = @();
        'neutron' = @()
    }
    $splitCfgOption = $cfgOption.Split(',')
    $validProjects = @('nova', 'networking-hyperv', 'neutron', 'compute-hyperv')
    foreach ($item in $splitCfgOption) {
        $splitItem = $item.Split('|')
        if ($splitItem.Count -ne 4) {
            Throw "ERROR: Wrong 'cherry-picks' config option format"
        }
        $projectName = $splitItem[0]
        if ($projectName -notin $validProjects) {
            Throw "ERROR: Invalid git project name '$projectName'"
        }
        $ret[$projectName] += @{
            'git_url' = $splitItem[1];
            'branch_name' = $splitItem[2];
            'commit_id' = $splitItem[3]
        }
    }
    return $ret
}


function Initialize-GitRepository {
    Param(
        [string]$BuildFolder,
        [string]$GitURL,
        [string]$BranchName,
        [array]$CherryPicks=@()
    )

    Write-JujuLog "Cloning $GitURL from $BranchName"
    Start-ExecuteWithRetry { Start-GitClonePull $BuildFolder $GitURL $BranchName }
    foreach ($commit in $CherryPicks) {
        Write-JujuLog ("Cherry-picking commit {0} from {1}, branch {2}" -f
                       @($commit['commit_id'], $commit['git_url'], $commit['branch_name']))
        pushd $BuildFolder
        Start-ExternalCommand { git fetch $commit['git_url'] $commit['branch_name'] }
        Start-ExternalCommand { git cherry-pick $commit['commit_id'] }
        popd
    }
}


function Initialize-GitRepositories {
    Param(
        [ValidateSet("hyperv", "ovs")]
        [string]$NetworkType,
        [string]$BranchName,
        [ValidateSet("openstack/nova", "openstack/neutron", "openstack/networking-hyperv", "openstack/quantum", "openstack/compute-hyperv")]
        [string]$BuildFor
    )

    Write-JujuLog "Cloning the required Git repositories"

    $cherryPicks = Get-CherryPicksObject
    $openstackBuild = Join-Path $BUILD_DIR "openstack"
    if ($NetworkType -eq 'hyperv') {
        if ($BuildFor -eq "openstack/networking-hyperv") {
            Initialize-GitRepository "$openstackBuild\nova" $NOVA_GIT $BranchName $cherryPicks['nova']
            Initialize-GitRepository "$openstackBuild\neutron" $NEUTRON_GIT $BranchName $cherryPicks['neutron']
        } else {
            Initialize-GitRepository "$openstackBuild\networking-hyperv" $NETWORKING_HYPERV_GIT "master" $cherryPicks['networking-hyperv']
        }
    }

    if ($BuildFor -eq "openstack/nova") {
        Initialize-GitRepository "$openstackBuild\neutron" $NEUTRON_GIT $BranchName $cherryPicks['neutron']
    }

    if (($BuildFor -eq "openstack/neutron") -or ($BuildFor -eq "openstack/quantum")) {
        Initialize-GitRepository "$openstackBuild\nova" $NOVA_GIT $BranchName $cherryPicks['nova']
    }
    Initialize-GitRepository "$openstackBuild\compute-hyperv" $COMPUTE_HYPERV_GIT $BranchName $cherryPicks['compute-hyperv']
}


function Initialize-Environment {
    Param(
        [string]$BranchName='master',
        [string]$BuildFor='openstack/nova'
    )

    $dirs = @($CONFIG_DIR, $BIN_DIR, $INSTANCES_DIR, $LOG_DIR, $SERVICE_DIR)
    foreach($dir in $dirs) {
        if (!(Test-Path $dir)) {
            Write-JujuLog "Creating $dir folder."
            mkdir $dir
        }
    }

    $mkisofsPath = Join-Path $BIN_DIR "mkisofs.exe"
    $qemuimgPath = Join-Path $BIN_DIR "qemu-img.exe"
    if (!(Test-Path $mkisofsPath) -or !(Test-Path $qemuimgPath)) {
        Write-JujuLog "Extracting OpenStack binaries"
        $zipPath = Join-Path $FILES_DIR "openstack_bin.zip"
        Expand-ZipArchive $zipPath $BIN_DIR
    }

    #$networkType = Get-JujuCharmConfig -Scope 'network-type'
    #Initialize-GitRepositories $networkType $BranchName $BuildFor

    #Install-Nova
    #Install-ComputeHyperV
    #Install-Neutron
    #if ($networkType -eq 'hyperv') {
    #    Install-NetworkingHyperV
    #} elseif ($networkType -eq 'ovs') {
    #    Check-OVSPrerequisites
    #    Enable-OVS
    #    Ensure-InternalOVSInterfaces
    #} else {
    #    Throw "Wrong network type config: '$networkType'"
    #}

    #$os_win_git = "git+https://git.openstack.org/openstack/os-win.git"
    #Start-ExternalCommand -ScriptBlock { pip install -U $os_win_git } `
    #                                -ErrorMessage "Failed to install $os_win_git"

    #Start-ExternalCommand -ScriptBlock { pip install -U "amqp==1.4.9" } `
    #                                -ErrorMessage "Failed to install $os_win_git"

    Write-JujuLog "Environment initialization done."
}


function Set-ServiceAcountCredentials {
    Param(
        [string]$ServiceName,
        [string]$ServiceUser,
        [string]$ServicePassword
    )

    $filter = 'Name=' + "'" + $ServiceName + "'" + ''
    $service = Get-WMIObject -Namespace "root\cimv2" -Class Win32_Service -Filter $filter
    $service.StopService()
    while ($service.Started) {
        Start-Sleep -Seconds 2
        $service = Get-WMIObject -Namespace "root\cimv2" -Class Win32_Service -Filter $filter
    }

    Grant-Privilege $ServiceUser "SeServiceLogonRight"
    Set-ServiceLogon -Services @($ServiceName) -UserName $ServiceUser -Password $ServicePassword
}


function New-OpenStackService {
    Param(
        [string]$ServiceName,
        [string]$ServiceDescription,
        [string]$ServiceExecutable,
        [string]$ServiceConfig,
        [string]$ServiceUser,
        [string]$ServicePassword
    )

    $filter='Name=' + "'" + $ServiceName + "'"

    $service = Get-WmiObject -Namespace "root\cimv2" -Class Win32_Service -Filter $filter
    if($service) {
        Write-JujuLog "Service $ServiceName is already created."
        return $true
    }

    $serviceFileName = "OpenStackService.exe"
    if(!(Test-Path "$SERVICE_DIR\$serviceFileName")) {
        Copy-Item "$FILES_DIR\$serviceFileName" "$SERVICE_DIR\$serviceFileName"
    }

    New-Service -Name "$ServiceName" -DisplayName "$ServiceName" -Description "$ServiceDescription" -StartupType "Manual" `
                -BinaryPathName "$SERVICE_DIR\$serviceFileName $ServiceName $ServiceExecutable --config-file $ServiceConfig" `

    if((Get-Service -Name $ServiceName).Status -eq "Running") {
        Stop-Service $ServiceName
    }

    Set-ServiceAcountCredentials $ServiceName $ServiceUser $ServicePassword
}


function Watch-ServiceStatus {
    Param(
        [string]$ServiceName,
        [int]$IntervalSeconds
    )

    $count = 0
    while ($count -lt $IntervalSeconds) {
        if ((Get-Service -Name $ServiceName).Status -ne "Running") {
            Throw "$ServiceName has errors. Please check the logs."
        }
        $count += 1
        Start-Sleep -Seconds 1
    }
}


function Get-JujuVMSwitchName {
    $VMswitchName = Get-JujuCharmConfig -Scope "vmswitch-name"
    if (!$VMswitchName){
        return "br100"
    }
    return $VMswitchName
}


function Get-InterfaceFromConfig {
    Param (
        [string]$ConfigOption="data-port",
        [switch]$MustFindAdapter=$false
    )

    $nic = $null
    $DataInterfaceFromConfig = Get-JujuCharmConfig -Scope $ConfigOption
    Write-JujuInfo "Looking for $DataInterfaceFromConfig"
    if (!$DataInterfaceFromConfig){
        if($MustFindAdapter) {
            Throw "No data-port was specified"
        }
        return $null
    }
    $byMac = @()
    $byName = @()
    $macregex = "^([a-f-A-F0-9]{2}:){5}([a-fA-F0-9]{2})$"
    foreach ($i in $DataInterfaceFromConfig.Split()){
        if ($i -match $macregex){
            $byMac += $i.Replace(":", "-")
        }else{
            $byName += $i
        }
    }
    if ($byMac.Length){
        $nicByMac = Get-NetAdapter | Where-Object { $_.MacAddress -in $byMac -and $_.DriverFileName -ne "vmswitch.sys" }
    }
    if ($byName.Length){
        $nicByName = Get-NetAdapter | Where-Object { $_.Name -in $byName }
    }
    if ($nicByMac -ne $null -and $nicByMac.GetType() -ne [System.Array]){
        $nicByMac = @($nicByMac)
    }
    if ($nicByName -ne $null -and $nicByName.GetType() -ne [System.Array]){
        $nicByName = @($nicByName)
    }
    $ret = $nicByMac + $nicByName
    if ($ret.Length -eq 0 -and $MustFindAdapter){
        Throw "Could not find network adapters"
    }
    return $ret
}


function Get-DataPortFromDataNetwork {
    $dataNetwork = Get-JujuCharmConfig -Scope "os-data-network"
    if (!$dataNetwork) {
        Write-JujuInfo "os-data-network is not defined"
        return $false
    }

    $local_ip = Get-CharmState -Namespace "novahyperv" -Key "local_ip"
    $ifIndex = Get-CharmState -Namespace "novahyperv" -Key "dataNetworkIfindex"

    if($local_ip -and $ifIndex){
        if((Confirm-LocalIP -IPaddress $ifIndex -ifIndex $ifIndex)){
            return Get-NetAdapter -ifindex $ifIndex
        }
    }

    # If there is any network interface configured to use DHCP and did not get an IP address
    # we manually renew its lease and try to get an IP address before searching for the data network
    $interfaces = Get-CimInstance -Class win32_networkadapterconfiguration | Where-Object { 
        $_.IPEnabled -eq $true -and $_.DHCPEnabled -eq $true -and $_.DHCPServer -eq "255.255.255.255"
    }
    if($interfaces){
        $interfaces.InterfaceIndex | Invoke-DHCPRenew -ErrorAction SilentlyContinue
    }
    $netDetails = $dataNetwork.Split("/")
    $decimalMask = ConvertTo-Mask $netDetails[1]

    $configuredAddresses = Get-NetIPAddress -AddressFamily IPv4
    foreach ($i in $configuredAddresses) {
        Write-JujuInfo ("Checking {0} on interface {1}" -f @($i.IPAddress, $i.InterfaceAlias))
        if ($i.PrefixLength -ne $netDetails[1]){
            continue
        }
        $network = Get-NetworkAddress $i.IPv4Address $decimalMask
        Write-JujuInfo ("Network address for {0} is {1}" -f @($i.IPAddress, $network))
        if ($network -eq $netDetails[0]){
            Set-CharmState -Namespace "novahyperv" -Key "local_ip" -Value $i.IPAddress
            Set-CharmState -Namespace "novahyperv" -Key "dataNetworkIfindex" -Value $i.IfIndex
            return Get-NetAdapter -ifindex $i.IfIndex
        }
    }
    return $false
}


function Get-RealInterface {
    [CmdletBinding()]
    Param(
        [Parameter(Mandatory=$true, ValueFromPipeline=$true)]
        [Microsoft.Management.Infrastructure.CimInstance]$interface
    )
    PROCESS {
        if($interface.DriverFileName -ne "vmswitch.sys") {
            return $interface
        }
        $realInterface = Get-NetAdapter | Where-Object {
            $_.MacAddress -eq $interface.MacAddress -and $_.ifIndex -ne $interface.ifIndex
        }

        if(!$realInterface){
            Throw "Failed to find interface attached to VMSwitch"
        }
        return $realInterface[0]
    }
}


function Get-FallbackNetadapter {
    $name = Get-MainNetadapter
    $net = Get-NetAdapter -Name $name
    return $net
}


function Get-OVSDataPort {
    $dataPort = Get-DataPortFromDataNetwork
    if ($dataPort){
        return Get-RealInterface $dataPort
    }else{
        $port = Get-FallbackNetadapter
        $local_ip = Get-NetIPAddress -AddressFamily IPv4 -InterfaceIndex $port.IfIndex -ErrorAction SilentlyContinue
        if(!$local_ip){
            Throw "failed to get fallback adapter IP address"
        }
        Set-CharmState -Namespace "novahyperv" -Key "local_ip" -Value $local_ip[0]
        Set-CharmState -Namespace "novahyperv" -Key "dataNetworkIfindex" -Value $port.IfIndex
    }

    return Get-RealInterface $port
}


function Get-DataPort {
    $managementOS = Get-JujuCharmConfig -Scope "vmswitch-management"
    $networkType = Get-JujuCharmConfig -Scope 'network-type'

    if ($networkType -eq "ovs"){
        Write-JujuInfo "Trying to fetch OVS data port"
        $dataPort = Get-OVSDataPort
        return @($dataPort[0], $managementOS)
    }

    Write-JujuInfo "Trying to fetch data port from config"
    $nic = Get-InterfaceFromConfig
    if(!$nic) {
        $nic = Get-FallbackNetadapter
        $managementOS = $true
    }
    $nic = Get-RealInterface $nic[0]
    return @($nic, $managementOS)
}


function Start-ConfigureVMSwitch {
    $VMswitchName = Get-JujuVMSwitchName
    $vmswitch = Get-VMSwitch -SwitchType External -Name $VMswitchName -ErrorAction SilentlyContinue

    if($vmswitch){
        return $true
    }

    Set-HyperVMACS

    $dataPort, $managementOS = Get-DataPort
    $VMswitches = Get-VMSwitch -SwitchType External -ErrorAction SilentlyContinue
    if ($VMswitches -and $VMswitches.Count -gt 0){
        foreach($i in $VMswitches){
            if ($i.NetAdapterInterfaceDescription -eq $dataPort.InterfaceDescription) {
                Rename-VMSwitch $i -NewName $VMswitchName
                Set-VMSwitch -Name $VMswitchName -AllowManagementOS $managementOS
                return $true
            }
        }
    }

    Write-JujuInfo "Adding new vmswitch: $VMswitchName"
    New-VMSwitch -Name $VMswitchName -NetAdapterName $dataPort.Name -AllowManagementOS $managementOS

    return $true
}


function Install-Dependency {
    Param(
        [string]$URLConfigKey,
        [array]$ArgumentList
    )

    $urlChecksum = Get-URLChecksum $URLConfigKey
    if ($urlChecksum['CHECKSUM'] -and $urlChecksum['HASHING_ALGORITHM']) {
        Install-Package -URL $urlChecksum['URL'] -Checksum $urlChecksum['CHECKSUM'] `
                        -HashingAlgorithm $urlChecksum['HASHING_ALGORITHM'] `
                        -ArgumentList $ArgumentList
    } else {
        Install-Package -URL $urlChecksum['URL'] -ArgumentList $ArgumentList
    }
}


function Install-FreeRDPConsole {
    Write-JujuLog "Installing FreeRDP"

    Install-Dependency 'vc-2012-url' @('/q')

    $freeRDPZip = Join-Path $FILES_DIR "FreeRDP_powershell.zip"
    $charmLibDir = Join-Path (Get-JujuCharmDir) "lib"
    Expand-ZipArchive $freeRDPZip $charmLibDir

    # Copy wfreerdp.exe and DLL file to Windows folder
    $freeRDPFiles = @('wfreerdp.exe', 'libeay32.dll', 'ssleay32.dll')
    $windows = Join-Path $env:SystemDrive "Windows"
    foreach ($file in $freeRDPFiles) {
        Copy-Item "$charmLibDir\FreeRDP\$file" $windows
    }

    $freeRDPModuleFolder = Join-Path $windows "system32\WindowsPowerShell\v1.0\Modules\FreeRDP"
    if (!(Test-Path $freeRDPModuleFolder)) {
        mkdir $freeRDPModuleFolder
    }
    Copy-Item "$charmLibDir\FreeRDP\FreeRDP.psm1" $freeRDPModuleFolder
    Remove-Item -Recurse "$charmLibDir\FreeRDP"

    Write-JujuLog "Finished installing FreeRDP."
}


function Write-PipConfigFile {
    $pipDir = Join-Path $env:APPDATA "pip"
    if (Test-Path $pipDir){
        Remove-Item -Force -Recurse $pipDir
    }

    $pypiMirror = Get-JujuCharmConfig -scope 'pypi-mirror'
    if ($pypiMirror -eq $null -or $pypiMirror.Length -eq 0) {
        Write-JujuLog ("pypi-mirror config is not present. " +
                       "Will not generate the pip.ini file.")
        return
    }
    mkdir $pipDir
    $pipIni = Join-Path $pipDir "pip.ini"
    New-Item -ItemType File $pipIni

    $mirrors = $pypiMirror.Split()
    $hosts = @()
    foreach ($i in $mirrors){
        $h = ([System.Uri]$i).Host
        if ($h -in $hosts) {
            continue
        }
        $hosts += $h
    }

    Set-IniFileValue "index-url" "global" $mirrors[0] $pipIni
    if ($mirrors.Length -gt 1){
        Set-IniFileValue "extra-index-url" "global" ($mirrors[1..$mirrors.Length] -Join " ") $pipIni
    }
    Set-IniFileValue "trusted-host" "install" ($hosts -Join " ") $pipIni
}


function Get-HypervADUser {
    $adUsername = Get-JujuCharmConfig -scope 'ad-user-name'
    if (!$adUsername) {
        $adUsername = "hyper-v-user"
    }
    return $adUsername
}


function Set-DevStackRelationParams {
    Param(
        [HashTable]$RelationParams
    )

    $rids = Get-JujuRelationIds -Relation "devstack"
    foreach ($rid in $rids) {
        try {
            Set-JujuRelation -Settings $RelationParams -RelationId $rid
        } catch {
            Write-JujuError "Failed to set DevStack relation parameters."
        }
    }
}


function Import-CloudbaseCert {
    $crt = Join-Path $FILES_DIR "Cloudbase_signing.cer"
    if (!(Test-Path $crt)){
        return $false
    }
    Import-Certificate $crt -StoreLocation LocalMachine -StoreName TrustedPublisher
}


# HOOKS FUNCTIONS

function Start-InstallHook {
    # Set machine to use high performance settings.
    try {
        Set-PowerProfile -PowerProfile Performance
    } catch {
        # No need to error out the hook if this fails.
        Write-JujuWarning "Failed to set power scheme."
    }
    Start-TimeResync

    # Disable firewall
    Start-ExternalCommand { netsh.exe advfirewall set allprofiles state off } -ErrorMessage "Failed to disable firewall."

    Write-JujuLog "Disabling automatic updates"
    $updates_service = Get-WmiObject Win32_Service -Filter 'Name="wuauserv"'
    $updates_service.ChangeStartMode("Disabled")
    $updates_service.StopService()

    Write-JujuLog "Enable and start MSiSCSI"
    $msiscsi_service = Get-WmiObject Win32_Service -Filter 'Name="MSiSCSI"'
    $msiscsi_service.ChangeStartMode("Automatic")
    $msiscsi_service.StartService()

    Import-CloudbaseCert
    Start-ConfigureVMSwitch
    Write-PipConfigFile

    # Install Git
    Install-Dependency 'git-url' @('/SILENT')
    Add-ToUserPath "${env:ProgramFiles(x86)}\Git\cmd"
    Add-ToSystemPath "${env:ProgramFiles(x86)}\Git\cmd"
    Add-ToSystemPath "${env:ProgramFiles(x86)}\Git\bin"

    # Install Python 2.7.x (x86)
    Install-Dependency 'python27-url' @('/qn')
    Add-ToUserPath "${env:SystemDrive}\Python27;${env:SystemDrive}\Python27\scripts"
    Add-ToSystemPath "${env:SystemDrive}\Python27;${env:SystemDrive}\Python27\scripts"

    # Install Windows OpenSSL
    Install-Dependency 'openssl-url' @('/verysilent')

    # Install FreeRDP Hyper-V console access
    $enableFreeRDP = Get-JujuCharmConfig -Scope 'enable-freerdp-console'
    if ($enableFreeRDP -eq $true) {
        Install-FreeRDPConsole
    }

    Write-JujuLog "Installing pip"
    $conf_pip_version = Get-JujuCharmConfig -Scope 'pip-version'
    $tmpPath = Join-Path $env:TEMP "get-pip.py"
    Start-DownloadFile -Uri "https://bootstrap.pypa.io/get-pip.py" -SkipIntegrityCheck -OutFile $tmpPath
    Start-ExternalCommand -ScriptBlock { python $tmpPath $conf_pip_version } -ErrorMessage "Failed to install pip."
    Remove-Item $tmpPath
    $version = Start-ExternalCommand { pip.exe --version } -ErrorMessage "Failed to get pip version."
    Write-JujuLog "Pip version: $version"

    Write-JujuLog "Installing pip dependencies"
    $pythonPkgs = Get-JujuCharmConfig -Scope 'extra-python-packages'
    if ($pythonPkgs) {
        $pythonPkgsArr = $pythonPkgs.Split()
        foreach ($pythonPkg in $pythonPkgsArr) {
            Write-JujuLog "Installing $pythonPkg"
            Start-ExternalCommand -ScriptBlock { pip install -U $pythonPkg } `
                                    -ErrorMessage "Failed to install $pythonPkg"
        }
    }

    Write-JujuLog "Installing posix_ipc library"
    $zipPath = Join-Path $FILES_DIR "posix_ipc.zip"
    $posixIpcEgg = Join-Path $LIB_DIR "posix_ipc-0.9.8-py2.7.egg-info"
    if (!(Test-Path $posixIpcEgg)) {
        Expand-ZipArchive $zipPath $LIB_DIR
    }

    Write-JujuLog "Installing pywin32"
    Start-ExternalCommand -ScriptBlock { pip install pywin32 } `
                          -ErrorMessage "Failed to install pywin32."
    Start-ExternalCommand {
        python "$PYTHON_DIR\Scripts\pywin32_postinstall.py" -install
    } -ErrorMessage "Failed to run pywin32_postinstall.py"

    #Write-JujuLog "Running Git Prep"
    #$zuulUrl = Get-JujuCharmConfig -Scope 'zuul-url'
    #$zuulRef = Get-JujuCharmConfig -Scope 'zuul-ref'
    #$zuulChange = Get-JujuCharmConfig -Scope 'zuul-change'
    #$zuulProject = Get-JujuCharmConfig -Scope 'zuul-project'
    #$gerritSite = $zuulUrl.Trim('/p')
    #Start-GerritGitPrep -ZuulUrl $zuulUrl -GerritSite $gerritSite -ZuulRef $zuulRef `
    #                    -ZuulChange $zuulChange -ZuulProject $zuulProject

    $gitEmail = Get-JujuCharmConfig -scope 'git-user-email'
    $gitName = Get-JujuCharmConfig -scope 'git-user-name'
    Start-ExternalCommand { git config --global user.email $gitEmail } `
        -ErrorMessage "Failed to set git global user.email"
    Start-ExternalCommand { git config --global user.name $gitName } `
        -ErrorMessage "Failed to set git global user.name"
    $zuulBranch = Get-JujuCharmConfig -scope 'zuul-branch'

    Write-JujuLog "Initializing the environment"
    Initialize-Environment
}


function Start-ADRelationJoinedHook {
    $hypervADUser = Get-HypervADUser
    $userGroup = @{$hypervADUser = @("CN=Users")}
    $encUserGroup = Get-MarshaledObject $userGroup
    $constraintsList = @("Microsoft Virtual System Migration Service", "cifs")
    $relationParams = @{
        'computername' = [System.Net.Dns]::GetHostName()
        'constraints' = Get-MarshaledObject $constraintsList
        'adusers' = $encUserGroup
    }

    $rids = Get-JujuRelationIds -Relation "ad-join"
    foreach ($rid in $rids) {
        try {
            Set-JujuRelation -Settings $relationParams -RelationId $rid
        } catch {
            Write-JujuError "Failed to set AD relation parameters."
        }
    }
}


function Start-RelationHooks {
    $charmServices = Get-CharmServices
    $networkType = Get-JujuCharmConfig -Scope 'network-type'
    if ($networkType -eq "hyperv") {
        $charmServices.Remove('neutron-ovs')
    } elseif ($networkType -eq "ovs") {
        $charmServices.Remove('neutron')
    } else {
        Throw "ERROR: Unknown network type: '$networkType'."
    }

    $adCtx = Get-ActiveDirectoryContext
    if (!$adCtx.Count) {
        Write-JujuLog "AD context is not ready."
    } else {
        Start-JoinDomain

    Write-JujuLog "Enabling Live Migration"
    Start-ExternalCommand { Enable-VMMigration } -ErrorMessage "Failed to enable live migation."
    Start-ExternalCommand { Set-VMHost -useanynetworkformigration $true } -ErrorMessage "Failed setting using any network for migration"
    Start-ExternalCommand { Set-VMHost -VirtualMachineMigrationAuthenticationType Kerberos -ErrorAction SilentlyContinue } -ErrorMessage "Failed setting VM migartion authentication type"

        $adUserCred = @{
            'domain'   = $adCtx["domainName"];
            'username' = $adCtx['adcredentials'][0]['username'];
            'password' = $adCtx['adcredentials'][0]['password']
        }
        #$relationParams = @{'ad_credentials' = (Get-MarshaledObject $adUserCred);}
        #Set-DevStackRelationParams $relationParams

        # Add AD user to local Administrators group
        Grant-PrivilegesOnDomainUser $adCtx['adcredentials'][0]['username']

        foreach($key in $charmServices.Keys) {
            New-OpenStackService $charmServices[$key]['service_name'] $charmServices[$key]['description'] `
                                 $charmServices[$key]['binary'] $charmServices[$key]['config'] `
                                 $adCtx['adcredentials'][0]['username'] `
                                 $adCtx['adcredentials'][0]['password']
            Write-ConfigFile $key
        }
        Set-JujuStatus -Status active -Message "Unit is ready"
    }

    #$devstackCtx = Get-DevStackContext
    #if (!$devstackCtx.Count -or !$adCtx.Count) {
    #    Write-JujuLog ("Both AD context and DevStack context must be complete " +
    #                   "before starting the OpenStack services.")
    #} else {
    #    Start-Service "MSiSCSI"
    #    Write-JujuLog "Starting OpenStack services"
    #    $pollingInterval = 60
    #    foreach($key in $charmServices.Keys) {
    #        $serviceName = $charmServices[$key]['service_name']
    #        Write-JujuLog "Starting $serviceName service"
    #        Start-Service -ServiceName $serviceName
    #        Write-JujuLog "Polling $serviceName service status for $pollingInterval seconds."
    #        Watch-ServiceStatus $serviceName -IntervalSeconds $pollingInterval
    #    }
    #}
}
