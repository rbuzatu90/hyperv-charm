$ErrorActionPreference = 'Stop'

try {
    $charmHelpersPath = Join-Path (Split-Path $PSScriptRoot) "lib\Modules\CharmHelpers"
    Import-Module -Force -DisableNameChecking $charmHelpersPath
} catch {
    juju-log.exe "ERROR while loading PowerShell charm helpers: $_"
    exit 1
}

$GIT_URL       = "https://github.com/msysgit/msysgit/releases/download/Git-1.9.5-preview20150319/Git-1.9.5-preview20150319.exe"
$GIT_SHA1      = "A8658BAE0DE8C8D3E40AA97A236A4FCF81DE50DF"
$PYTHON27_URL  = "https://www.python.org/ftp/python/2.7.10/python-2.7.10.msi"
$PYTHON27_SHA1 = "9E62F37407E6964EE0374B32869B7B4AB050D12A"
$7Z_URL        = "http://www.7-zip.org/a/7z938.exe"
$7Z_SHA1       = "9AC9E5E6A19BF3B18CD7BCBE34A5141996BB3028"
$VC_2012_URL   = "http://download.microsoft.com/download/1/6/B/16B06F60-3B20-4FF2-B699-5E9B7962F9AE/VSU_4/vcredist_x86.exe"
$VC_2012_SHA1  = "96B377A27AC5445328CBAAE210FC4F0AAA750D3F"

$NEUTRON_GIT           = "https://github.com/openstack/neutron.git"
$NOVA_GIT              = "https://github.com/openstack/nova.git"
$NETWORKING_HYPERV_GIT = "https://github.com/stackforge/networking-hyperv.git"

$OPENSTACK_DIR = Join-Path $env:SystemDrive "OpenStack"
$PYTHON_DIR    = Join-Path $env:SystemDrive "Python27"
$LIB_DIR       = Join-Path $PYTHON_DIR "lib\site-packages"
$BUILD_DIR     = Join-Path $OPENSTACK_DIR "build"
$INSTANCES_DIR = Join-Path $OPENSTACK_DIR "Instances"
$BIN_DIR       = Join-Path $OPENSTACK_DIR "bin"
$CONFIG_DIR    = Join-Path $OPENSTACK_DIR "etc"
$LOG_DIR       = Join-Path $OPENSTACK_DIR "log"
$SERVICE_DIR   = Join-Path $OPENSTACK_DIR "service"

$NOVA_SERVICE_NAME        = "nova-compute"
$NOVA_SERVICE_DESCRIPTION = "OpenStack nova Compute Service"
$NOVA_SERVICE_EXECUTABLE  = Join-Path $PYTHON_DIR "Scripts\nova-compute.exe"
$NOVA_SERVICE_CONFIG      = Join-Path $CONFIG_DIR "nova.conf"

$NEUTRON_SERVICE_NAME        = "neutron-hyperv-agent"
$NEUTRON_SERVICE_DESCRIPTION = "OpenStack Neutron Hyper-V Agent Service"
$NEUTRON_SERVICE_EXECUTABLE  = Join-Path $PYTHON_DIR "Scripts\neutron-hyperv-agent.exe"
$NEUTRON_SERVICE_CONFIG      = Join-Path $CONFIG_DIR "neutron_hyperv_agent.conf"

$PYTHON_PROCESS_NAME = "python"


function Get-TemplatesDir {
    return (Join-Path (Get-JujuCharmDir) "templates")
}


function Unzip-With7z {
    Param(
        [string]$ZipPath,
        [string]$DestinationFolder
    )

    Execute-ExternalCommand -Command { 7z.exe x -y $ZipPath -o"$DestinationFolder" } `
                            -ErrorMessage "Failed to unzip $ZipPath."
}


function Get-ADContext {
    $ctx =  @{
        "ad_host"        = "private-address";
        "ip_address"     = "address";
        "ad_hostname"    = "hostname";
        "ad_username"    = "username";
        "ad_password"    = "password";
        "ad_domain"      = "domainName";
        "ad_credentials" = "adcredentials";
    }
    return (Get-JujuRelationParams 'ad-join' $ctx)
}


function Get-DevStackContext {
    $ctx =  @{
        "devstack_ip"       = "devstack_ip";
        "devstack_password" = "password";
        "rabbit_user"       = "rabbit_user";
    }
    return (Get-JujuRelationParams 'devstack' $ctx)
}


# Returns an HashTable with the download URL and SHA1 checksum for a specific
# package. First, it is checked if the user provided his own download link
# and SHA1 checksum in config.yaml. If those options are not present,
# $null is returned.
function Get-URLChecksum {
    Param(
        [string]$URLConfigKey,
        [string]$SHA1ConfigKey
    )

    $url = Get-JujuCharmConfig -scope $URLConfigKey
    if ($url) {
        $sha1Checksum = Get-JujuCharmConfig -scope $SHA1ConfigKey
        if ($sha1Checksum) {
            return @{ 'URL' = $url; 
                      'SHA1_CHECKSUM' = $sha1Checksum }
        }
    }
    return $null
}

# Returns the full path of the package after it is downloaded using
# the URL and SHA1 checksum received as parameters. The package is cached
# on the disk until the installation successfully finishes. If the hook
# fails, on the second run this function will return the cached package path.
function Get-PackagePath {
    Param(
        [string]$URL,
        [string]$Sha1Checksum
    )

    $packagePath = Join-Path $env:TEMP $URL.Split('/')[-1]
    if (Test-Path $packagePath) {
        $sha1Hash = (Get-FileHash -Path $packagePath -Algorithm "SHA1").Hash
        if ($sha1Hash -eq $Sha1Checksum) {
            return $packagePath
        }
        Remove-Item -Recurse -Force -Path $packagePath
    }
    return (Download-File -DownloadLink $URL -ExpectedSHA1Hash $Sha1Checksum `
                          -DestinationFile $packagePath)
}


# Installs a package after it is downloaded from the Internet and checked for
# integrity with SHA1 checksum. Accepts as parameters:  an URL, a SHA1
# checksum and 'ArgumentList' which can be passed if the installer requires
# unattended installation. Supported packages formats are: '.exe' and '.msi'.
function Install-Package {
    Param(
        [string]$URL,
        [string]$SHA1Checksum,
        [array]$ArgumentList
    )

    Write-JujuLog "Installing package $URL..."

    $packageFormat = $URL.Split('.')[-1]
    $acceptedFormats = @('msi', 'exe')
    if ($packageFormat -notin $acceptedFormats) {
        Throw ("Cannot install the package found at this URL: $URL " +
               "Unsupported installer format.")
    }

    $installerPath = Get-PackagePath $URL $SHA1Checksum
    $stat = Start-Process -FilePath $installerPath -ArgumentList $ArgumentList `
                          -PassThru -Wait
    if ($stat.ExitCode -ne 0) {
        throw "Package failed to install."
    }
    Remove-Item $installerPath

    Write-JujuLog "Finished installing package."
}


function Run-GitClonePull {
    Param(
        [string]$Path,
        [string]$URL,
        [string]$Branch="master"
    )

    if (!(Test-Path -Path $Path)) {
        ExecuteWith-Retry {
            Execute-ExternalCommand -Command { git clone $URL $Path } `
                                    -ErrorMessage "Git clone failed"
        }
        Execute-ExternalCommand -Command { git checkout $Branch } `
                                -ErrorMessage "Git checkout failed"
    } else {
        pushd $Path
        try {
            $gitPath = Join-Path $Path ".git"
            if (!(Test-Path -Path $gitPath)) {
                Remove-Item -Recurse -Force *
                ExecuteWith-Retry {
                    Execute-ExternalCommand -Command { git clone $URL $Path } `
                                            -ErrorMessage "Git clone failed"
                }
            } else {
                ExecuteWith-Retry {
                    Execute-ExternalCommand -Command { git fetch --all } `
                                            -ErrorMessage "Git fetch failed"
                }
            }
            ExecuteWith-Retry {
                Execute-ExternalCommand -Command { git checkout $Branch } `
                                        -ErrorMessage "Git checkout failed"
            }
            Get-ChildItem . -Include *.pyc -Recurse | foreach ($_) { Remove-Item $_.fullname }
            Execute-ExternalCommand -Command { git reset --hard } `
                                    -ErrorMessage "Git reset failed"
            Execute-ExternalCommand -Command { git clean -f -d } `
                                    -ErrorMessage "Git clean failed"
            ExecuteWith-Retry {
                Execute-ExternalCommand -Command { git pull } `
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

    pushd $ProjectPath
    Execute-ExternalCommand -Command { python setup.py install } `
                            -ErrorMessage "Failed to install $ProjectPath from repo."
    popd
}


function Run-GerritGitPrep {
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
            Execute-ExternalCommand { git clone "$GitOrigin/$ZuulProject" $projectDir } `
                -ErrorMessage "Failed to clone $GitOrigin/$ZuulProject"
        } catch {
            rm -Recurse -Force $projectDir
            Throw $_
        }
    }

    pushd $projectDir

    Execute-ExternalCommand { git remote set-url origin "$GitOrigin/$ZuulProject" } `
        -ErrorMessage "Failed to set origin: $GitOrigin/$ZuulProject"

    try {
        Execute-ExternalCommand { git remote update } -ErrorMessage "Failed to update remote"
    } catch {
        Write-JujuLog "The remote update failed, so garbage collecting before trying again."
        Execute-ExternalCommand { git gc } -ErrorMessage "Failed to run git gc."
        Execute-ExternalCommand { git remote update } -ErrorMessage "Failed to update remote"
    }

    Execute-ExternalCommand { git reset --hard } -ErrorMessage "Failed to git reset"
    try {
        Execute-ExternalCommand { git clean -x -f -d -q } -ErrorMessage "Failed to git clean"
    } catch {
        sleep 1
        Execute-ExternalCommand { git clean -x -f -d -q } -ErrorMessage "Failed to git clean"
    }

    echo "Before doing git checkout:"
    echo "Git branch output:"
    Execute-ExternalCommand { git branch } -ErrorMessage "Failed to show git branch."
    echo "Git log output:"
    Execute-ExternalCommand { git log -10 --pretty=format:"%h - %an, %ae, %ar : %s" } `
        -ErrorMessage "Failed to show git log."

    $ret = echo "$ZuulRef" | Where-Object { $_ -match "^refs/tags/" }
    if ($ret) {
        Execute-ExternalCommand { git fetch --tags "$ZuulUrl/$ZuulProject" } `
            -ErrorMessage "Failed to fetch tags from: $ZuulUrl/$ZuulProject"
        Execute-ExternalCommand { git checkout $ZuulRef } `
            -ErrorMessage "Failed to fetch tags to: $ZuulRef"
        Execute-ExternalCommand { git reset --hard $ZuulRef } `
            -ErrorMessage "Failed to hard reset to: $ZuulRef"
    } elseif (!$ZuulNewrev) {
        Execute-ExternalCommand { git fetch "$ZuulUrl/$ZuulProject" $ZuulRef } `
            -ErrorMessage "Failed to fetch: $ZuulUrl/$ZuulProject $ZuulRef"
        Execute-ExternalCommand { git checkout FETCH_HEAD } `
            -ErrorMessage "Failed to checkout FETCH_HEAD"
        Execute-ExternalCommand { git reset --hard FETCH_HEAD } `
            -ErrorMessage "Failed to hard reset FETCH_HEAD"
    } else {
        Execute-ExternalCommand { git checkout $ZuulNewrev } `
            -ErrorMessage "Failed to checkout $ZuulNewrev"
        Execute-ExternalCommand { git reset --hard $ZuulNewrev } `
            -ErrorMessage "Failed to hard reset $ZuulNewrev"
    }

    try {
        Execute-ExternalCommand { git clean -x -f -d -q } -ErrorMessage "Failed to git clean"
    } catch {
        sleep 1
        Execute-ExternalCommand { git clean -x -f -d -q } -ErrorMessage "Failed to git clean"
    }

    if (Test-Path .gitmodules) {
        Execute-ExternalCommand { git submodule init } -ErrorMessage "Failed to init submodule"
        Execute-ExternalCommand { git submodule sync } -ErrorMessage "Failed to sync submodule"
        Execute-ExternalCommand { git submodule update --init } -ErrorMessage "Failed to update submodule"
    }

    echo "Final result:"
    echo "Git branch output:"
    Execute-ExternalCommand { git branch } -ErrorMessage "Failed to show git branch."
    echo "Git log output:"
    Execute-ExternalCommand { git log -10 --pretty=format:"%h - %an, %ae, %ar : %s" } `
        -ErrorMessage "Failed to show git log."

    popd
}


function Render-ConfigFile {
    Param(
        [string]$TemplatePath,
        [string]$ConfPath,
        [HashTable]$Configs
    )

    $template = Get-Content $TemplatePath
    foreach ($config in $Configs.GetEnumerator()) {
        $regex = "{{\s*" + $config.Name + "\s*}}"
        $template = $template | ForEach-Object { $_ -replace $regex,$config.Value }
    }

    Set-Content $ConfPath $template
}


function Create-Environment {
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
    $downloadMirror = Get-JujuCharmConfig -scope "download-mirror"
    if (!(Test-Path $mkisofsPath) -or !(Test-Path $qemuimgPath)) {
        Write-JujuLog "Downloading OpenStack binaries..."
        $zipPath = "$BIN_DIR\openstack_bin.zip"
        Invoke-WebRequest -Uri "$downloadMirror/openstack_bin.zip" -OutFile $zipPath
        Unzip-With7z $zipPath $BIN_DIR
        rm $zipPath
    }

    Write-JujuLog "Cloning the required Git repositories..."
    $openstackBuild = Join-Path $BUILD_DIR "openstack"
    if ($BuildFor -eq "openstack/nova") {
        Write-JujuLog "Cloning neutron from $NEUTRON_GIT $BranchName..."
        ExecuteWith-Retry {
            Run-GitClonePull "$openstackBuild\neutron" $NEUTRON_GIT $BranchName
        }
        Write-JujuLog "Cloning $NETWORKING_HYPERV_GIT from master..."
        ExecuteWith-Retry {
            Run-GitClonePull "$openstackBuild\networking-hyperv" $NETWORKING_HYPERV_GIT "master"
        }
    } elseif (($BuildFor -eq "openstack/neutron") -or ($BuildFor -eq "openstack/quantum")) {
        Write-JujuLog "Cloning $NOVA_GIT from $BranchName..."
        ExecuteWith-Retry {
            Run-GitClonePull "$openstackBuild\nova" $NOVA_GIT $BranchName
        }
        Write-JujuLog "Cloning $NETWORKING_HYPERV_GIT from master..."
        ExecuteWith-Retry {
            Run-GitClonePull "$openstackBuild\networking-hyperv" $NETWORKING_HYPERV_GIT "master"
        }
    } elseif ($buildFor -eq "stackforge/networking-hyperv") {
        Write-JujuLog "Cloning $NOVA_GIT from $BranchName..."
        ExecuteWith-Retry {
            Run-GitClonePull "$openstackBuild\nova" $NOVA_GIT $BranchName
        }
        Write-JujuLog "Cloning neutron from $NEUTRON_GIT $BranchName..."
        ExecuteWith-Retry {
            Run-GitClonePull "$openstackBuild\neutron" $NEUTRON_GIT $BranchName
        }
    } else {
        Throw "Cannot build for project: $BuildFor"
    }

    Write-JujuLog "Installing neutron..."
    ExecuteWith-Retry {
        Install-OpenStackProjectFromRepo "$openstackBuild\neutron"
    }
    if (!(Test-Path $NEUTRON_SERVICE_EXECUTABLE)) {
        Throw "$NEUTRON_SERVICE_EXECUTABLE was not found."
    }

    Write-JujuLog "Installing networking-hyperv..."
    ExecuteWith-Retry {
        Install-OpenStackProjectFromRepo "$openstackBuild\networking-hyperv"
    }

    Write-JujuLog "Installing nova..."
    ExecuteWith-Retry {
        Install-OpenStackProjectFromRepo "$openstackBuild\nova"
    }
    if (!(Test-Path $NOVA_SERVICE_EXECUTABLE)) {
        Throw "$NOVA_SERVICE_EXECUTABLE was not found."
    }

    Write-JujuLog "Copying default config files..."
    $defaultConfigFiles = @('rootwrap.d', 'api-paste.ini', 'cells.json',
                            'policy.json','rootwrap.conf')
    foreach ($config in $defaultConfigFiles) {
        Copy-Item -Recurse -Force "$openstackBuild\nova\etc\nova\$config" $CONFIG_DIR
    }
    Copy-Item -Force (Join-Path (Get-TemplatesDir) "interfaces.template") $CONFIG_DIR

    Write-JujuLog "Environment initialization done."
}


function Generate-ConfigFiles {
    Param(
        [string]$DevStackIP,
        [string]$DevStackPassword,
        [string]$RabbitUser
    )

    Write-JujuLog "Generating Nova config file"
    $novaTemplate = Join-Path (Get-TemplatesDir) "nova.conf"
    $configs = @{
        "instances_path"      = Join-Path $OPENSTACK_DIR "Instances";
        "interfaces_template" = Join-Path $CONFIG_DIR "interfaces.template";
        "policy_file"         = Join-Path $CONFIG_DIR "policy.json";
        "mkisofs_exe"         = Join-Path $BIN_DIR "mkisofs.exe";
        "devstack_ip"         = $DevStackIP;
        "rabbit_user"         = $RabbitUser;
        "rabbit_password"     = $DevStackPassword;
        "log_directory"       = $LOG_DIR;
        "qemu_img_exe"        = Join-Path $BIN_DIR "qemu-img.exe";
        "admin_password"      = $DevStackPassword;
        "vswitch_name"        = Get-JujuVMSwitchName
    }
    Render-ConfigFile -TemplatePath $novaTemplate `
                      -ConfPath $NOVA_SERVICE_CONFIG `
                      -Configs $configs

    Write-JujuLog "Generating Neutron config file"
    $neutronTemplate = Join-Path (Get-TemplatesDir) "neutron_hyperv_agent.conf"
    $configs = @{
        "policy_file"     = Join-Path $CONFIG_DIR "policy.json";
        "devstack_ip"     = $DevStackIP;
        "rabbit_user"     = $RabbitUser;
        "rabbit_password" = $DevStackPassword;
        "log_directory"   = $LOG_DIR;
        "admin_password"  = $DevStackPassword;
        "vswitch_name"    = Get-JujuVMSwitchName
    }
    Render-ConfigFile -TemplatePath $neutronTemplate `
                      -ConfPath $NEUTRON_SERVICE_CONFIG `
                      -Configs $configs
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

    Set-UserLogonAsServiceRights $ServiceUser

    $service.Change($null, $null, $null, $null, $null, $null, $ServiceUser, $ServicePassword)
}


function Create-OpenStackService {
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
        $downloadMirror = Get-JujuCharmConfig -scope "download-mirror"
        Invoke-WebRequest -Uri "$downloadMirror/$serviceFileName" `
                          -OutFile "$SERVICE_DIR\$serviceFileName"
    }

    New-Service -Name "$ServiceName" `
                -BinaryPathName "$SERVICE_DIR\$serviceFileName $ServiceName $ServiceExecutable --config-file $ServiceConfig" `
                -DisplayName "$ServiceName" `
                -Description "$ServiceDescription" `
                -StartupType "Manual"

    if((Get-Service -Name $ServiceName).Status -eq "Running") {
        Stop-Service $ServiceName
    }

    Set-ServiceAcountCredentials $ServiceName $ServiceUser $ServicePassword
}


function Poll-ServiceStatus {
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
    $VMswitchName = Get-JujuCharmConfig -scope "vmswitch-name"
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
    $DataInterfaceFromConfig = Get-JujuCharmConfig -scope $ConfigOption
    Write-JujuLog "Looking for $DataInterfaceFromConfig"
    if ($DataInterfaceFromConfig -eq $false -or $DataInterfaceFromConfig -eq "") {
        return $null
    }
    $byMac = @()
    $byName = @()
    $macregex = "^([a-f-A-F0-9]{2}:){5}([a-fA-F0-9]{2})$"
    foreach ($i in $DataInterfaceFromConfig.Split()) {
        if ($i -match $macregex) {
            $byMac += $i.Replace(":", "-")
        } else {
            $byName += $i
        }
    }
    Write-JujuLog "We have MAC: $byMac  Name: $byName"
    if ($byMac.Length -ne 0){
        $nicByMac = Get-NetAdapter | Where-Object { $_.MacAddress -in $byMac }
    }
    if ($byName.Length -ne 0){
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


function Configure-VMSwitch {
    $managementOS = Get-JujuCharmConfig -scope 'vmswitch-management'
    $VMswitchName = Get-JujuVMSwitchName

    try {
        $isConfigured = Get-VMSwitch -SwitchType External -Name $VMswitchName -ErrorAction SilentlyContinue
    } catch {
        $isConfigured = $false
    }

    if ($isConfigured) {
        return $true
    }
    $VMswitches = Get-VMSwitch -SwitchType External
    if ($VMswitches.Count -gt 0){
        Rename-VMSwitch $VMswitches[0] -NewName $VMswitchName
        return $true
    }

    $interfaces = Get-NetAdapter -Physical | Where-Object { $_.Status -eq "Up" }

    if ($interfaces.GetType().BaseType -ne [System.Array]){
        # we have ony one ethernet adapter. Going to use it for
        # vmswitch
        New-VMSwitch -Name $VMswitchName -NetAdapterName $interfaces.Name -AllowManagementOS $true
        if ($? -eq $false) {
            Throw "Failed to create vmswitch"
        }
    } else {
        Write-JujuLog "Trying to fetch data port from config"
        $nic = Get-InterfaceFromConfig -MustFindAdapter
        Write-JujuLog "Got NetAdapterName $nic"
        New-VMSwitch -Name $VMswitchName -NetAdapterName $nic[0].Name -AllowManagementOS $managementOS
        if ($? -eq $false){
            Throw "Failed to create vmswitch"
        }
    }
    $hasVM = Get-VM
    if ($hasVM){
        Connect-VMNetworkAdapter * -SwitchName $VMswitchName
        Start-VM *
    }
    return $true
}


function Add-UserToLocalAdminsGroup {
    Param(
        [string]$FQDN,
        [string]$Username
    )

    $ret = Execute-ExternalCommand {
        net.exe localgroup Administrators
    } -ErrorMessage "Failed to get local Administrators."
    $localAdmins = $ret[6..($ret.Length-3)]

    $isLocalAdmin = $false
    foreach ($localAdmin in $localAdmins) {
        $split = $localAdmin.Split("\")
        $domainName = $split[0]
        $user = $split[1]
        if (($FQDN -match $domainName) -and ($user -eq $UserName)) {
            $isLocalAdmin = $true
            break
        }
    }

    if (!$isLocalAdmin) {
        Execute-ExternalCommand {
            net.exe localgroup Administrators "$FQDN\$UserName" '/ADD'
        } -ErrorMessage "Failed to add user to local Administrators group."
    }
}


function Get-HostFromURL {
    Param(
        [string]$URL
    )

    $uri = [System.Uri]$URL
    return $uri.Host
}


function Install-FreeRDPConsole {
    Write-JujuLog "Installing FreeRDP..."

    $urlChecksum = Get-URLChecksum 'vc-2012-url' 'vc-2012-sha1'
    if (!$urlChecksum) {
        Install-Package $VC_2012_URL $VC_2012_SHA1 @('/q')
    } else {
        Install-Package $urlChecksum['URL'] $urlChecksum['SHA1_CHECKSUM'] @('/q')
    }

    $charmLibDir = Join-Path (Get-JujuCharmDir) "lib"
    $freeRDPZip = Join-Path $charmLibDir "FreeRDP_powershell.zip"
    Unzip-With7z $freeRDPZip $charmLibDir

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


function Generate-PipConfigFile {
    $wheelMirror = Get-JujuCharmConfig -scope 'wheel-mirror'
    $ppyMirror = Get-JujuCharmConfig -scope 'ppy-mirror'
    if (!$wheelMirror -and !$ppyMirror) {
        Write-JujuLog ("wheel-mirror option and ppy-mirror are not present. " +
                       "Will not generate the pip.ini file.")
        return
    }

    $pipDir = Join-Path $env:APPDATA "pip"
    if (!(Test-Path $pipDir)){
        mkdir $pipDir
    } else {
        Remove-Item -Force "$pipDir\*"
    }
    $pipIni = Join-Path $pipDir "pip.ini"
    New-Item -ItemType File $pipIni

    if ($ppyMirror) {
        Set-IniFileValue "index-url" "global" $ppyMirror $pipIni
    }

    if ($wheelMirror) {
        $wheelHost = Get-HostFromURL $wheelMirror
        Set-IniFileValue "trusted-host" "install" $wheelHost $pipIni
        Set-IniFileValue "find-links" "install" $wheelMirror $pipIni
    }
}


function Get-HypervADUser {
    $adUsername = Get-JujuCharmConfig -scope 'ad-user-name'
    if (!$adUsername) {
        $adUsername = "hyper-v-user"
    }
    return $adUsername
}


function Set-ADRelationParams {
    $hypervADUser = Get-HypervADUser
    $userGroup = @{
        $hypervADUser = @( )
    }
    $encUserGroup = Marshall-Object $userGroup
    $relationParams = @{
        'adusers' = $encUserGroup;
    }
    $ret = Set-JujuRelation -Relation_Settings $relationParams
    if ($ret -eq $false) {
       Write-JujuError "Failed to set AD relation parameters."
    }
}


function Set-CharmStatus {
    Param(
        [string]$Status
    )

    Execute-ExternalCommand {
        status-set.exe $Status
    } -ErrorMessage "Failed to set charm status to '$Status'."
}

function Set-DevStackRelationParams {
    Param(
        [HashTable]$RelationParams
    )

    $rids = Get-JujuRelationIds -RelType "devstack"
    foreach ($rid in $rids) {
        $ret = Set-JujuRelation -Relation_Id $rid -Relation_Settings $RelationParams
        if ($ret -eq $false) {
           Write-JujuError "Failed to set DevStack relation parameters."
        }
    }
}


# HOOKS FUNCTIONS

function Run-InstallHook {
    # Disable firewall
    Execute-ExternalCommand {
        netsh.exe advfirewall set allprofiles state off
    } -ErrorMessage "Failed to disable firewall."

    Configure-VMSwitch

    # Install Git
    $urlChecksum = Get-URLChecksum 'git-url' 'git-sha1'
    if (!$urlChecksum) {
        Install-Package $GIT_URL $GIT_SHA1 @('/SILENT')
    } else {
        Install-Package $urlChecksum['URL'] $urlChecksum['SHA1_CHECKSUM'] @('/SILENT')
    }
    AddTo-UserPath "${env:ProgramFiles(x86)}\Git\cmd"
    Renew-PSSessionPath

    # Install 7z
    $urlChecksum = Get-URLChecksum '7z-url' '7z-sha1'
    if (!$urlChecksum) {
        Install-Package $7Z_URL $7Z_SHA1 @('/S')
    } else {
        Install-Package $urlChecksum['URL'] $urlChecksum['SHA1_CHECKSUM'] @('/S')
    }
    AddTo-UserPath "${env:ProgramFiles(x86)}\7-Zip"
    Renew-PSSessionPath

    # Install Python 2.7.x (x86)
    $urlChecksum = Get-URLChecksum 'python27-url' 'python27-sha1'
    if (!$urlChecksum) {
        Install-Package $PYTHON27_URL $PYTHON27_SHA1 @('/qn')
    } else {
        Install-Package $urlChecksum['URL'] $urlChecksum['SHA1_CHECKSUM'] @('/qn')
    }
    AddTo-UserPath "${env:SystemDrive}\Python27;${env:SystemDrive}\Python27\scripts"
    Renew-PSSessionPath

    # Install FreeRDP Hyper-V console access
    $enableFreeRDP = Get-JujuCharmConfig -scope 'enable-freerdp-console'
    if ($enableFreeRDP -eq $true) {
        Install-FreeRDPConsole
    }

    # Install extra python packages
    Write-JujuLog "Installing pip dependencies..."
    Execute-ExternalCommand -Command { easy_install -U pip } `
                            -ErrorMessage "Failed to install pip."
    $pythonPkgs = Get-JujuCharmConfig -scope 'extra-python-packages'
    if ($pythonPkgs) {
        $pythonPkgsArr = $pythonPkgs.Split()
        foreach ($pythonPkg in $pythonPkgsArr) {
            Write-JujuLog "Installing $pythonPkg..."
            Execute-ExternalCommand -Command { pip install -U $pythonPkg } `
                                    -ErrorMessage "Failed to install $pythonPkg"
        }
    }

    # Install posix_ipc
    Write-JujuLog "Installing posix_ipc library..."
    $zipPath = Join-Path $LIB_DIR "posix_ipc.zip"
    $downloadMirror = Get-JujuCharmConfig -scope "download-mirror"
    Download-File -DownloadLink "$downloadMirror/posix_ipc.zip" `
                  -DestinationFile $zipPath
    Unzip-With7z $zipPath $LIB_DIR
    rm $zipPath

    # Generate pip.ini config file
    Generate-PipConfigFile

    Write-JujuLog "Installing pywin32..."
    Execute-ExternalCommand -Command { pip install pywin32 } `
                            -ErrorMessage "Failed to install pywin32."
    Execute-ExternalCommand {
        python "$PYTHON_DIR\Scripts\pywin32_postinstall.py" -install
    } -ErrorMessage "Failed to run pywin32_postinstall.py"

    Write-JujuLog "Running Git Prep..."
    $zuulUrl = Get-JujuCharmConfig -scope 'zuul-url'
    $zuulRef = Get-JujuCharmConfig -scope 'zuul-ref'
    $zuulChange = Get-JujuCharmConfig -scope 'zuul-change'
    $zuulProject = Get-JujuCharmConfig -scope 'zuul-project'
    $gerritSite = $zuulUrl.Trim('/p')
    Run-GerritGitPrep -ZuulUrl $zuulUrl `
                      -GerritSite $gerritSite `
                      -ZuulRef $zuulRef `
                      -ZuulChange $zuulChange `
                      -ZuulProject $zuulProject

    $gitEmail = Get-JujuCharmConfig -scope 'git-user-email'
    $gitName = Get-JujuCharmConfig -scope 'git-user-name'
    Execute-ExternalCommand { git config --global user.email $gitEmail } `
        -ErrorMessage "Failed to set git global user.email"
    Execute-ExternalCommand { git config --global user.name $gitName } `
        -ErrorMessage "Failed to set git global user.name"
    $zuulBranch = Get-JujuCharmConfig -scope 'zuul-branch'

    Write-JujuLog "Creating the Environment..."
    Create-Environment -BranchName $zuulBranch `
                       -BuildFor $zuulProject
}


function Run-ADRelationJoinedHook {
    Set-ADRelationParams
}


function Run-RelationHooks {
    Renew-PSSessionPath
    $adCtx = Get-ADContext

    if (!$adCtx["context"]) {
        Write-JujuLog "AD context is not ready."
    } else {
        if (!(Is-InDomain $adCtx["ad_domain"])) {
            ConnectTo-ADController $adCtx
            ExitFrom-JujuHook -WithReboot
        } else {
            Write-JujuLog "AD domain already joined."
        }

        $adUserCreds = Unmarshall-Object $adCtx["ad_credentials"]
        $adUser = $adUserCreds.PSObject.Properties.Name
        $adUserPassword = $adUserCreds.PSObject.Properties.Value
        $domainUser = $adCtx["ad_domain"] + "\" + $adUser

        $adUserCred = @{
            'domain'   = $adCtx["ad_domain"];
            'username' = $adUser;
            'password' = $adUserPassword
        }
        $encADUserCred = Marshall-Object $adUserCred
        $relationParams = @{ 'ad_credentials' = $encADUserCred; }
        Set-DevStackRelationParams $relationParams

        # Add AD user to local Administrators group
        Add-UserToLocalAdminsGroup $adCtx["ad_domain"] $adUser

        Create-OpenStackService $NOVA_SERVICE_NAME $NOVA_SERVICE_DESCRIPTION `
                      $NOVA_SERVICE_EXECUTABLE $NOVA_SERVICE_CONFIG `
                      $domainUser $adUserPassword
        Create-OpenStackService $NEUTRON_SERVICE_NAME $NEUTRON_SERVICE_DESCRIPTION `
                      $NEUTRON_SERVICE_EXECUTABLE $NEUTRON_SERVICE_CONFIG `
                      $domainUser $adUserPassword
    }

    $devstackCtx = Get-DevStackContext
    if (!$devstackCtx['context']) {
        Write-JujuLog ("DevStack context is not ready. Will not generate config files.")
    } else {
        Generate-ConfigFiles -DevStackIP $devstackCtx['devstack_ip'] `
                             -DevStackPassword $devstackCtx['devstack_password'] `
                             -RabbitUser $devstackCtx['rabbit_user']
    }

    if (!$devstackCtx['context'] -or !$adCtx['context']) {
        Write-JujuLog ("AD context and DevStack context must be complete " +
                       "before starting the OpenStack services.")
    } else {
        Write-JujuLog "Starting OpenStack services..."

        Write-JujuLog "Starting $NOVA_SERVICE_NAME service"
        Start-Service -ServiceName $NOVA_SERVICE_NAME
        Write-JujuLog "Polling $NOVA_SERVICE_NAME service status for 60 seconds."
        Poll-ServiceStatus $NOVA_SERVICE_NAME -IntervalSeconds 60

        Write-JujuLog "Starting $NEUTRON_SERVICE_NAME service"
        Start-Service -ServiceName $NEUTRON_SERVICE_NAME
        Write-JujuLog "Polling $NEUTRON_SERVICE_NAME service status for 60 seconds."
        Poll-ServiceStatus $NEUTRON_SERVICE_NAME -IntervalSeconds 60

        Start-Service "MSiSCSI"

        Set-CharmStatus "active"
    }
}


Export-ModuleMember -Function Run-InstallHook
Export-ModuleMember -Function Run-ADRelationJoinedHook
Export-ModuleMember -Function Run-RelationHooks
