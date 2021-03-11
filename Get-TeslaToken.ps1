[string]$AuthUri = "https://auth.tesla.com/oauth2/v3/authorize"
[string]$TokenUri = "https://auth.tesla.com/oauth2/v3/token"
[string]$ApiUri = "https://owner-api.teslamotors.com/oauth/token"
$CLIENT_ID = "81527cff06843c8634fdc09e8ac0abefb46ac849f38fe1e431c2ef2106796384"
$CLIENT_SECRET = "c7257eb71a564034f9419ee651c7d0e5f7aa6bfbd18bafb5c5c033b093bb2fa3"
if(!$Credential) { $Credential = Get-Credential }

function Get-TeslaAuthToken($Credential) {
    # Step 1
    if(!$CompletedStep) {  
        [string]$Code_verifier = -join ((65..90) + (97..122) | Get-Random -Count 86 | % {[char]$_})
        $Random_stream = [IO.MemoryStream]::new([byte[]][char[]]$Code_verifier)
        [string]$Random_hash = (Get-FileHash -InputStream $Random_stream -Algorithm SHA256).Hash
        $Random_bytes = [System.Text.Encoding]::Unicode.GetBytes($Random_hash)
        $Code_challenge = [Convert]::ToBase64String($Random_bytes)
        [string]$State = -join ((65..90) + (97..122) | Get-Random -Count 24 | % {[char]$_})
        $Header =  @{ 'Accept' = '*/*'; 'Accept-Encoding' = 'gzip,deflate' }
        $Body = @{
            'client_id' = 'ownerapi'
            'code_challenge' = $Code_challenge 
            'code_challenge_method' = 'S256'
            'redirect_uri' = 'https://auth.tesla.com/void/callback'
            'response_type' = 'code'
            'scope' = 'openid email offline_access'
            'state' = $State 
            'login_hint' = $Credential.UserName
        }

        Write-Host Requesting first response -ForegroundColor Green
        $Response1 = Invoke-WebRequest -Uri $AuthUri -SessionVariable 'Session' -Headers $Header -Body $Body -Method Get -TimeoutSec 15 

        Write-Host Parsing first response -ForegroundColor Green
        $Cookie = $Response1.Headers.'Set-Cookie'
        $Hidden = $Response1.InputFields | Where-Object {$_.type -eq "hidden"} | select name,value
        $Hidden_Fields = @{}
        $Hidden | foreach { $Hidden_Fields[$_.name] = $_.value }
        if($Cookie -and $Hidden_Fields) { $CompletedStep = 1 } else { Write-Host Failed Step 1 -ForegroundColor Red }
    }

    # Step 2
    if($CompletedStep -eq 1) { 
        $Header =  @{ 'Accept' = '*/*'; 'Accept-Encoding' = 'gzip,deflate' }
        $Body = $Hidden_Fields
        $Body += @{
            'identity' = $Credential.UserName
            'credential' = $Credential.GetNetworkCredential().password
        }

        Write-Host Requesting second response -ForegroundColor Green
        try{ $Response2 = Invoke-WebRequest -Uri $AuthUri  -Body $Body -Method Post -ContentType 'application/x-www-form-urlencoded' -MaximumRedirection 0 -TimeoutSec 15 -Headers $Header -WebSession $Session }
        catch { $_.Exception.Message }    

        Write-Host Parsing second response -ForegroundColor Green    
        $Code = ($Response2.Headers.Location -split "=" -split "&")[1]
        if( $Response2.StatusCode -eq "302" -and $Code.Length -ge 1) { $CompletedStep = 2 } else { Write-Host Failed Step 2 -ForegroundColor Red }
    }

    # Step 3
    if($CompletedStep -eq 2) { 
        $Header =  @{ 'Accept' = '*/*'; 'Accept-Encoding' = 'gzip,deflate' }
        $Body = @{
            'grant_type' = 'authorization_code'
            'client_id' = 'ownerapi'
            'code' = $Code
            'code_verifier' = $Code_verifier
            'redirect_uri' = 'https://auth.tesla.com/void/callback'
        }

        Write-Host Requesting third response -ForegroundColor Green
        try{ $Response3 = Invoke-webrequest -Uri $TokenUri -Method Post -Body ($Body|ConvertTo-Json) -ContentType 'application/json' -MaximumRedirection 0 -TimeoutSec 15 -Headers $Header -WebSession $Session }
        catch { $_.Exception.Message }  

        Write-Host Parsing third response -ForegroundColor Green    
        $Content3 = $Response3.Content | convertfrom-json 
        $Access_Token = $Content3.access_token 
        if($Access_Token) { 
            $CompletedStep = 3 
            Write-Host Auth token successfully retrieved, exporting as AuthToken.xml to the current path -ForegroundColor Green
            $Content3 | Export-CliXML -Path ".\AuthToken.xml"
        } else { Write-Host Failed Step 3 -ForegroundColor Red }
    }
    if($CompletedStep -eq 3) { Return $Content3 }
}

function Get-TeslaApiToken($Access_Token) {
    # Step 4
    $Header =  @{ 'Authorization' = "Bearer $Access_Token"; 'Accept' = '*/*'; 'Accept-Encoding' = 'gzip,deflate' }
    $Body = @{
        'grant_type' = 'urn:ietf:params:oauth:grant-type:jwt-bearer'
        'client_id' = $CLIENT_ID
        'client_secret' = $CLIENT_SECRET
    }

    Write-Host Requesting API response -ForegroundColor Green
    try{
        $Response4 = Invoke-webrequest -Uri $ApiUri -Method Post -Body ($Body|ConvertTo-Json) -ContentType 'application/json' -MaximumRedirection 0 -TimeoutSec 15 -Headers $Header
    }
    catch {
        $_.Exception.Message
    }  

    Write-Host Parsing API response -ForegroundColor Green
    $Content4 = $Response4.Content | convertfrom-json 
    if($Content4.expires_in -eq 3888000) {
        Write-Host API token successfully retrieved, exporting as ApiToken.xml to the current path -ForegroundColor Green
        $Content4 | Export-CliXML -Path ".\ApiToken.xml"
        Return $Content4 
    } else { Write-Host Failed Step 4 -ForegroundColor Red }
}

function Refresh-TeslaAuthToken($Refresh_token) {
    $Header =  @{ 'Accept' = '*/*'; 'Accept-Encoding' = 'gzip,deflate' }
    $Body = @{
        'grant_type' = 'refresh_token'
        'client_id' = 'ownerapi'
        'refresh_token' = $Refresh_token
        'scope' = 'openid email offline_access'
    }

    Write-Host Requesting refresh response -ForegroundColor Green
    try{ $Response5 = Invoke-webrequest -Uri $TokenUri -Method Post -Body ($Body|ConvertTo-Json) -ContentType 'application/json' -MaximumRedirection 1 -TimeoutSec 15 -Headers $Header -WebSession $Session }
    catch { $_.Exception.Message }  

    Write-Host Parsing refresh response -ForegroundColor Green    
    $Content5 = $Response5.Content | convertfrom-json 
    $Access_Token = $Content5.access_token 
    if($Access_Token) { 
        Write-Host Auth token successfully retrieved, exporting as AuthToken.xml to the current path  -ForegroundColor Green
        $RefreshContent | Export-CliXML -Path ".\AuthToken.xml"
        Return $Content5
    }
}

$AuthToken = Get-TeslaAuthToken($Credential)
Get-TeslaApiToken($AuthToken.Access_Token)


# Refresh the API & Auth tokens using the previous Auth token
#$AuthToken = Import-CliXML -Path ".\AuthToken.xml"
#$AuthToken = Refresh-TeslaAuthToken($AuthToken.Refresh_Token)
#Get-TeslaApiToken($AuthToken.Access_Token)