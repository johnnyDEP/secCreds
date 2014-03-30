# This module is designed to secure embedded credentials so that they are encrypted.  
# Basically offloads security to NTFS permissions
#
#
# Tested with Powershell V3.0


function create-key{
    <#  
    .SYNOPSIS  
        Creates key for use with securestrings
    .DESCRIPTION  
        Generates a random array of values for a 256 bit AES key 
    .NOTES  

        Prerequisite   : PowerShell V3
        
    .SYNTAX 

    .EXAMPLE  
        create-key -outPutDir "C:\KeyTesting"
    	
    #>


    Param ([Parameter(Mandatory=$false)][string]$outPutDir)

    $key = [Convert]::ToBase64String((1..32 |% { [byte](Get-Random -Minimum 0 -Maximum 255) }))
    $acl = $null
    
    if($outPutDir -ne $null){
    	$outKey = $outPutDir + "\key.txt"
    	$key | Set-Content $outKey
      $acl = Get-Acl $outKey
       
      $isProtected = $true 
    	$preserveInheritance = $false
    	$acl.SetAccessRuleProtection($isProtected, $preserveInheritance)
        
        # Moving call to purge rules to *after* inheritance is turned off (so inheritance doesn't overwrite the purge).
        $acl.Access | %{$acl.PurgeAccessRules($_.IdentityReference)}

        $currentUser = [Environment]::UserDomainName + "\" + [Environment]::UserName

        $Ar = New-Object  system.security.accesscontrol.filesystemaccessrule($currentUser,"FullControl","Allow")
        $Acl.AddAccessRule($Ar)
        Set-Acl $outKey $Acl

        $debug = Get-Acl -Path $outKey
        Write-Debug $debug.Access
    }
    else {
    	return $key
    }
}

function encrypt-string{

<#  
.SYNOPSIS  
    Encrypts a string and outputs the cipher text to a directory
.DESCRIPTION  
    Uses the Dataprotection windows API to encrypt a string and outputs the string to cipher text in a desired directory
.NOTES  

    Prerequisite   : PowerShell V3
    
.SYNTAX 

.EXAMPLE  
    encrypt-string -sensitiveString "ed snowden long 43.021 lat -86.089" -outPutDir "C:\KeyTesting" -keyPath "C:\KeyTesting\key.txt"
	
#>

Param ([Parameter(Mandatory=$True)][string]$sensitiveString,
[Parameter(Mandatory=$True)][string]$keyPath,
[Parameter(Mandatory=$false)][string]$outPutDir)

$key = Get-Content -Path $keyPath

$encryptedSecret = ConvertTo-SecureString -AsPlainText -Force -String $sensitiveString | ConvertFrom-SecureString -Key ([Convert]::FromBase64String($key))  

$outCipher = $outPutDir + "\cipher.txt"

$encryptedSecret | Set-Content -Path $outCipher

}

function decrypt-string{

<#  

.SYNOPSIS  
    Decrypts a string and outputs the cipher text to a directory

.DESCRIPTION  
    Uses the Dataprotection windows API to decrypt a string and outputs the string to plain text, requires key and cipher text encrypted with that key as input

.NOTES  

    Prerequisite   : PowerShell V3
    
.SYNTAX 

.EXAMPLE  
    decrypt-string -keyPath "C:\KeyTesting\key.txt" -cipherPath "C:\KeyTesting\cipher.txt"
	
#>

Param ([Parameter(Mandatory=$True)][string]$keyPath,
[Parameter(Mandatory=$True)][string]$cipherPath,
[Parameter(Mandatory=$false)][string]$outPut)

$key = Get-Content -Path $keyPath

$secureString = ConvertTo-SecureString (Get-Content -Path $cipherPath) -Key ([Convert]::FromBase64String($key))  

$credentials = new-object System.Management.Automation.PsCredential("blank", $secureString)

$password = $credentials.GetNetworkCredential().Password

return $password

}

Export-ModuleMember decrypt-string
Export-ModuleMember create-key
Export-ModuleMember encrypt-string
