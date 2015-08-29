##
## Script created by Jeff Yana, August 6 2015, for Standard Vision LLC
##
## What this script does:  
## On an existing Windows 2012 Server (R2) previously been promoted to Domain Controller and     
## hosting a valid Windows 2102 Domain/Forest with supporting DNS services, this script does the following: 
## adds the additional role of DHCP server; adds and configures all necessary networking (including a Teamed (virtual) interface) 
## adds and configures the missing PTR (reverse) zone and select A and PTR Resource Records.
## 
## This script will also add any number of users and groups the administrator prefers, but typically adds, via  
## user-directed input, a common set of users and groups consistent across a typical Standard Vision customer site.
##
## Additional configuration tasks:
##
## System Requirements: It is assumed that the subject server has been previously promoted to the role of domain controller either  
## manually using the Windows Server Essential 2012 Configuration Wizard (on Windows 2012 Essential systems), or DCPROMO mechanism on  
## Windows Server Standard or Enterprise. The preferred and supported and tested method is by using the custom created Powershell script ( titled "start_wss_config_service") 
## especially create for Standard Vision.
## 


##
## REQUIRED FIXES:
## 
## - Add a Scope Option for DNS Servers for DHCP
##
##

##
## TO DO:
## 
## - Add domain admin (xxx_admin) to custom Server Administrators, Network Administrators & Systems groups
## - Add logic to aggregate multiple group-adds when setting up new users using, for example, a comma separated list
## - Add A Records for all switches and network devices, players etc. Have a manual method to add them during initial setup instead of hard-coded. Same for PTR records.
## - Put the DHCP role add into a loop
## - Add additional A, PTR and alias DNS records (for devices that cannot join the domain,ex. mail, ccs-idrac, player1-idrac, player2-idrac, ups1, ups2 ... )
## - Automate setup of clocks, 1 clock for local time and the other for Los Angeles Time
## - Open ports firewall 8000-8002 for FSSO, In and Out
## - Add Telnet Client
##

Import-Module ActiveDirectory
Import-Module NetAdapter

####################################################################################
## (( BEGIN )) DEFINE FUNCTIONS ####################################################
####################################################################################

Function Password-Check{

    param(
        [string]$pwd = $(throw "Please specify password"),
        [int]$minLength=12,
        [int]$numUpper = 2,
        [int]$numLower = 2,
        [int]$numNumbers = 2, 
        [int]$numSpecial = 2
    )

    $upper = [regex]"[A-Z]"
    $lower = [regex]"[a-z]"
    $number = [regex]"[0-9]"
    #Special is "none of the above"
    $special = [regex]"[^a-zA-Z0-9]"

    # Check the length.
    if($pwd.length -lt $minLength) {$false; return}

    # Check for minimum number of occurrences.
    if($upper.Matches($pwd).Count -lt $numUpper ) {$false; return}
    if($lower.Matches($pwd).Count -lt $numLower ) {$false; return}
    if($number.Matches($pwd).Count -lt $numNumbers ) {$false; return}
    if($special.Matches($pwd).Count -lt $numSpecial ) {$false; return}

    # Passed all checks.
    $true
}

#################################################################################### 
## (( END )) DEFINE FUNCTIONS ######################################################
#################################################################################### 

#################################################################################### 
## (( BEGIN )) DEFINE VARIABLES ####################################################
#################################################################################### 

####################################################################################
# >>>>>>>>>>>>>>>>>>>>>>>>> Dynamically Assigned Variables <<<<<<<<<<<<<<<<<<<<<<<<<
####################################################################################

Clear-Host

Write-Host
Write-Host Preparing to setup the new system. We need to collect some information first . . .
Write-Host

Start-Sleep -s 2

#del Variable:\projCode
$projCode = Read-Host "`nPlease enter the Project Code for this install/site. `nExample: 1301"
Write-Host
Write-Host 'You selected:' $projCode

#del Variable:\fullNetID
$netID = Read-Host "`nPlease enter the IPv4 **Network Number** of your LAN. `nExample: 10.1.nn"
$fullNetID = $netID + '.0/25'
Write-Host
Write-Host 'You selected:' $fullNetID

#del Variable:\IPv4addr
$IPv4addr = Read-Host "`nPlease enter the IPv4 **Network Address** of this host. `nExample: $netID.nn"
Write-Host
Write-Host 'You selected:' $IPv4addr

#del Variable:\subnetMask
$subnetMask = Read-Host "`nPlease enter the **Subnet Mask** for network address: $IPv4addr. `nExample: 255.255.255.nnn"
Write-Host
Write-Host 'You selected:' $subnetMask

#del Variable:\router
$router = Read-Host "`nPlease enter the IPv4 **Gateway Address**. `nExample: $netID.1"
Write-Host
Write-Host 'You selected:' $router

#del Variable:\scopeID
$scopeID = Read-Host "`nThis systems will be shortly be promoted to the role of DHCP server.`n`nPlease enter the desired **DHCP Scope** for this server. `nExample: $netID.0"
Write-Host
Write-Host 'You selected:' $scopeID

#del Variable:\dhcpStart
$dhcpStart = Read-Host "`nPlease enter the **Starting** DHCP IP Address for Scope ID $scopeID.`nExample: $netID.nn"
Write-Host
Write-Host 'You selected:' $dhcpStart

#del Variable:\dhcpEnd
$dhcpEnd = Read-Host "`nPlease enter the **Ending** DHCP IP Address for scope ID $scopeID.`nExample: $netID.nnn"
Write-Host
Write-Host 'You selected:' $dhcpEnd

#del Variable:\rDnsPrefix
$rDnsPrefix = Read-Host "`nPlease enter the **Reverse DNS Zone Prefix**.`nExample: nn.1.10"
Write-Host
Write-Host You entered: $rDnsPrefix

#del Variable:\lan01
$lan01 = Read-Host "`nPlease enter the IPv4 Address for Lan01.`nExample: 10.1.NN.2"
Write-Host
Write-Host You entered: $lan01

####################################################################################
# >>>>>>>>>>>>>>>>>>>>>>>>>> Statically Assigned Variables <<<<<<<<<<<<<<<<<<<<<<<<<
####################################################################################

$DomainName = -join ("domain",$projCode)
$allGroups = @()
$newUserOU = -join ("OU=Users,","OU=",$projCode,",","DC=",$DomainName,",","DC=lan")
$newGroupOU = -join ("OU=Groups,","OU=",$projCode,",","DC=",$DomainName,",","DC=lan")
$newCompOU = -join ("OU=Computers,","OU=",$projCode,",","DC=",$DomainName,",","DC=lan")
$rootDN = -join ("DC=",$DomainName,",","DC=lan")
$DnsSuffix = -join ($DomainName,".","lan")
$DnsDomain = -join (".",$DomainName,".","lan")
$OU = -join ("OU=",$projCode,",")
$fullDN = $OU += $rootDN
$dhcpServerName = -join ("CCS-", $projCode)
$DhcpServerFQDN = $dhcpServerName += $DnsDomain
$GTWYFQDN = -join ("gw",".",$DomainName,".","lan")
$LAN01FQDN = -join ("lan01",".",$DomainName,".","lan")
$rDnsSuffix = '.in-addr.arpa'
$revDnsZone = $rDnsPrefix
$revDnsZone += $rDnsSuffix
$gw = $router
$mySearchBase = $fullDN

## Network Variables
#$netadapter = Get-NetAdapter -Name Team1

#################################################################################### 
## (( END )) DEFINE VARIABLES ######################################################
#################################################################################### 

####################################################################################
# >>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>> Create New OUs <<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<
####################################################################################

Clear-Host

Write-Host
Write-Host Please standby, creating new Organizational Units from newly inputted user data . . .
Write-Host

Start-Sleep -s 1

NEW-ADOrganizationalUnit -Name $projCode -Path $rootDN  
NEW-ADOrganizationalUnit -Name Groups -Path $fullDN 
NEW-ADOrganizationalUnit -Name Users -Path $fullDN
NEW-ADOrganizationalUnit -Name Computers -Path $fullDN 

Start-Sleep -s 2

Write-Host
Write-Host . . . done . . .
Write-Host

####################################################################################
# >>>>>>>>>>>>>>>>>>>>>>>>>>> Define New Security Groups <<<<<<<<<<<<<<<<<<<<<<<<<<<
####################################################################################

Clear-Host

Write-Host
Write-Host Define new Security Groups . . .
Write-Host

Start-Sleep -s 1

## Create empty array, populate with user input below

$allGroups = @()

while(($inp = Read-Host -Prompt "Would you like to create new Security Groups for Domain ** $DomainName ** `n`nEnter 'Y' to Continue or 'N' to Exit.") -ne "N"){
switch($inp){
   Y {Write-Host Preparing ... 
   
        Write-Host ""
        
        $allGroups += Read-Host -prompt "`nPlease Enter the Name of the new Security Group.`nExample: Server Administrator.  Do NOT use quotes!"
        
        Write-Host ""
        Write-Host You entered: $allGroups   
        Write-Host ""        
          
   }
   #A {"Reserved for Future Options"}
   #B {"Reserved for Future Options"}
   N {"End"}
   default {Write-Host 'Invalid entry. Please try again.'}
   }
}

Start-Sleep -s 2

Write-Host
Write-Host . . . done . . .
Write-Host

####################################################################################
# >>>>>>>>>>>>>>>>>>>>>>>>>>> Create New Security Groups <<<<<<<<<<<<<<<<<<<<<<<<<<<
####################################################################################

Clear-Host

Start-Sleep -s 1

Write-Host
Write-Host Applying changes, creating new Security Groups
Write-Host

## Loop through the $allGroups array, create new groups

	foreach ($i in $allGroups) {
		New-ADGroup -Path $newGroupOU -Name $i -GroupScope Global
	}

Start-Sleep -s 2

Write-Host
Write-Host . . . done . . .
Write-Host

####################################################################################
# >>>>>>>>>>>>>>>>>>>>>>>>>>> Define & Create New Users <<<<<<<<<<<<<<<<<<<<<<<<<<<
####################################################################################

Clear-Host

Start-Sleep -s 1

while(($inp = Read-Host -Prompt "Would You Like to Create a NEW USER?`n`nEnter 'Y' to Continue or 'N' to Exit and commit any unsaved changes.") -ne "N"){
switch($inp){
   Y {Write-Host `nCollecting important user information ... 
        
        $strDisplayName = Read-Host "`n Please Enter the 'Full Name' of the user (no quotes). Example: Joe Smith"
        Write-Host "`n   You entered:" $strDisplayName
		Write-Host

        $strUserName = Read-Host "Please Enter 'Log On' Name for the new user. Example: jsmith"
        Write-Host "`n   You entered:" $strUserName
        
        $strPassword = Read-Host "`nPlease Enter a COMPLEX PASSWORD.  A complex password consists of: `n`n   - A minimum length of 12 apha-numeric characters `n   - 2 upper case letters`n   - 1 lower case letters`n   - 2 numbers`n   - 2 special characters`n`n"
        
        "`nPassword '{0}'meets complexity requirements: {1}" -f $strPassword,(Password-Check $strPassword)
        
        Write-Host
        $pwdTest = $strPassword,(Password-Check $strPassword)
        
        #Write-Host
        #Write-Host $pwdTest         
         
		if ($pwdTest -eq "True" ) {"Password is valid ... Please re-enter Complex Password `n"
        
        Start-Sleep -s 1
        
        # Create Domain User Account
        New-ADUser -Name $strUserName -UserPrincipalName $strUserName@$DnsSuffix -DisplayName $strDisplayName -Enabled $true -AccountPassword (Read-Host -AsSecureString $strPassword) -CannotChangePassword 1 -PasswordNeverExpires 1 -Path $newUserOU 
        
        Write-Host Please wait, adding new user ...

        Start-Sleep -s 2

}
          
   }
   #A {"Reserved for Future Options"}
   #B {"Reserved for Future Options"}
   N {"End"}
   default {Write-Host 'Invalid entry. Please try again.'}
   }
}

Write-Host ""
Write-Host . . . done . . .
Write-Host ""

####################################################################################
# >>>>>>>>>>>>>>>>>>>>>>>>>> Add New Users to New Groups <<<<<<<<<<<<<<<<<<<<<<<<<<<
####################################################################################

Clear-Host

Start-Sleep -s 1

Write-Host
while(($inp = Read-Host -Prompt "Would you Like to add USERS to one or more GROUPS?`n`n   Enter 'Y' to Continue or 'N' to Exit and commit any unsaved changes") -ne "N") {
switch($inp){

	###
	#### < ========== First Locate Existing Groups ========== >
	###

    Y{  Write-Host
        Write-Host "   Please Wait ... "
        Start-Sleep -s 1
        Write-Host
        Write-Host "   Locating Security Groups from domain ** $DomainName ** within Organization Unit: $MySearchBase"
        Write-Host

        Start-Sleep -s 3
        
        	Clear-Host

			Get-ADGroup -Filter * -SearchBase $mySearchBase |  Format-Table Name

	        $myGSelection = Read-Host "To continue, please select the desired Security Group from one the following 'Groups' (left column). No quotes."
	        Write-Host ""
	        Write-Host You selected: ** $myGSelection **

	        Start-Sleep -s 2

	###
	#### < ========== Next, Locate Existing Users ========== >
	####

        Clear-Host
        
        Write-Host
        Write-Host "   Searching for existing users under OU:" $MySearchBase ...

	    Start-Sleep -s 2

	    ## Get a list of all AD Users under specified Search Base
        
	    Get-AdUser -SearchBase $MySearchBase -Filter * -Properties Name | FT Name,samAccountName

	    $myUSelection = Read-Host `n"Please select the USER you would like to add to GROUP ** $myGSelection **. Choose either 'Name' or 'Log-In' (samAccountName)."

	    Write-Host
	    Write-Host "  You selected user: **" $myUSelection **
	    Write-Host
	    Start-Sleep -s 2
	    Write-Host ... Adding User: $myUSelection to Group: $myGSelection
	    Write-Host

	    ## Add AD User to AD Group
	    Add-ADGroupMember -identity $myGSelection -members $myUSelection

	    #$Error

   }
   #A {"Reserved for Future Options"}
   #B {"Reserved for Future Options"}
   N {"End"}
   default {Write-Host 'Invalid entry. Please try again.'}
   }
}

Write-Host
Write-Host . . . done . . .
Write-Host

####################################################################################
# >>>>>>>>>>>>>>>>>>>>>>>>>>>>> Setup Teamed Interface <<<<<<<<<<<<<<<<<<<<<<<<<<<<<
####################################################################################

Clear-Host

Start-Sleep -s 1

while(($inp = Read-Host -Prompt "Would You Like to setup NIC Teaming on your available, on-board network interfaces?`n`nEnter 'Y' to Continue or 'N' to Exit.") -ne "N"){
switch($inp){
   			Y 	{
				New-NetLbfoTeam -Name Team1 -TeamMembers NIC1,NIC2 -TeamingMode SwitchIndependent

				Write-Host
				Write-Host . . . done . . .
				Write-Host

				Write-Host
				Write-Host Configure Team1 Interface
				Write-Host 

				Set-NetIPInterface -InterfaceAlias Team1 -dhcp Disabled
				New-NetIPAddress -InterfaceAlias Team1 -AddressFamily IPV4 -IPaddress $IPv4addr -PrefixLength 25 -Type Unicast -DefaultGateway $router
				Set-DnsClientServerAddress -InterfaceAlias Team1 -ServerAddresses 127.0.0.1
				Set-DnsClientGlobalSetting -SuffixSearchList $DnsSuffix
				
				Start-Sleep -s 2
 				}
				#A {"Reserved for Future Options"}
	   			#B {"Reserved for Future Options"}
	   			N {"End"}
	   			default {Write-Host 'Invalid entry. Please try again.'}
	   			}
	}


Write-Host
Write-Host . . . done . . .
Write-Host

####################################################################################
# >>>>>>>>>>>>>>>>>>>>>>>> Add DHCP Server Role & Configure <<<<<<<<<<<<<<<<<<<<<<<<
####################################################################################

Write-Host
Write-Host Adding DHCP Server Role, Please Wait . . .
Write-Host

Add-WindowsFeature -IncludeManagementTools DHCP

Write-Host
Write-Host Restarting DHCP Server, Please Wait . . .
Write-Host

restart-service dhcpserver

Write-Host
Write-Host Resuming DHCP Server Setup, Please Wait . . .
Write-Host 

#Add-DhcpServerInDC $dhcpServerName $IPv4addr
#Set-ItemProperty -Path registry::HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\ -Name ConfigurationState -Value 2
#netsh dhcp add securitygroups
#Add-DhcpServerv4Scope -Name Production -Description "Production Network" -LeaseDuration 1:00:00:00 -StartRange $dhcpStart -EndRange $dhcpEnd -SubnetMask 255.255.255.128
#Set-DhcpServerV4DnsSetting -ComputerName $DhcpServerFQDN -DeleteDnsRROnLeaseExpiry 1 -DisableDnsPtrRRUpdate 1 -ScopeID $scopeID -DynamicUpdates OnClientRequest
#Set-DhcpServerV4OptionValue -ComputerName $DhcpServerFQDN -DnsDomain $DnsSuffix -DnsServer $IPv4addr -Router $router -ScopeID $scopeID

####################################################################################
# >>>>>>>>>>>>>>>>>>>>>>>>> Enable Terminal Services & RDP <<<<<<<<<<<<<<<<<<<<<<<<
####################################################################################

Clear-Host
Write-Host

while(($inp = Read-Host -Prompt "Would you Like to setup Remote Access for Admin Users?`n`n   Enter 'Y' to Continue or 'Q' to Quit and Commit Changes.") -ne "Q"){
switch($inp){

    Y{  

    Write-Host
    Write-Host "   Enabling Remote Desktop Terminal Services"
    Write-Host

    set-ItemProperty -Path 'HKLM:\System\CurrentControlSet\Control\Terminal Server'-name "fDenyTSConnections" -Value 0
    Enable-NetFirewallRule -DisplayGroup "Remote Desktop"
    set-ItemProperty -Path 'HKLM:\System\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp' -name "UserAuthentication" -Value 1 

    }

   #A {"Reserved for Future Options"}
   #B {"Reserved for Future Options"}

   Q {"End"}

   default {Write-Host 'Invalid entry. Please try again.'}

   }
   }

Write-Host
Write-Host . . . done . . .
Write-Host  

####################################################################################
# >>>>>>>>>>>>>>>>>>>>>>> Add Reverse DNS Zone & A/PTR Records <<<<<<<<<<<<<<<<<<<<<
####################################################################################

Write-Host
Write-Host "Add Reverse DNS Zone and Populate with new A & PTR records"
Write-Host 

## Add Reverse DNS Zone

Add-DnsServerPrimaryZone -NetworkID $fullNetID -ReplicationScope Forest

## Add Forward "A" Records

Add-DnsServerResourceRecordCName -Name "dc1" -ZoneName $DnsSuffix -HostNameAlias $DhcpServerFQDN
Add-DnsServerResourceRecordA -Name "gw" -ZoneName $DnsSuffix -IPv4Address $router
Add-DnsServerResourceRecordA -Name "lan01" -ZoneName $DnsSuffix -IPv4Address $lan01

## Add Reverse "PTR" Records

Add-DnsServerResourceRecordPtr -Name "1" -ZoneName $revDnsZone -PtrDomainName $GTWYFQDN
Add-DnsServerResourceRecordPtr -Name "2" -ZoneName $revDnsZone -PtrDomainName $LAN01FQDN


Write-Host 
Write-Host . . . Server Setup Complete . . .
Write-Host 
