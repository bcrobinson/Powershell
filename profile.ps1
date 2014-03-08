function Test-IsAdmin
{
    $identity = [System.Security.Principal.WindowsIdentity]::GetCurrent();
    $principal = New-Object Security.Principal.WindowsPrincipal -ArgumentList $identity
        
    Write-Output $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator);
}

function prompt
{

    if(Test-IsAdmin)
    {
        $pref = 'Administrator: ';
    }
    
    $host.UI.RawUI.WindowTitle = $pref + (Get-Location).Path;

    Write-Output ([datetime]::Now.ToString('s') + '>');
}