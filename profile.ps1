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

function Get-RelativePath
{
    [CmdletBinding()]
    param
    (
        [Parameter(Position=0, Mandatory=$True)]
        [string] $Root,
        
        [Parameter(Position=1, Mandatory=$True)]
        [string] $Path
    )
    
    $baseUri = [Uri](Resolve-Path $Root).Path;
    $relativeUri = [Uri](Resolve-Path $Path).Path;
    $relativeString = $baseUri.MakeRelative($relativeUri);

    Write-Output ('./' + $relativeString);
}

function Find-InFiles
{
    [CmdletBinding()]
    param
    (
        [Parameter(Position=0, Mandatory=$True)]
        [string] $Path,

        
        [Parameter(Position=1, Mandatory=$True)]
        [string] $Filter,
        
        [Parameter(Position=2, Mandatory=$True)]
        [string] $Match,
        
        [switch] $Recurse,
        [switch] $OutLines,
        [switch] $OutValues
    )
    
    Write-Verbose "Looking for $Match in $Filter files";

    $regex = new-object -TypeName System.Text.RegularExpressions.Regex -ArgumentList ($Match, [System.Text.RegularExpressions.RegexOptions]::IgnoreCase) ;
      
    $basePath = Resolve-Path $Path;

    Get-ChildItem -Path $Path -Filter $Filter -Recurse:$Recurse -File `
        | ForEach-Object {
            if(!$_.PSIsContainer -and (Test-Path $_.FullName))
            {
                Write-Verbose "Checking file $(Get-RelativePath $basePath $_.FullName)"; 

                try
                {
                    if($OutLines)
                    {
                        $lines = [IO.File]::ReadAllLines($_.FullName) | Where-Object {$regex.IsMatch($_)};
                            
                        if ($lines.Count -gt 0)
                        {
                            Write-Output ([pscustomobject]@{Path=$_.FullName; Lines=$lines});
                        }
                    }
                    elseif($OutValues)
                    {
                        $text = [IO.File]::ReadAllText($_.FullName);

                        $captures = $regex.Matches($text);
                        

                        if ($captures.Count -gt 0)
                        {
                            $values = $captures | ForEach-Object { @($_.Groups | ForEach-Object Value) };
                            Write-Output ([pscustomobject]@{Path=$_.FullName; Captures=$values});
                        }
                    }
                    else
                    {
                        if ([IO.File]::ReadAllText($_.FullName) -match $Match)
                        {
                            Write-Output $_;
                        }   
                    }
                }
                catch
                {}
            }
        } | Write-Output;
}

Set-Alias -Name pGrep -Value Find-InFiles;
