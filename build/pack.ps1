param([string] $v)

if (!$v)
{
    $version = '1.0.3-prerelease1.' + $([System.DateTime]::Now.ToString('MM-dd-HHmmss'))
}
else{
	$version = $v
}
Write-Host 'Version: ' $version 
get-childitem * -include *.nupkg | remove-item
dotnet build ..\src\NetDevPack.Security.JwtSigningCredentials.sln
dotnet test ..\src\NetDevPack.Security.JwtSigningCredentials.sln
dotnet pack ..\src\NetDevPack.Security.JwtSigningCredentials.sln -o .\ -p:PackageVersion=$version