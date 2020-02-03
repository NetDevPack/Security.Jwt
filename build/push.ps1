param([string] $source = "../.nuget",
	  [switch] $prod)

if($prod)
{
	$source = "https://api.nuget.org/v3/index.json"
}

$files = Get-ChildItem -recurse -filter *.nupkg

foreach ($file in $files) {
	if($prod)
	{
		dotnet nuget push $file.Name -s $source
	}
	else
	{
		nuget add $file.Name -source $source
	}
}