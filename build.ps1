function BuildVariants {
  param (
    $ldflags,
    $compileflags,
    $prefix,
    $suffix,
    $arch,
    $os,
    $path
  )

  foreach ($currentarch in $arch) {
    foreach ($currentos in $os) {
      $env:GOARCH = $currentarch
      $env:GOOS = $currentos
      $outputfile = "binaries/$prefix-$currentos-$currentarch$suffix"
      if ($currentos -eq "windows") {
        $outputfile += ".exe"
      }
      go build -ldflags "$ldflags" -o $outputfile $compileflags $path
      if (Get-Command "cyclonedx-gomod" -ErrorAction SilentlyContinue)
      {
        cyclonedx-gomod app -json -licenses -output $outputfile.bom.json -main $path .
      }
    }
  }
}

Set-Location $PSScriptRoot

# Release
BuildVariants -ldflags "$LDFLAGS -s" -prefix ldapnomnom -path . -arch @("386", "amd64", "arm64") -os @("windows", "darwin", "linux")
