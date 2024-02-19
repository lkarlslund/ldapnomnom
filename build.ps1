function BuildVariants {
  param (
    $builder,
    $ldflags,
    $compileflags,
    $prefix,
    $arch,
    $os,
    $path
  )

  foreach ($currentarch in $arch) {
    foreach ($currentos in $os) {
      $env:GOARCH = $currentarch
      $env:GOOS = $currentos

      # More sensible naming for x64
      $namearch = $currentarch
      if ($namearch -eq "amd64") {
        $namearch = "x64"
      }

      $outputfile = "binaries/$prefix-$currentos-$namearch"
      if ($currentos -eq "windows") {
        $outputfile += ".exe"
      }
      go build -ldflags "$ldflags" -o $outputfile $compileflags $path

      $outputfile = "binaries/$prefix-$currentos-$namearch-obfuscated"
      if ($currentos -eq "windows") {
        $outputfile += ".exe"
      }
      garble -seed=random -tiny -literals build -ldflags "$ldflags" -o $outputfile $compileflags $path

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

$env:GOGARBLE="github.com/lkarlslund"
