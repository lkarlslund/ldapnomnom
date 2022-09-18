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
      go build -ldflags "$ldflags" -o binaries/$prefix-$currentos-$currentarch-$VERSION$suffix.exe $compileflags $path
      if (Get-Command "cyclonedx-gomod" -ErrorAction SilentlyContinue)
      {
        cyclonedx-gomod app -json -licenses -output binaries/$prefix-$currentos-$currentarch-$VERSION$suffix.bom.json -main $path .
      }
    }
  }
}

Set-Location $PSScriptRoot

$COMMIT = git rev-parse --short HEAD
$VERSION = git describe --tags --exclude latest
$DIRTYFILES = git status --porcelain

if ("$DIRTYFILES" -ne "") {
  $VERSION = "$VERSION-local-changes"
}

# Release
BuildVariants -ldflags "$LDFLAGS -s" -prefix ldapnomnom -path . -arch @("386", "amd64", "arm64") -os @("windows", "darwin", "linux")
