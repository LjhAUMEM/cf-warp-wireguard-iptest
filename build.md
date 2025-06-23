$env:CGO_ENABLED=0
$env:GOOS="linux"
$env:GOARCH="amd64"
go build -trimpath -ldflags="-s -w" -o bin/warp

$env:CGO_ENABLED=0
$env:GOOS="linux"
$env:GOARCH="arm64"
go build -trimpath -ldflags="-s -w" -o bin/warp-arm64

$env:CGO_ENABLED=0
$env:GOOS="windows"
$env:GOARCH="amd64"
go build -trimpath -ldflags="-s -w" -o bin/warp.exe
