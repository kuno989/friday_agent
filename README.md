# Friday virtualbox agent system <br/>
### Compiling on Mac
`env GOOS="windows" GOARCH="amd64" CGO_ENABLED="1" CC="x86_64-w64-mingw32-gcc" go build .`