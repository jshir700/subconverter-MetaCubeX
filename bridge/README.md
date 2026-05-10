# Mihomo Go Parser Bridge for subconverter-MetaCubeX

This bridge enables subconverter-MetaCubeX to use mihomo's native Go parser for
parsing proxy subscription links. This ensures 100% compatibility with mihomo's
protocol support, including XHTTP, VLESS encryption, and any future protocols.

## Architecture

```
subconverter (C++)  --[CGo]-->  bridge/converter.go  --[mihomo]-->  JSON output
                                     |
                                     v
                              mihomo library
                           (libmihomo.so or .a)
```

The C++ side calls `ConvertSubscription()` via CGo, which passes subscription
data to mihomo's `ConvertsV2Ray` function. The parsed nodes are returned as
JSON, then converted to C++ ProxyNode structs.

## Build Modes

Two build modes are supported:

### 1. Shared Library (.so) - Default (for Alpine/musl)

```bash
cd bridge
./build.sh          # or: ./build.sh so
```

Produces `libmihomo.so` (c-shared). Recommended for Alpine Docker images where
Go runtime has issues with static linking.

### 2. Static Library (.a) - (for glibc/Debian)

```bash
cd bridge
./build.sh static   # or: ./build.sh a
```

Produces `libmihomo.a` (c-archive). Suitable for glibc-based systems like
Debian/Ubuntu.

## Build Dependencies

- Go 1.21+
- C/C++ compiler (gcc/clang)

## How It Works

1. **Go Bridge** (`converter.go`):
   - Exports `ConvertSubscription(char* data) -> char*` via CGo
   - Calls mihomo's `constant.ConvertsV2Ray()` to parse subscription data
   - Returns JSON array of parsed nodes with all parameters
   - Exports `FreeString()` to release C strings

2. **C++ Bridge** (`mihomo_bridge.cpp`):
   - Calls the Go `ConvertSubscription()` function
   - Parses JSON response into `mihomo::ProxyNode` structs
   - Provides `isMihomoParserAvailable()` for runtime detection

3. **Integration**:
   - `nodemanip.cpp`: Uses mihomo parser when `USE_MIHOMO_PARSER` is defined
   - Falls back to legacy C++ parser if mihomo parser fails
   - Smart link routing detects subscription vs single node links

4. **Output** (`subexport.cpp`):
   - RawParams pass-through outputs all mihomo params directly
   - param_compat.h prevents overriding mihomo's hardcoded defaults

## Supported Protocols

All protocols supported by mihomo, including:
hysteria, hysteria2, hy2, tuic, trojan, vless, vmess, ss, ssr,
socks, socks5, socks5h, http, https, anytls, mierus

## Version Tracking

Update `go.mod` to track the latest mihomo release:

```bash
cd bridge
go get github.com/metacubex/mihomo@latest
```
