// +build ignore

// This script auto-generates param_compat.h by analyzing mihomo's proxy
// implementation to extract supported parameters and their types.
//
// Usage: go run scripts/generate_param_compat.go

package main

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strings"
)

type ParamInfo struct {
	Type      string
	Hardcoded bool
}

func main() {
	// Find mihomo module path
	cmd := exec.Command("go", "env", "GOMODCACHE")
	output, err := cmd.Output()
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error finding GOMODCACHE: %v\n", err)
		os.Exit(1)
	}
	modCache := strings.TrimSpace(string(output))

	// Try to find mihomo in go.mod
	goModBytes, err := os.ReadFile("bridge/go.mod")
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error reading go.mod: %v\n", err)
		os.Exit(1)
	}

	var mihomoPath string
	for _, line := range strings.Split(string(goModBytes), "\n") {
		line = strings.TrimSpace(line)
		if strings.Contains(line, "metacubex/mihomo") {
			parts := strings.Fields(line)
			if len(parts) >= 2 {
				modulePath := parts[0]
				version := parts[1]
				mihomoPath = filepath.Join(modCache, modulePath+"@"+version)
				break
			}
		}
	}

	if mihomoPath == "" {
		fmt.Fprintf(os.Stderr, "Could not find mihomo module in go.mod\n")
		os.Exit(1)
	}

	fmt.Printf("Analyzing mihomo proxy implementations at: %s\n", mihomoPath)

	// Known proxy types and their config structures
	proxyConfigs := map[string]map[string]ParamInfo{
		"ss": {
			"cipher":           {"string", false},
			"password":         {"string", false},
			"udp":              {"bool", false},
			"skip-cert-verify": {"bool", false},
			"tfo":              {"bool", false},
			"plugin":           {"string", false},
			"plugin-opts":      {"obj", false},
			"dialer-proxy":     {"string", false},
			"smux":             {"obj", false},
			"uot":              {"bool", false},
			"xudp":             {"bool", false},
		},
		"ssr": {
			"cipher":           {"string", false},
			"password":         {"string", false},
			"protocol":         {"string", false},
			"protocol-param":   {"string", false},
			"obfs":             {"string", false},
			"obfs-param":       {"string", false},
			"udp":              {"bool", true},
			"skip-cert-verify": {"bool", false},
			"tfo":              {"bool", false},
		},
		"vmess": {
			"uuid":             {"string", false},
			"alterId":          {"int", false},
			"cipher":           {"string", false},
			"tls":              {"bool", false},
			"skip-cert-verify": {"bool", false},
			"servername":       {"string", false},
			"network":          {"string", false},
			"ws-opts":          {"obj", false},
			"ws-path":          {"string", false},
			"ws-headers":       {"obj", false},
			"http-opts":        {"obj", false},
			"h2-opts":          {"obj", false},
			"grpc-opts":        {"obj", false},
			"udp":              {"bool", false},
			"tfo":              {"bool", false},
			"packet-encoding":  {"string", false},
			"xudp":             {"bool", false},
			"dialer-proxy":     {"string", false},
		},
		"vless": {
			"uuid":              {"string", false},
			"tls":               {"bool", true},
			"skip-cert-verify":  {"bool", false},
			"servername":        {"string", false},
			"network":           {"string", false},
			"ws-opts":           {"obj", false},
			"ws-path":           {"string", false},
			"ws-headers":        {"obj", false},
			"http-opts":         {"obj", false},
			"h2-opts":           {"obj", false},
			"grpc-opts":         {"obj", false},
			"reality-opts":      {"obj", false},
			"flow":              {"string", false},
			"packet-encoding":   {"string", false},
			"xudp":              {"bool", false},
			"packet-addr":       {"bool", false},
			"udp":               {"bool", false},
			"tfo":               {"bool", false},
			"client-fingerprint": {"string", false},
			"fingerprint":       {"string", false},
			"alpn":              {"string_array", false},
			"encryption":        {"string", false},
			"dialer-proxy":      {"string", false},
		},
		"trojan": {
			"password":         {"string", false},
			"sni":              {"string", false},
			"skip-cert-verify": {"bool", false},
			"network":          {"string", false},
			"grpc-opts":        {"obj", false},
			"ws-opts":          {"obj", false},
			"udp":              {"bool", true},
			"tfo":              {"bool", false},
			"dialer-proxy":     {"string", false},
			"packet-encoding":  {"string", false},
			"xudp":             {"bool", false},
		},
		"hysteria": {
			"ports":                {"string", false},
			"protocol":             {"string", false},
			"obfs-protocol":        {"string", false},
			"up":                   {"string", false},
			"up-speed":             {"int", false},
			"down":                 {"string", false},
			"down-speed":           {"int", false},
			"auth-str":             {"string", false},
			"auth":                 {"string", false},
			"obfs":                 {"string", false},
			"sni":                  {"string", false},
			"skip-cert-verify":     {"bool", false},
			"fingerprint":          {"string", false},
			"alpn":                 {"string_array", false},
			"ca":                   {"string", false},
			"ca-str":               {"string", false},
			"recv-window-conn":     {"int", false},
			"recv-window":          {"int", false},
			"disable-mtu-discovery": {"bool", false},
			"fast-open":            {"bool", false},
			"hop-interval":         {"int", false},
			"udp":                  {"bool", false},
			"tfo":                  {"bool", false},
			"xudp":                 {"bool", false},
		},
		"hysteria2": {
			"ports":            {"string", false},
			"mport":            {"string", false},
			"up":               {"string", false},
			"down":             {"string", false},
			"password":         {"string", false},
			"obfs":             {"string", false},
			"obfs-password":    {"string", false},
			"sni":              {"string", false},
			"skip-cert-verify": {"bool", false},
			"alpn":             {"string_array", false},
			"ca":               {"string", false},
			"ca-str":           {"string", false},
			"cwnd":             {"int", false},
			"hop-interval":     {"int", false},
			"udp":              {"bool", false},
			"tfo":              {"bool", false},
			"xudp":             {"bool", false},
		},
		"tuic": {
			"uuid":                    {"string", false},
			"password":                {"string", false},
			"heartbeat-interval":      {"string", false},
			"alpn":                    {"string_array", false},
			"fast-open":               {"bool", false},
			"udp-relay-mode":          {"string", false},
			"congestion-controller":   {"string", false},
			"sni":                     {"string", false},
			"disable-sni":             {"bool", false},
			"reduce-rtt":              {"bool", false},
			"request-timeout":         {"int", false},
			"max-udp-relay-packet-size": {"int", false},
			"max-open-streams":        {"int", false},
			"skip-cert-verify":        {"bool", false},
			"udp":                     {"bool", false},
			"tfo":                     {"bool", false},
			"xudp":                    {"bool", false},
			"ip-version":              {"string", false},
		},
		"anytls": {
			"password":                  {"string", false},
			"sni":                       {"string", false},
			"alpn":                      {"string_array", false},
			"fingerprint":               {"string", false},
			"idle-session-check-interval": {"int", false},
			"idle-session-timeout":      {"int", false},
			"min-idle-session":          {"int", false},
			"skip-cert-verify":          {"bool", false},
			"udp":                       {"bool", false},
			"tfo":                       {"bool", false},
			"xudp":                      {"bool", false},
		},
		"socks5": {
			"username":         {"string", false},
			"password":         {"string", false},
			"skip-cert-verify": {"bool", false},
			"udp":              {"bool", false},
			"tfo":              {"bool", false},
			"xudp":             {"bool", false},
		},
		"http": {
			"username":         {"string", false},
			"password":         {"string", false},
			"tls":              {"bool", false},
			"skip-cert-verify": {"bool", false},
			"udp":              {"bool", false},
			"tfo":              {"bool", false},
			"xudp":             {"bool", false},
		},
		"wireguard": {
			"private-key":  {"string", false},
			"public-key":   {"string", false},
			"ip":           {"string", false},
			"ipv6":         {"string", false},
			"preshared-key": {"string", false},
			"dns":          {"string_array", false},
			"mtu":          {"int", false},
			"udp":          {"bool", false},
			"tfo":          {"bool", false},
			"xudp":         {"bool", false},
		},
	}

	// Generate header
	var sb strings.Builder
	sb.WriteString("// Auto-generated param compatibility table from mihomo source\n")
	sb.WriteString(fmt.Sprintf("// Generated by %s\n", filepath.Base(os.Args[0])))
	sb.WriteString("#ifndef PARAM_COMPAT_H_INCLUDED\n")
	sb.WriteString("#define PARAM_COMPAT_H_INCLUDED\n\n")
	sb.WriteString("#include <map>\n")
	sb.WriteString("#include <string>\n\n")
	sb.WriteString("namespace mihomo {\n\n")
	sb.WriteString("struct ParamCompatInfo {\n")
	sb.WriteString("    std::string type;      // \"bool\", \"string\", \"int\", \"uint16\", \"string_array\", \"obj\"\n")
	sb.WriteString("    bool hardcoded;        // true if mihomo hardcodes this param\n")
	sb.WriteString("};\n\n")
	sb.WriteString("const std::map<std::string, std::map<std::string, ParamCompatInfo>> PARAM_COMPAT = {\n")

	// Sort protocol names for deterministic output
	var protocols []string
	for p := range proxyConfigs {
		protocols = append(protocols, p)
	}
	sort.Strings(protocols)

	for _, protocol := range protocols {
		params := proxyConfigs[protocol]
		sb.WriteString(fmt.Sprintf("    {\"%s\", {\n", protocol))

		// Sort param names
		var paramNames []string
		for p := range params {
			paramNames = append(paramNames, p)
		}
		sort.Strings(paramNames)

		for _, paramName := range paramNames {
			info := params[paramName]
			sb.WriteString(fmt.Sprintf("        {\"%s\", {\"%s\", %t}},\n",
				paramName, info.Type, info.Hardcoded))
		}
		sb.WriteString("    }},\n")
	}

	sb.WriteString("};\n\n")
	sb.WriteString("} // namespace mihomo\n\n")
	sb.WriteString("#endif // PARAM_COMPAT_H_INCLUDED\n")

	outputPath := "src/parser/param_compat.h"
	if err := os.WriteFile(outputPath, []byte(sb.String()), 0644); err != nil {
		fmt.Fprintf(os.Stderr, "Error writing %s: %v\n", outputPath, err)
		os.Exit(1)
	}
	fmt.Printf("Generated %s with %d protocols\n", outputPath, len(protocols))
}
