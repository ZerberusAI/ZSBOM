package main

/*
#include <stdlib.h>
*/
import "C"
import (
    "context"
    "encoding/json"
    "fmt"
    "strings"
    "unsafe"

    scalibr "github.com/google/osv-scalibr"
    "github.com/google/osv-scalibr/plugin"
    pl "github.com/google/osv-scalibr/plugin/list"
    "github.com/google/osv-scalibr/fs"
    "github.com/google/osv-scalibr/extractor/filesystem"
    "github.com/google/osv-scalibr/extractor/standalone"
    "github.com/google/osv-scalibr/detector"
    "github.com/google/osv-scalibr/enricher"
    "github.com/google/osv-scalibr/annotator"
)

// ScanConfig represents the simplified configuration for a scan
type ScanConfig struct {
    Root     string   `json:"root"`
    Plugins  []string `json:"plugins"`
    Mode     string   `json:"mode"`
}

// PluginInfo represents information about a plugin
type PluginInfo struct {
    Name         string `json:"name"`
    Requirements string `json:"requirements"`
    Type         string `json:"type"`
}

//export GetAllPlugins
func GetAllPlugins() *C.char {
    allPlugins := pl.All()
    var plugins []PluginInfo

    for _, p := range allPlugins {
        requirements := ""
        if req := p.Requirements(); req != nil {
            if req.OS != plugin.OSAny {
                requirements += fmt.Sprintf("OS:%v,", req.OS)
            }
            if req.Network != plugin.NetworkAny {
                requirements += fmt.Sprintf("Network:%v,", req.Network)
            }
            if req.DirectFS {
                requirements += "DirectFS:true,"
            }
        }

        pluginType := "unknown"
        switch p.(type) {
        case filesystem.Extractor:
            pluginType = "filesystem_extractor"
        case standalone.Extractor:
            pluginType = "standalone_extractor"
        case detector.Detector:
            pluginType = "detector"
        case enricher.Enricher:
            pluginType = "enricher"
        case annotator.Annotator:
            pluginType = "annotator"
        }

        plugins = append(plugins, PluginInfo{
            Name:         p.Name(),
            Requirements: strings.TrimSuffix(requirements, ","),
            Type:         pluginType,
        })
    }

    jsonData, _ := json.Marshal(plugins)
    return C.CString(string(jsonData))
}

// getCapabilitiesFromMode converts mode string to plugin capabilities
func getCapabilitiesFromMode(mode string) *plugin.Capabilities {
    switch mode {
    case "offline":
        return &plugin.Capabilities{
            Network:  plugin.NetworkOffline,
            OS:       plugin.OSAny,
            DirectFS: true,
        }
    case "online":
        return &plugin.Capabilities{
            Network:  plugin.NetworkOnline,
            OS:       plugin.OSAny,
            DirectFS: true,
        }
    default: // "auto" or any other value
        return &plugin.Capabilities{
            Network:  plugin.NetworkAny,
            OS:       plugin.OSAny,
            DirectFS: true,
        }
    }
}

//export Scan
func Scan(root *C.char, pluginsJSON *C.char, mode *C.char) *C.char {
    rootPath := C.GoString(root)
    pluginList := []string{}
    capMode := C.GoString(mode)

    // Parse plugins if provided
    if pluginsJSON != nil {
        pluginStr := C.GoString(pluginsJSON)
        if pluginStr != "" {
            err := json.Unmarshal([]byte(pluginStr), &pluginList)
            if err != nil {
                errResp := map[string]string{"error": fmt.Sprintf("Failed to parse plugins: %v", err)}
                errJSON, _ := json.Marshal(errResp)
                return C.CString(string(errJSON))
            }
        }
    }

    // Get capabilities based on mode
    capabilities := getCapabilitiesFromMode(capMode)

    // Get plugins from names or use default
    var plugins []plugin.Plugin
    var err error

    if len(pluginList) > 0 {
        // Use specified plugins
        plugins, err = pl.FromNames(pluginList)
        if err != nil {
            errResp := map[string]string{"error": fmt.Sprintf("Failed to resolve plugins: %v", err)}
            errJSON, _ := json.Marshal(errResp)
            return C.CString(string(errJSON))
        }
    } else {
        // Use default plugins based on capabilities
        plugins = pl.FromCapabilities(capabilities)
    }

    // Create scan configuration
    scanConfig := &scalibr.ScanConfig{
        ScanRoots:    fs.RealFSScanRoots(rootPath),
        Capabilities: capabilities,
        Plugins:      plugins,
    }

    // Run scan
    ctx := context.Background()
    scanner := scalibr.New()
    result := scanner.Scan(ctx, scanConfig)

    // Convert results to JSON
    jsonData, err := json.Marshal(result)
    if err != nil {
        errResp := map[string]string{"error": fmt.Sprintf("Failed to marshal results: %v", err)}
        errJSON, _ := json.Marshal(errResp)
        return C.CString(string(errJSON))
    }

    return C.CString(string(jsonData))
}

//export ScanDirectory
func ScanDirectory(path *C.char) *C.char {
    // Scan with default plugins and auto mode
    return Scan(path, nil, C.CString("auto"))
}

//export GetPluginAliases
func GetPluginAliases() *C.char {
    // Common plugin aliases that users can specify
    aliases := map[string]string{
        "python":           "Python language extractors and artifact parsers",
        "java":             "Java language extractors (Maven, Gradle) and JAR parsers",
        "javascript":       "JavaScript/Node.js extractors (npm, yarn, pnpm)",
        "go":               "Go language extractors (go.mod, binaries)",
        "rust":             "Rust extractors (Cargo.toml, cargo-auditable)",
        "ruby":             "Ruby extractors (Gemfile, gemspec)",
        "php":              "PHP extractors (composer.lock)",
        "dotnet":           "C#/.NET extractors (deps.json, packages.config)",
        "cpp":              "C++ extractors (conan.lock)",
        "swift":            "Swift extractors (Package.resolved)",
        "dart":             "Dart extractors (pubspec.yaml)",
        "os":               "Operating system package managers (dpkg, rpm, apk)",
        "containers":       "Container image extractors (Docker, containerd)",
        "secrets":          "Secret detection",
        "sbom":             "SBOM file parsers (CycloneDX, SPDX)",
        "extractors/all":   "All available extractors",
        "extractors/default": "Default recommended extractors",
        "enrichers/all":    "All enrichers (vulnerability matching, licenses)",
        "annotators/all":   "All annotators (VEX generation, metadata)",
        "all":              "All plugins (extractors, detectors, enrichers, annotators)",
        "default":          "Default recommended plugins",
    }

    jsonData, _ := json.Marshal(aliases)
    return C.CString(string(jsonData))
}

//export FreeString
func FreeString(str *C.char) {
    C.free(unsafe.Pointer(str))
}

func main() {}