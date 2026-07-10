// Package version exposes build metadata for gateway binaries.
package version

// These values may be replaced at build time with -ldflags -X.
var (
	Version   = "dev"
	Commit    = "unknown"
	BuildTime = "unknown"
)

// Info is the stable, machine-readable build metadata contract.
type Info struct {
	Version   string `json:"version"`
	Commit    string `json:"commit"`
	BuildTime string `json:"build_time"`
}

// Current returns the metadata embedded in the running binary.
func Current() Info {
	return Info{
		Version:   Version,
		Commit:    Commit,
		BuildTime: BuildTime,
	}
}
