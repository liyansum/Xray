package confloader

import (
	"io"
	"os"
)

type (
	configFileLoader func(string) (io.Reader, error)
)

var EffectiveConfigFileLoader configFileLoader

// LoadConfig reads from a local path or stdin. An optional module may replace
// EffectiveConfigFileLoader when another source is required.
func LoadConfig(file string) (io.Reader, error) {
	if EffectiveConfigFileLoader == nil {
		if file == "-" || file == "stdin:" {
			return os.Stdin, nil
		}
		return os.Open(file)
	}
	return EffectiveConfigFileLoader(file)
}
