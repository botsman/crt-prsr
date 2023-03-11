package plugin

import (
	"github.com/botsman/crt-prsr/prsr"
	"github.com/botsman/crt-prsr/prsr/crt"
)

type ExamplePlugin struct {
}

func (e *ExamplePlugin) Parse(c *crt.Certificate) prsr.PluginParseResult {
	return &ExamplePluginResult{
		example: "example",
	}
}

type ExamplePluginResult struct {
	example string
}
