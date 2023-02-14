package plugin

import (
	"fmt"
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

func (e *ExamplePluginResult) MarshalJSON() ([]byte, error) {
	return []byte(fmt.Sprintf(`{"example": "%s"}`, e.example)), nil
}
