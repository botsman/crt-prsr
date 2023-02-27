package plugin

import (
	"github.com/botsman/crt-prsr/prsr"
	"github.com/botsman/crt-prsr/prsr/crt"
	"testing"
)

func TestExamplePlugin(t *testing.T) {
	plugins := map[string]prsr.Plugin{
		"example": &ExamplePlugin{},
	}
	parser := prsr.NewParser([]crt.Id{}, plugins)
	cert, err := crt.LoadCertFromPath("../prsr/testdata/qwac.crt")
	if err != nil {
		t.Fatal(err)
	}
	result, err := parser.Parse(cert)
	if err != nil {
		t.Fatal(err)
	}
	if result.Plugins["example"] == nil {
		t.Fatal("plugin result should not be nil")
	}
	examplePluginResult := result.Plugins["example"].(*ExamplePluginResult)
	if examplePluginResult == nil {
		t.Fatal("examplePluginResult should not be nil")
	}
	if examplePluginResult.example != "example" {
		t.Fatal("examplePluginResult.Example should be 'example'")
	}
}
