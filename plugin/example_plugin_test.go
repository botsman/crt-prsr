package plugin

import (
	"github.com/botsman/crt-prsr/prsr"
	"github.com/botsman/crt-prsr/prsr/crt"
	"testing"
)

func TestExamplePlugin(t *testing.T) {
	plugins := []prsr.Plugin{
		&ExamplePlugin{},
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
	if result.Plugins[0] == nil {
		t.Fatal("plugin result should not be nil")
	}
	examplePluginResult := result.Plugins[0].(*ExamplePluginResult)
	if examplePluginResult == nil {
		t.Fatal("examplePluginResult should not be nil")
	}
	if examplePluginResult.example != "example" {
		t.Fatal("examplePluginResult.Example should be 'example'")
	}
}
