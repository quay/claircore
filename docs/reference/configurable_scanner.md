# ConfigurableScanner
A ConfigurableSanner is an optional interface a Scanner interface may implement.
When implemented, the scanner's Configure method will be called with a ConfigDeserializer function.
The Scanner may pass its config as an argument to the ConfigDeserializer function to populate the struct.

```go
package indexer

// ConfigDeserializer can be thought of as an Unmarshal function with the byte
// slice provided.
//
// This will typically be something like (*json.Decoder).Decode.
type ConfigDeserializer func(interface{}) error

// ConfigurableScanner is an interface scanners can implement to receive
// configuration.
type ConfigurableScanner interface {
	Configure(context.Context, ConfigDeserializer) error
}
```
