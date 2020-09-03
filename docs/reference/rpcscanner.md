# RPCScanner
RPCScanner is an optional interface a Scanner may implement.
When implemented, the scanner's Configure method will be called with a ConfigDeserializer function and an http client.
The Scanner may pass its config as an argument to the ConfigDeserializer function to populate the struct and use the http client for any remote access necessary during the scanning process.

```go
package indexer

// ConfigDeserializer can be thought of as an Unmarshal function with the byte
// slice provided.
//
// This will typically be something like (*json.Decoder).Decode.
type ConfigDeserializer func(interface{}) error

// RPCScanner is an interface scanners can implement to receive configuration
// and denote that they expect to be able to talk to the network at run time.
type RPCScanner interface {
	Configure(context.Context, ConfigDeserializer, *http.Client) error
}
```
