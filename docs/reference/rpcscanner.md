# RPCScanner
`RPCScanner` is an optional interface a `Scanner` may implement.
When implemented, the scanner's `Configure` method will be called with a
`ConfigDeserializer` function and an HTTP client.
The `Scanner` may pass its config as an argument to the `ConfigDeserializer`
function to populate the struct and use the HTTP client for any remote access
necessary during the scanning process.

{{# godoc internal/indexer.RPCScanner}}
{{# godoc internal/indexer.ConfigDeserializer}}
