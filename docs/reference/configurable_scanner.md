# ConfigurableScanner
A `ConfigurableSanner` is an optional interface a `Scanner` interface may
implement.  When implemented, the scanner's `Configure` method will be called
with a `ConfigDeserializer` function. The `Scanner` may pass its config as an
argument to the `ConfigDeserializer` function to populate the struct.

{{# godoc internal/indexer.ConfigDeserializer}}
{{# godoc internal/indexer.ConfigurableScanner}}
