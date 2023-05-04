# Resolver
A Resolver is used to analyze and modify the post-coalesced index report. This is useful for operations that need all context from an index report.

{{# godoc indexer.Resolver}}

Any Resolvers' `Resolve()` methods are called (in no set order) at the end of the coalesce step after reports from separate scanners are merged.
