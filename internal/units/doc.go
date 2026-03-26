// Package units provides a common spot for [OTel units].
//
// Units should follow the [Unified Code for Units of Measure] (UCUM).
//
//   - Instruments for utilization metrics (that measure the fraction out of a
//     total) are dimensionless and SHOULD use the default unit 1 (the unity).
//   - All non-units that use curly braces to annotate a quantity need to match
//     the grammatical number of the quantity it represent. For example, if
//     measuring the number of individual requests to a process the unit would be
//     "{request}", not "{requests}".
//   - Instruments that measure an integer count of something SHOULD only use
//     annotations with curly braces to give additional meaning without the
//     leading default unit (1). For example, use "{packet}", "{error}",
//     "{fault}", etc.
//   - Instrument units other than 1 and those that use annotations SHOULD be
//     specified using the UCUM case sensitive ("c/s") variant. For example, "Cel"
//     for the unit with full name "degree Celsius".
//   - Instruments SHOULD use non-prefixed units (i.e. "By" instead of "MiBy")
//     unless there is good technical reason to not do so.
//   - When instruments are measuring durations, seconds (i.e. "s") SHOULD be
//     used.
//
// [Unified Code for Units of Measure]: https://ucum.org/ucum
// [OTel units]: https://opentelemetry.io/docs/specs/semconv/general/metrics/#instrument-units
package units
