// Package httpreader implements [io.ReaderAt] over an [http.Client] for a
// resource that implements HTTP Range requests ([RFC7233]). Various tricks are
// implemented to maximize compatibility.
//
// # Tricks
//
//   - Only use GET requests, to allow for locked-down signed requests.
//   - Request last byte to negate weird CDN caching.
//   - Try multiple ways to get the resource size.
//
// # Handled weirdness
//
//   - Server not handling negative ranges correctly.
//   - Server not reporting content length when making Range requests.
//   - "200 OK" for a range starting at 0.
//
// [RFC7233]: https://datatracker.ietf.org/doc/html/rfc7233
package httpreader
