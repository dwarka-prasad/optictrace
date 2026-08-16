module github.com/dwarka-prasad/optictrace-example-memstore

go 1.25.0

require github.com/dwarka-prasad/optictrace v0.0.0

// A separate module on purpose, and deliberately NOT under the
// github.com/dwarka-prasad/optictrace/... path prefix. Go's internal rule is
// prefix-based, so an examples/ module sharing that prefix could still import
// internal/ and would prove nothing. Under this path it genuinely cannot —
// the same position a commercial optictrace-pro module is in.
//
// The replace points at the checkout so the example tracks the working tree.
replace github.com/dwarka-prasad/optictrace => ../..
