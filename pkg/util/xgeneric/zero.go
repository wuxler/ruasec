package xgeneric

// ZeroValue returns an empty value of the given type.
func ZeroValue[V any]() V {
	var zero V
	return zero
}
