// Copyright 2023 CUE Labs AG
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
//
// Modifications copyright (C) 2024 RuaSec Authors
//
// The file are copied from oci[github.com/cue-labs/oci], and we keep the original copyright
// and license above.
//
// We directly considered copying the code and made modifications to the code as needed because
// we didn't want to introduce additional dependencies.
// Thanks to the original author of the code!

// Package iter provides iterator functions for iterating over.
package iter

// TODO(go1.23) when we can depend on Go 1.23, this should be:
// type Iterator[T any] = iter.Seq2[T, error]

// Seq defines the type of an iterator sequence returned from
// the iterator functions. In general, a non-nil
// error means that the item is the last in the sequence.
type Seq[T any] func(yield func(T, error) bool)

// All returns all items from the iterator sequence.
func All[T any](it Seq[T]) (_ []T, _err error) {
	xs := []T{}
	// TODO(go1.23) for x, err := range it
	it(func(x T, err error) bool {
		if err != nil {
			_err = err
			return false
		}
		xs = append(xs, x)
		return true
	})
	return xs, _err
}

// SliceSeq returns an iterator that yields the items in the given slice.
func SliceSeq[T any](xs []T) Seq[T] {
	return func(yield func(T, error) bool) {
		for _, x := range xs {
			if !yield(x, nil) {
				return
			}
		}
	}
}

// ErrorSeq returns an iterator that has no items and always returns the given error.
func ErrorSeq[T any](err error) Seq[T] {
	return func(yield func(T, error) bool) {
		yield(*new(T), err)
	}
}
