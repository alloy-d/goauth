// Copyright 2009 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package oauth

func shouldEscape(c byte) bool {
	switch {
	case c >= 0x41 && c <= 0x5A:
		return false
	case c >= 0x61 && c <= 0x7A:
		return false
	case c >= 0x30 && c <= 0x39:
		return false
	case c == '-', c == '.', c == '_', c == '~':
		return false
	}
	return true
}

//Performs percent-encoding as specified by RFC 5849.
//
//Can be reversed with http.URLUnescape.
func PercentEncode(s string) string {
	spaceCount, hexCount := 0, 0
	for i := 0; i < len(s); i++ {
		c := s[i]
		if shouldEscape(c) {
			hexCount++
		}
	}

	if spaceCount == 0 && hexCount == 0 {
		return s
	}

	t := make([]byte, len(s)+2*hexCount)
	j := 0
	for i := 0; i < len(s); i++ {
		switch c := s[i]; {
		case shouldEscape(c):
			t[j] = '%'
			t[j+1] = "0123456789ABCDEF"[c>>4]
			t[j+2] = "0123456789ABCDEF"[c&15]
			j += 3
		default:
			t[j] = s[i]
			j++
		}
	}
	return string(t)
}
