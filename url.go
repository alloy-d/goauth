// Copyright 2009 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package oauth

// This function lifted shamelessly from the http package and slightly
// modified.
func shouldEscape(c byte) bool {
    if c <= ' ' || c >= 0x7F {
        return true
    }
    switch c {
    case '<', '>', '#', '%', '"', // delims
        '{', '}', '|', '\\', '^', '[', ']', '`', // unwise
        ';', '/', '?', ':', '@', '&', '=', '+', '$', ',': // reserved
        return true
    }
    return false
}

/*
Performs percent-encoding as specified by RFC 5849.

Similar to http.URLEscape, except that this also encodes *all* values
listed as restricted in RFC 2396.  This also percent-encodes spaces,
rather than replacing them with '+'.  Hex values are upper-case.

Can be reversed with http.URLUnescape.
*/
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

    t := make([]byte, len(s) + 2*hexCount)
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
