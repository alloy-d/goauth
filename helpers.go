package oauth

import (
	"bytes"

	"io"
	"strings"
	"url"
)

func addQueryParams(url_ string, params map[string]string) string {
	str := url_

	first := true
	for k, v := range params {
		if first {
			str += "?"
			first = false
		} else {
			str += "&"
		}

		rawv, err := url.QueryUnescape(v)
		if err == nil {
			v = rawv
		}
		str += k + "=" + url.QueryEscape(v)
	}

	return str
}

// An annoying enough task that it gets its own function.
func bodyString(body io.Reader) string {
	buf := new(bytes.Buffer)
	buf.ReadFrom(body)
	return buf.String()
}

// This doesn't escape the keys as the spec requires,
// but I have yet to see a key that *needs* escaping.
func escapeParams(p map[string]string) {
	for k, v := range p {
		p[k] = PercentEncode(v)
	}
}

// Merge parameter maps into a single map, with entries in first taking
// precedence over entries in second.
//
// TODO: multiple values should be permissible (and, in fact, requests
// will currently fail if any parameter includes multiple values).
func mergeParams(first, second map[string]string) (all map[string]string) {
	all = make(map[string]string)

	for k2, v2 := range second {
		if _, there := first[k2]; !there {
			all[k2] = v2
		}
	}

	for k1, v1 := range first {
		all[k1] = v1
	}
	return
}

// Parse parameters from a string of the form "k1=v1&k2=v2" (and so on).
//
// TODO: parse multiple values if present.
func parseParams(body string) map[string]string {
	p := make(map[string]string)
	if body == "" {
		return p
	}
	var pairs []string
	if strings.LastIndex(body, "&") > 0 {
		pairs = strings.Split(body, "&")
	} else {
		pairs = []string{body}
	}
	for _, pair := range pairs {
		if strings.LastIndex(pair, "=") > 0 {
			kv := strings.SplitN(pair, "=", 2)
			p[kv[0]] = kv[1]
		} else {
			p[pair] = ""
		}
	}

	return p
}

func unescapeParams(p map[string]string) {
	for k, v := range p {
		uv, _ := url.QueryUnescape(v)
		p[k] = uv
	}
}
