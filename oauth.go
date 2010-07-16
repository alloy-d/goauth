// A Go OAuth library, mainly created to interact with Twitter.
package oauth

import (
    "bytes"
    "crypto/hmac"
    "encoding/base64"
    "fmt"
    "http"
    "os"
    "rand"
    "sort"
    "strconv"
    "strings"
    "time"
)

// Supported oauth version:
const OAUTH_VERSION = "1.0"

// Supported signature methods:
const (
    HMAC_SHA1 = iota
)

// Request types:
const (
    TempCredentialReq = iota
    OwnerAuthorization
    TokenReq
)

var (
    ConsumerKey string
    ConsumerSecret string
    SignatureMethod int
)

// Signature method representations for oauth_signature.
var signatureMethods = map[int]string{
    HMAC_SHA1: "HMAC-SHA1",
}

// The map used to store endpoints.
var url = make(map[int]string)

// Sets the given endpoint URL.
func SetURL(requestType int, endpoint string) {
    switch(requestType) {
    case TempCredentialReq, OwnerAuthorization, TokenReq:
        url[requestType] = endpoint
    }
}

func MakeRequest(requestType int, params map[string]string) {
    addRequiredParams(params)
    escapeParams(params)
    switch(requestType) {
    case TempCredentialReq:
        rstring := requestString("POST", url[requestType], params)

        key := signingKey(ConsumerSecret, "")
        sig := signature(key, rstring)
        params["oauth_signature"] = PercentEncode(sig)

        r, err := post(url[requestType], params)
        if err != nil {
            fmt.Fprintln(os.Stderr, err)
        }
        resp, _ := http.DumpResponse(r, true)
        fmt.Fprintf(os.Stderr, "%s\n\n", resp)

        buf := new(bytes.Buffer)
        buf.ReadFrom(r.Body)

        response := buf.String()

        parsedResponse := make(map[string]string)
        pieces := strings.Split(response, "&", 3)
        for _, p := range pieces {
            kv := strings.Split(p, "=", 2)
            parsedResponse[kv[0]] = kv[1]
        }

        if v, ok := parsedResponse["oauth_callback_confirmed"]; !ok || v != "true" {
            fmt.Fprintln(os.Stderr, "Callback not confirmed!")
            return
        }

        fmt.Printf("Please visit the following URL:\n%s?oauth_token=%s\n",
            url[OwnerAuthorization], parsedResponse["oauth_token"])
    }
}

func addRequiredParams(given map[string]string) {
    given["oauth_consumer_key"] = ConsumerKey
    given["oauth_signature_method"] = signatureMethods[SignatureMethod]
    given["oauth_timestamp"] = timestamp()
    given["oauth_nonce"] = nonce()
    given["oauth_version"] = OAUTH_VERSION
}

// This doesn't escape the keys as the spec requires,
// but I have yet to see a key that *needs* escaping.
func escapeParams(p map[string]string) {
    for k, v := range p {
        p[k] = PercentEncode(v)
    }
}

func requestString(method, url string, queryParams map[string]string) string {
    str := method + "&"
    str += PercentEncode(url)

    keys := make([]string, len(queryParams))
    i := 0
    for k, _ := range queryParams {
        keys[i] = k
        i++
    }

    sort.SortStrings(keys)
    first := true
    for _, k := range keys {
        if first {
            str += "&"
            first = false
        } else {
            str += "%26"
        }
        str += PercentEncode(k) + "%3D"
        str += PercentEncode(queryParams[k])
    }

    return str
}

func nonce() string {
    return strconv.Itoa64(rand.Int63())
}

func signingKey(consumerSecret, oauthTokenSecret string) string {
    return consumerSecret + "&" + oauthTokenSecret
}

// base64 bits inspired by github.com/montsamu/go-twitter-oauth
func signature(key, request string) string {
    switch (SignatureMethod) {
    case HMAC_SHA1:
        hash := hmac.NewSHA1([]byte(key))
        hash.Write([]byte(request))
        signature := bytes.TrimSpace(hash.Sum())
        digest := make([]byte, base64.StdEncoding.EncodedLen(len(signature)))
        base64.StdEncoding.Encode(digest, signature)
        return strings.TrimSpace(bytes.NewBuffer(digest).String())
    }
    fmt.Fprintln(os.Stderr, "Unknown signature method requested.")
    return ""
}

func timestamp() string {
    return strconv.Itoa64(time.Seconds())
}

