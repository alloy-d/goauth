// A Go OAuth library, mainly created to interact with Twitter.
package oauth

import (
    "bytes"
    "crypto/hmac"
    "encoding/base64"
    "fmt"
    "http"
    "log"
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

type OAuth struct {
    ConsumerKey string
    ConsumerSecret string
    SignatureMethod int

    Callback string

    RequestTokenURL string
    OwnerAuthURL string
    AccessTokenURL string

    requestToken string
    requestSecret string

    verifier string

    userName string
    userId int
    accessToken string
    accessSecret string
}

// Signature method representations for oauth_signature.
var signatureMethods = map[int]string{
    HMAC_SHA1: "HMAC-SHA1",
}

func (o *OAuth) GetTempCredentials() (err os.Error) {
    params := o.params()
    params["oauth_callback"] = o.Callback
    escapeParams(params)

    signature := o.sign(baseString("POST", o.RequestTokenURL, params))

    params["oauth_signature"] = PercentEncode(signature)

    resp, err := post(o.RequestTokenURL, params)
    if err != nil {
        return
    }
    err = o.parseResponse(resp, TempCredentialReq)
    return
}

func (o *OAuth) AuthorizationURL() (string, os.Error) {
    if o.requestToken == "" || o.requestSecret == "" {
        return "", &DanceError{
            What: "attempt to get authorization without credentials",
            Where: "OAuth:AuthorizationURL()",
        }
    }

    url := o.OwnerAuthURL + "?oauth_token=" + o.requestToken
    return url, nil
}

func (o *OAuth) parseResponse(resp *http.Response, requestType int) os.Error {
    dump, _ := http.DumpResponse(resp, true)
    fmt.Fprintf(os.Stderr, "%s\n", dump)
    buf := new(bytes.Buffer)
    buf.ReadFrom(resp.Body)
    r := buf.String()
    resp.Body.Close()

    if resp.StatusCode == 401 {
        return &DanceError{
            What: r,
            Where: fmt.Sprintf("parseResponse(requestType=%d)", requestType),
        }
    }

    parts := strings.Split(r, "&", -1)
    params := make(map[string]string)
    for _, part := range parts {
        kv := strings.Split(part, "=", 2)
        params[kv[0]] = kv[1]
    }

    switch(requestType) {
    case TempCredentialReq:
        o.requestToken = params["oauth_token"]
        o.requestSecret = params["oauth_token_secret"]
        if confirmed, ok := params["oauth_calback_confirmed"]; !ok ||
            confirmed != "true" {
            return &CallbackError{o.Callback}
        }
    case TokenReq:
        o.accessToken = params["oauth_token"]
        o.accessSecret = params["oauth_token_secret"]
    default:
        return &ImplementationError{
            What: "requestType=" + strconv.Itoa(requestType),
            Where: "OAuth:parseResponse()",
        }
    }
    return nil
}

func (o *OAuth) addRequiredParams(given map[string]string) {
    given["oauth_consumer_key"] = o.ConsumerKey
    given["oauth_signature_method"] = signatureMethods[o.SignatureMethod]
    given["oauth_timestamp"] = timestamp()
    given["oauth_nonce"] = nonce()
    given["oauth_version"] = OAUTH_VERSION
}

func (o *OAuth) params() (p map[string]string) {
    p = make(map[string]string)
    p["oauth_consumer_key"] = o.ConsumerKey
    p["oauth_signature_method"] = signatureMethods[o.SignatureMethod]
    p["oauth_timestamp"] = timestamp()
    p["oauth_nonce"] = nonce()
    p["oauth_version"] = OAUTH_VERSION
    return
}

// This doesn't escape the keys as the spec requires,
// but I have yet to see a key that *needs* escaping.
func escapeParams(p map[string]string) {
    for k, v := range p {
        p[k] = PercentEncode(v)
    }
}

func baseString(method, url string, queryParams map[string]string) string {
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

func (o *OAuth) signingKey() string {
    key := o.ConsumerSecret + "&"
    if o.accessSecret != "" {
        key += o.accessSecret
    } else if o.requestSecret != "" {
        key += o.requestSecret
    }
    return key
}

// base64 bits inspired by github.com/montsamu/go-twitter-oauth
func (o *OAuth) sign(request string) string {
    key := o.signingKey()
    switch (o.SignatureMethod) {
    case HMAC_SHA1:
        hash := hmac.NewSHA1([]byte(key))
        hash.Write([]byte(request))
        signature := bytes.TrimSpace(hash.Sum())
        digest := make([]byte, base64.StdEncoding.EncodedLen(len(signature)))
        base64.StdEncoding.Encode(digest, signature)
        return strings.TrimSpace(bytes.NewBuffer(digest).String())
    }
    log.Stderr("Unknown signature method requested.")
    return ""
}

func timestamp() string {
    return strconv.Itoa64(time.Seconds())
}

