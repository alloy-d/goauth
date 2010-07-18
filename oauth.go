// A Go OAuth library, mainly created to interact with Twitter.
package oauth

import (
    //"bytes"
    "crypto/hmac"
    "encoding/base64"
    "fmt"
    "http"
    "io"
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
    SignatureMethod uint

    Callback string

    RequestTokenURL string
    OwnerAuthURL string
    AccessTokenURL string

    requestToken string
    requestSecret string

    verifier string

    userName string
    userId uint
    accessToken string
    accessSecret string
}

// Signature method representations for oauth_signature.
//
// TODO: why does this exist, anyway?
var signatureMethods = map[uint]string{
    HMAC_SHA1: "HMAC-SHA1",
}

func (o *OAuth) Authorized() bool {
    if o.accessToken != "" && o.accessSecret != "" {
        return true
    }
    return false
}

// Returns the username, if any.
// Does not return any dance errors, because that would just be
// obnoxious.
func (o *OAuth) UserName() string {
    return o.userName
}

// Initiates the OAuth dance.
func (o *OAuth) GetTempCredentials() (err os.Error) {
    params := o.params()
    params["oauth_callback"] = o.Callback

    resp, err := o.makeRequest("POST", o.RequestTokenURL, params, "", "")
    if err != nil {
        return
    }
    err = o.parseResponse(resp.StatusCode, resp.Body, TempCredentialReq)
    return
}

// Makes an HTTP request, handling all the repetitive OAuth overhead.
func (o *OAuth) makeRequest(method, url string, params map[string]string, bodyType string, body string) (resp *http.Response, err os.Error) {
    escapeParams(params)

    signature, err := o.sign(baseString(method, url, params, bodyType, body))
    if err != nil {
        return
    }

    params["oauth_signature"] = PercentEncode(signature)

    switch(method) {
    case "POST":
        resp, err = post(url, params, bodyType, strings.NewReader(body))
    default:
        return nil, &ImplementationError{
            What: fmt.Sprintf("HTTP method (%s)", method),
            Where: "OAuth\xb7makeRequest()",
        }
    }
    return
}

// The URL the user needs to visit to grant authorization.
// Call after GetTempCredentials().
func (o *OAuth) AuthorizationURL() (string, os.Error) {
    if o.requestToken == "" || o.requestSecret == "" {
        return "", &DanceError{
            What: "attempt to get authorization without credentials",
            Where: "OAuth\xb7AuthorizationURL()",
        }
    }

    url := o.OwnerAuthURL + "?oauth_token=" + o.requestToken
    return url, nil
}

// Sets the OAuth verifier if gotten out-of-band.
// (For Twitter, you would pass the user's "PIN" to this.)
func (o *OAuth) OOBVerifier(v string) {
    o.verifier = v
}

// Performs the final step in the dance: getting the access token.
//
// Call this after GetTempCredentials() and setting the verifier.
func (o *OAuth) GetAccessToken() (err os.Error) {
    if o.requestToken == "" || o.requestSecret == "" {
        return &DanceError{
            What: "Temporary credentials not avaiable",
            Where: "OAuth\xb7GetAccessToken()",
        }
    } else if o.verifier == "" {
        return &DanceError{
            What: "Verifier not available",
            Where: "OAuth\xb7GetAccessToken()",
        }
    }

    params := o.params()
    params["oauth_token"] = o.requestToken
    params["oauth_verifier"] = o.verifier
    resp, err := o.makeRequest("POST", o.AccessTokenURL, params, "", "")
    if err != nil {
        return
    }

    return o.parseResponse(resp.StatusCode, resp.Body, TokenReq)
}

// Parses a response for the OAuth dance and sets the appropriate fields
// in o for the request type.
func (o *OAuth) parseResponse(status int, body io.Reader, requestType int) os.Error {
    //dump, _ := http.DumpResponse(resp, true)
    //fmt.Fprintf(os.Stderr, "%s\n", dump)
    r := bodyString(body)

    if status == 401 {
        return &DanceError{
            What: r,
            Where: fmt.Sprintf("parseResponse(requestType=%d)", requestType),
        }
    }

    params := parseParams(r)

    switch(requestType) {
    case TempCredentialReq:
        log.Stdoutf("Recv'd request token '%s'.\n", params["oauth_token"])
        o.requestToken = params["oauth_token"]
        log.Stdoutf("Recv'd request secret '%s'.\n", params["oauth_token_secret"])
        o.requestSecret = params["oauth_token_secret"]
        if confirmed, ok := params["oauth_callback_confirmed"]; !ok ||
            confirmed != "true" {
            return &CallbackError{o.Callback}
        }
    case TokenReq:
        log.Stdoutf("Recv'd access token '%s'.\n", params["oauth_token"])
        o.accessToken = params["oauth_token"]
        log.Stdoutf("Recv'd access secret '%s'.\n", params["oauth_token_secret"])
        o.accessSecret = params["oauth_token_secret"]
        o.userId, _ = strconv.Atoui(params["user_id"])
        o.userName = params["screen_name"]
    default:
        return &ImplementationError{
            What: "requestType=" + strconv.Itoa(requestType),
            Where: "OAuth\xb7parseResponse()",
        }
    }
    return nil
}

func (o *OAuth) params() (p map[string]string) {
    p = make(map[string]string)
    p["oauth_consumer_key"] = o.ConsumerKey
    p["oauth_signature_method"] = signatureMethods[o.SignatureMethod]
    p["oauth_timestamp"] = timestamp()
    p["oauth_nonce"] = nonce()
    p["oauth_version"] = OAUTH_VERSION
    if o.Authorized() {
        p["oauth_token"] = o.accessToken
    }
    return
}

// The base string used to compute signatures.
//
// TODO: handle parameters in the URL. 
func baseString(method, url string, queryParams map[string]string, bodyType string, body string) string {
    str := method + "&"
    str += PercentEncode(url)

    var bodyParams, allParams map[string]string
    if bodyType == "application/x-www-form-urlencoded" {
        bodyParams = parseParams(body)
        unescapeParams(bodyParams)  // Un-url-encode before...
        escapeParams(bodyParams)    // ...re-percent-encoding!
        allParams = mergeParams(queryParams, bodyParams)
    } else {
        allParams = queryParams
    }

    keys := make([]string, len(allParams))
    i := 0
    for k, _ := range allParams {
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
        str += PercentEncode(allParams[k])
        fmt.Fprintf(os.Stderr, "bs -> %s=%s\n", k, allParams[k])
    }

    log.Stderrf("\n---\nComputed base string:\n%s\n---\n", str)
    return str
}

// For oauth_nonce.
func nonce() string {
    return strconv.Itoa64(rand.Int63())
}

// This could probably seem like less of a hack...
func (o *OAuth) signingKey() string {
    key := o.ConsumerSecret + "&"
    if o.accessSecret != "" {
        key += o.accessSecret
    } else if o.requestSecret != "" {
        key += o.requestSecret
    }
    log.Stderrf("Using key: %s\n", key)
    return key
}

// base64 bits inspired by github.com/montsamu/go-twitter-oauth
func (o *OAuth) sign(request string) (string, os.Error) {
    key := o.signingKey()
    switch (o.SignatureMethod) {
    case HMAC_SHA1:
        hash := hmac.NewSHA1([]byte(key))
        hash.Write([]byte(request))
        signature := hash.Sum()
        digest := make([]byte, base64.StdEncoding.EncodedLen(len(signature)))
        base64.StdEncoding.Encode(digest, signature)
        //return bytes.NewBuffer(digest).String(), nil
        log.Stderrf("Generated signature %s\n", digest)
        return string(digest), nil
    }
    return "", &ImplementationError{
        What: fmt.Sprintf("Unknown signature method (%d)", o.SignatureMethod),
        Where: "OAuth\xb7sign",
    }
}

func timestamp() string {
    return strconv.Itoa64(time.Seconds())
}

// Issues an OAuth-wrapped POST to the specified URL.
//
// Caller should close r.Body when done reading it.
func (o *OAuth) Post(url string, bodyType string, body io.Reader) (r *http.Response, err os.Error) {
    if !o.Authorized() {
        return nil, &DanceError{
            What: "Not authorized",
            Where: "OAuth\xb7Post()",
        }
    }

    bs := bodyString(body)
    fmt.Fprintln(os.Stderr, bs)
    params := o.params()
    r, err = o.makeRequest("POST", url, params, bodyType, bs)
    dump, _ := http.DumpResponse(r, true)
    fmt.Fprintf(os.Stderr, "%s\n", dump)
    return
}

