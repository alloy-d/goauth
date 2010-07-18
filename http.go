package oauth

import (
    "bufio"
    "bytes"
    //"crypto/tls"
    "net"
    "fmt"
    "http"
    "io"
    "os"
    "strings"
)

type badStringError struct {
    what string
    str string
}

func (e *badStringError) String() string {
    return fmt.Sprintf("%s %q", e.what, e.str)
}

type readClose struct {
    io.Reader
    io.Closer
}

type nopCloser struct {
    io.Reader
}
func (nopCloser) Close() os.Error { return nil }

func hasPort(s string) bool {
    return strings.LastIndex(s, ":") > strings.LastIndex(s, "]")
}

func send(req *http.Request) (resp *http.Response, err os.Error) {
    //dump, _ := http.DumpRequest(req, true)
    //fmt.Fprintf(os.Stderr, "%s", dump)
    //fmt.Fprintf(os.Stderr, "\n--- body:\n%s\n---", bodyString(req.Body))
    if req.URL.Scheme != "http" {
        return nil, &badStringError{"unsupported protocol scheme", req.URL.Scheme}
    }

    addr := req.URL.Host
    if !hasPort(addr) {
        addr += ":http"
    }

    conn, err := net.Dial("tcp", "", addr)
    if err != nil {
        return nil, err
    }

    err = req.Write(os.Stdout)
    err = req.Write(conn)
    if err != nil {
        conn.Close()
        return nil, err
    }

    reader := bufio.NewReader(conn)
    resp, err = http.ReadResponse(reader, req.Method)
    if err != nil {
        conn.Close()
        return nil, err
    }

    resp.Body = readClose{resp.Body, conn}

    return
}

func post(url string, oauthHeaders map[string]string, bodyType string, body io.Reader) (r *http.Response, err os.Error) {
    buf := new(bytes.Buffer)
    buf.ReadFrom(body)

    var req http.Request
    req.Method = "POST"
    req.ProtoMajor = 1
    req.ProtoMinor = 1
    req.Close = true
    req.ContentLength = int64(buf.Len())
    req.Body = nopCloser{buf}
    req.Header = map[string]string{
        "Content-Type": bodyType,
        "Authorization": "OAuth ",
    }
    req.TransferEncoding = []string{"chunked"}

    first := true
    for k, v := range oauthHeaders {
        if first {
            first = false
        } else {
            req.Header["Authorization"] += ",\n    "
        }
        req.Header["Authorization"] += k+"=\""+v+"\""
    }

    req.URL, err = http.ParseURL(url)
    if err != nil {
        return nil, err
    }

    return send(&req)
}

