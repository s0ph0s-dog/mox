package webchatmailsrv

import (
	"bytes"
	cryptorand "crypto/rand"
	"encoding/base32"
	"encoding/base64"
	"encoding/json"
	"fmt"
	htmltemplate "html/template"
	"log/slog"
	"net/http"

	//"github.com/prometheus/client_golang/prometheus"
	//"github.com/prometheus/client_golang/prometheus/promauto"
	"rsc.io/qr"

	"github.com/mjl-/mox/mlog"
	"github.com/mjl-/mox/mox-"
)

var pkglog = mlog.New("chatmail-web", nil)

var (
	// Similar between ../webmail/webmail.go:/metricSubmission and ../smtpserver/server.go:/metricSubmission and ../webapisrv/server.go:/metricSubmission
	/*
	metricResults = promauto.NewCounterVec(
		prometheus.CounterOpts{
			Name: "mox_webchatmail_results_total",
			Help: "HTTP webchatmail results by method and result.",
		},
		[]string{"method", "result"}, // result: "badauth", "ok", or error code
	)
	metricDuration = promauto.NewHistogramVec(
		prometheus.HistogramOpts{
			Name:    "mox_webchatmail_duration_seconds",
			Help:    "HTTP chatmail webpage call duration.",
			Buckets: []float64{0.01, 0.05, 0.1, 0.5, 1, 5, 10, 20, 30},
		},
		[]string{"method"},
	)
	*/
)

func init() {
	mox.NewChatmailHandler = func(basePath string) http.Handler {
		pkglog.Debug("making handler for basepath", slog.Any("basePath", basePath))
		return NewServer(basePath)
	}
}

func templateIndex(domain, basePath, adminContact string) ([]byte, error) {
	chatmailIndexTmpl := htmltemplate.Must(htmltemplate.New("index").Parse(`<!doctype html>
<html>
	<head>
		<meta charset="utf-8" />
		<title>Chatmail Relay on {{ .Domain }}</title>
		<style>
:root { color-scheme: light dark; }
body, html { padding: 1em; font-size: 16px; }
* { font-size: inherit; font-family: ubuntu, lato, sans-serif; margin: 0; padding: 0; box-sizing: border-box; }
h1, h2, h3, h4 { margin-bottom: 1ex; }
h1 { font-size: 1.2rem; }
h2 { font-size: 1.1rem; }
h3, h4 { font-size: 1rem; }
ul { padding-left: 1rem; }
p { margin-bottom: 1em; max-width: 50em; }
[title] { text-decoration: underline; text-decoration-style: dotted; }
fieldset { border: 0; }
		</style>
	</head>
	<body>
		<h1>Chatmail Relay on {{ .Domain }}</h1>
		<p>This is a <a href="https://chatmail.at/">Chatmail</a> relay for <a href="https://delta.chat/">Delta Chat</a> (and similar software).</p>
		<p><a href="DCACCOUNT:https://{{ .Domain }}{{ .BasePath }}new">Get a {{ .Domain }} chat profile</a></p>
		<p>If you are viewing this page on a different device without a Delta Chat app installed, you can also <strong>scan this QR code</strong> with Delta Chat:</p>
		<img src="/qr.svg">
		<ul>
			<li><p><strong>Choose</strong> your profile picture and name</p></li>
			<li><p><strong>Start</strong> chatting with any Delta Chat contacts using QR invite codes</p></li>
		</ul>
		<p>If you would like to report abuse of this relay, you can contact the administrator here:</p>
		<p><code><pre>{{ .AdminContact }}</pre></code></p>
	</body>
</html>
`))
	indexArgs := struct {
		Domain       string
		BasePath     string
		AdminContact string
	}{domain, basePath, adminContact}
	var b bytes.Buffer
	err := chatmailIndexTmpl.Execute(&b, indexArgs)
	if err != nil {
		return nil, err
	}
	return b.Bytes(), nil
}

type server struct {
	basePath string
}

func NewServer(basePath string) http.Handler {
	return server{basePath}
}

type account struct {
	Email string `json:"email"`
	Password string `json:"password"`
}

func newAccount(domain string) account {
	randomData := make([]byte, 5)
	cryptorand.Read(randomData)
	var username = &bytes.Buffer{}
	encoder := base32.NewEncoder(base32.StdEncoding, username)
	encoder.Write(randomData)
	encoder.Close()

	randomData = make([]byte, 8)
	cryptorand.Read(randomData)
	var password = &bytes.Buffer{}
	b64encoder := base64.NewEncoder(base64.StdEncoding, password)
	b64encoder.Write(randomData)
	b64encoder.Close()

	return account{
		Email: fmt.Sprintf("%s@%s", username.String(), domain),
		Password: password.String(),
	}
}

func (s server) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	pkglog.Debug("answering request", slog.Any("r", r))
	if r.URL.Path == "/" {
		if r.Method != "GET" {
			http.Error(w, "405 - method not allowed", http.StatusMethodNotAllowed)
		}
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		chatmailIndex, err := templateIndex(r.Host, s.basePath, "admin@example.com")
		if err != nil {
			http.Error(w, "500 - internal server error", http.StatusInternalServerError)
		}
		w.Write(chatmailIndex)
	}

	if r.URL.Path == "/qr.svg" {
		if r.Method != "GET" {
			http.Error(w, "405 - method not allowed", http.StatusMethodNotAllowed)
		}
		w.Header().Set("Content-Type", "image/png")
		// TODO: generate this once instead of every time
		// TODO: switch to an SVG QR code generator
		// TODO: superimpose Delta Chat logo over QR code
		code, err := qr.Encode(fmt.Sprintf("DCACCOUNT:https://%s%snew", r.Host, s.basePath), qr.L)
		if err != nil {
			http.Error(w, "500 - internal server error", http.StatusInternalServerError)
		}
		w.Write(code.PNG())
	}

	if r.URL.Path == "/new" {
		if r.Method != "POST" {
			http.Error(w, "405 - method not allowed", http.StatusMethodNotAllowed)
		}
		w.Header().Set("Content-Type", "application/json")
		resp, err := json.Marshal(newAccount(r.Host))
		if err != nil {
			http.Error(w, "500 - internal server error", http.StatusInternalServerError)
		}
		w.Write(resp)
	}
}
