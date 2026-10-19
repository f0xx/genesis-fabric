// genesis-web runs the genesis CLI and shows its progress.
// It does not link libgenesis_core. Bind it to localhost.
package main

import (
	"bufio"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"sync"
	"time"
)

type progress struct {
	Running bool   `json:"running"`
	Line    string `json:"line"`
	OK      bool   `json:"ok"`
	Err     string `json:"err,omitempty"`
}

type job struct {
	mu   sync.Mutex
	cur  progress
	subs map[chan progress]struct{}
	cmd  *exec.Cmd
}

func newJob() *job { return &job{subs: map[chan progress]struct{}{}} }

func (j *job) publish(p progress) {
	j.mu.Lock()
	j.cur = p
	for ch := range j.subs {
		select {
		case ch <- p:
		default:
		}
	}
	j.mu.Unlock()
}

func (j *job) snapshot() progress {
	j.mu.Lock()
	defer j.mu.Unlock()
	return j.cur
}

func (j *job) subscribe() (chan progress, func()) {
	ch := make(chan progress, 8)
	j.mu.Lock()
	j.subs[ch] = struct{}{}
	cur := j.cur
	j.mu.Unlock()
	ch <- cur
	return ch, func() {
		j.mu.Lock()
		delete(j.subs, ch)
		j.mu.Unlock()
	}
}

func (j *job) busy() bool {
	j.mu.Lock()
	defer j.mu.Unlock()
	return j.cmd != nil
}

func main() {
	listen := flag.String("listen", "127.0.0.1:8787", "http listen address")
	genesis := flag.String("genesis", "genesis", "path to the genesis CLI")
	flag.Parse()

	j := newJob()
	mux := http.NewServeMux()
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/" {
			http.NotFound(w, r)
			return
		}
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		_, _ = io.WriteString(w, page)
	})
	mux.HandleFunc("/api/status", func(w http.ResponseWriter, r *http.Request) {
		writeJSON(w, j.snapshot())
	})
	mux.HandleFunc("/events", func(w http.ResponseWriter, r *http.Request) {
		fl, ok := w.(http.Flusher)
		if !ok {
			http.Error(w, "no flush", http.StatusInternalServerError)
			return
		}
		w.Header().Set("Content-Type", "text/event-stream")
		w.Header().Set("Cache-Control", "no-cache")
		ch, cancel := j.subscribe()
		defer cancel()
		for {
			select {
			case <-r.Context().Done():
				return
			case p := <-ch:
				b, _ := json.Marshal(p)
				fmt.Fprintf(w, "data: %s\n\n", b)
				fl.Flush()
			}
		}
	})
	mux.HandleFunc("/api/start", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			http.Error(w, "POST", http.StatusMethodNotAllowed)
			return
		}
		if j.busy() {
			http.Error(w, "busy", http.StatusConflict)
			return
		}
		var req struct {
			Mode    string `json:"mode"`
			File    string `json:"file"`
			Host    string `json:"host"`
			Port    int    `json:"port"`
			Fec     string `json:"fec"`
			Nack    string `json:"nack"`
			Profile string `json:"profile"`
			Window  int    `json:"window"`
			Control string `json:"control"`
		}
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			http.Error(w, "bad json", http.StatusBadRequest)
			return
		}
		args, err := buildArgs(req.Mode, req.File, req.Host, req.Fec, req.Nack, req.Profile, req.Control, req.Port, req.Window)
		if err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		cmd := exec.Command(*genesis, args...)
		stderr, err := cmd.StderrPipe()
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		stdout, _ := cmd.StdoutPipe()
		if err := cmd.Start(); err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		j.mu.Lock()
		j.cmd = cmd
		j.mu.Unlock()
		j.publish(progress{Running: true, Line: "started"})
		go func() {
			readProgress(j, stderr)
			if stdout != nil {
				_, _ = io.Copy(io.Discard, stdout)
			}
			err := cmd.Wait()
			j.mu.Lock()
			j.cmd = nil
			j.mu.Unlock()
			p := progress{Running: false, OK: err == nil, Line: "done"}
			if err != nil {
				p.Err = err.Error()
				p.Line = "failed"
			}
			j.publish(p)
		}()
		writeJSON(w, map[string]string{"status": "started"})
	})

	srv := &http.Server{Addr: *listen, Handler: mux, ReadHeaderTimeout: 5 * time.Second}
	log.Printf("genesis-web listening on http://%s", *listen)
	if err := srv.ListenAndServe(); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}

func buildArgs(mode, file, host, fec, nack, profile, control string, port, window int) ([]string, error) {
	if mode != "send" && mode != "recv" {
		return nil, fmt.Errorf("mode must be send or recv")
	}
	if file == "" || strings.ContainsAny(file, "\n\r") {
		return nil, fmt.Errorf("file is required")
	}
	if port < 1 || port > 65535 {
		return nil, fmt.Errorf("port out of range")
	}
	tri := func(v string) (string, error) {
		switch v {
		case "", "auto", "on", "off":
			if v == "" {
				v = "auto"
			}
			return v, nil
		default:
			return "", fmt.Errorf("fec and nack must be auto, on, or off")
		}
	}
	fec, err := tri(fec)
	if err != nil {
		return nil, err
	}
	nack, err = tri(nack)
	if err != nil {
		return nil, err
	}
	switch profile {
	case "", "auto", "gbe", "wifi", "cellular":
		if profile == "" {
			profile = "auto"
		}
	default:
		return nil, fmt.Errorf("bad profile")
	}
	args := []string{mode, "--fec", fec, "--nack", nack, "--profile", profile, "-p", strconv.Itoa(port)}
	if control != "" {
		if strings.ContainsAny(control, "\n\r") {
			return nil, fmt.Errorf("control spec is invalid")
		}
		args = append(args, "--control", control)
	}
	if window >= 16 && window <= 512 {
		args = append(args, "--window", strconv.Itoa(window))
	}
	if mode == "send" {
		if host == "" || strings.ContainsAny(host, " \n\r") {
			return nil, fmt.Errorf("host is required")
		}
		args = append(args, file, host)
	} else {
		args = append(args, "-o", file)
	}
	return args, nil
}

func readProgress(j *job, r io.Reader) {
	br := bufio.NewReader(r)
	var buf strings.Builder
	for {
		b, err := br.ReadByte()
		if err != nil {
			return
		}
		if b == '\r' || b == '\n' {
			line := strings.TrimSpace(buf.String())
			buf.Reset()
			if line != "" {
				j.publish(progress{Running: true, Line: line})
			}
			continue
		}
		buf.WriteByte(b)
	}
}

func writeJSON(w http.ResponseWriter, v any) {
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(v)
}

const page = `<!doctype html>
<meta charset="utf-8">
<title>genesis</title>
<style>
  body { font: 16px/1.4 sans-serif; margin: 2rem auto; max-width: 40rem; }
  label { display: block; margin: 0.6rem 0 0.2rem; }
  input, select, button { font: inherit; padding: 0.3rem 0.5rem; }
  #bar { height: 1.2rem; background: #ddd; margin-top: 1rem; }
  #bar > div { height: 100%; width: 0; background: #3a6; }
  #line { font-family: ui-monospace, monospace; white-space: pre-wrap; }
</style>
<h1>genesis</h1>
<form id="f">
  <label>Mode <select name="mode"><option>send</option><option>recv</option></select></label>
  <label>File <input name="file" size="48" required placeholder="/path/to/file or -"></label>
  <label>Host <input name="host" placeholder="192.168.4.100"></label>
  <label>Port <input name="port" type="number" value="37420"></label>
  <label>FEC <select name="fec"><option>auto</option><option>on</option><option>off</option></select></label>
  <label>NACK <select name="nack"><option>auto</option><option>on</option><option>off</option></select></label>
  <label>Profile <select name="profile"><option>auto</option><option>gbe</option><option>wifi</option><option>cellular</option></select></label>
  <label>Window <input name="window" type="number" value="128"></label>
  <label>Daemon control <input name="control" placeholder="empty uses the library; or /tmp/genesis.sock"></label>
  <button>Start</button>
</form>
<div id="bar"><div></div></div>
<p id="line">idle</p>
<script>
const line = document.getElementById("line");
const fill = document.querySelector("#bar > div");
const es = new EventSource("/events");
es.onmessage = (ev) => {
  const p = JSON.parse(ev.data);
  line.textContent = p.line || (p.running ? "running" : "idle");
  if (p.err) line.textContent += "\n" + p.err;
  const m = /([0-9.]+)%/.exec(p.line || "");
  fill.style.width = m ? m[1] + "%" : "0";
};
document.getElementById("f").onsubmit = async (ev) => {
  ev.preventDefault();
  const f = ev.target;
  const body = {
    mode: f.mode.value, file: f.file.value, host: f.host.value,
    port: Number(f.port.value), fec: f.fec.value, nack: f.nack.value,
    profile: f.profile.value, window: Number(f.window.value), control: f.control.value
  };
  const res = await fetch("/api/start", {method: "POST", headers: {"Content-Type": "application/json"}, body: JSON.stringify(body)});
  if (!res.ok) line.textContent = await res.text();
};
</script>
`
