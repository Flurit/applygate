package main

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net/http"
	"os"

	"github.com/Flurit/applygate/internal/config"
	"github.com/Flurit/applygate/internal/judge"
)

// Endpoint judges through the backend applygate ships (judge.New with the
// default endpoint unless -base-url says otherwise), so the measurement is
// of the code users run. It reads the token usage from each response to
// price the call; the shipped backend does not.
type Endpoint struct {
	judge.OpenAI
	In, Out float64 // dollars per million input and output tokens
}

func newEndpoint(model, baseURL, keyEnv, effort string, in, out float64) Endpoint {
	cfg := &config.Config{Judge: config.Judge{Model: model, BaseURL: baseURL, APIKeyEnv: keyEnv, ReasoningEffort: effort}}
	env := map[string]string{}
	for _, k := range []string{keyEnv, config.DefaultJudgeKeyEnv} {
		if k != "" {
			env[k] = os.Getenv(k)
		}
	}
	j, err := judge.New(cfg, env)
	check(err)
	return Endpoint{OpenAI: j.(judge.OpenAI), In: in, Out: out}
}

func (e Endpoint) Name() string { return "api-" + e.Model + "/" + e.ReasoningEffort }

func (e Endpoint) Judge(ctx context.Context, in judge.Input) judge.Result {
	var u usage
	o := e.OpenAI
	o.Client = &http.Client{Transport: counter{&u}}
	r := o.Judge(ctx, in)
	r.CostUSD = (u.Usage.Prompt*e.In + u.Usage.Completion*e.Out) / 1e6
	return r
}

type usage struct {
	Usage struct {
		Prompt     float64 `json:"prompt_tokens"`
		Completion float64 `json:"completion_tokens"`
	} `json:"usage"`
}

// counter reads the usage block of a response and passes the body on.
type counter struct{ u *usage }

func (c counter) RoundTrip(req *http.Request) (*http.Response, error) {
	resp, err := http.DefaultTransport.RoundTrip(req)
	if err != nil {
		return resp, err
	}
	b, err := io.ReadAll(resp.Body)
	resp.Body.Close()
	if err != nil {
		return nil, err
	}
	_ = json.Unmarshal(b, c.u)
	resp.Body = io.NopCloser(bytes.NewReader(b))
	return resp, nil
}
