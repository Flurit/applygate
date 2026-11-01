package judge

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"
)

// OpenAI judges through any OpenAI-compatible chat completions endpoint
// with the user's own key: Anthropic's compatible endpoint (the default),
// OpenAI, other providers that offer one, and local servers. It uses plain HTTP, so it adds no
// dependency. The answer is requested as a JSON schema; servers that ignore
// response_format still work when the model answers with the JSON object.
type OpenAI struct {
	Model, BaseURL, Key string
	ReasoningEffort     string       // sent only when set
	Client              *http.Client // nil: http.DefaultClient
}

func (o OpenAI) Name() string { return o.Model }

func (o OpenAI) Judge(ctx context.Context, in Input) Result {
	r := Result{Model: o.Model}
	req := map[string]any{
		"model": o.Model,
		"messages": []map[string]string{
			{"role": "system", "content": System},
			{"role": "user", "content": Prompt(in)},
		},
		"response_format": map[string]any{
			"type":        "json_schema",
			"json_schema": map[string]any{"name": "verdict", "strict": true, "schema": Schema},
		},
	}
	if o.ReasoningEffort != "" {
		req["reasoning_effort"] = o.ReasoningEffort
	}
	body, _ := json.Marshal(req)
	hreq, err := http.NewRequestWithContext(ctx, http.MethodPost, strings.TrimRight(o.BaseURL, "/")+"/chat/completions", bytes.NewReader(body))
	if err != nil {
		r.Err = "openai: " + err.Error()
		return r
	}
	hreq.Header.Set("Content-Type", "application/json")
	if o.Key != "" {
		hreq.Header.Set("Authorization", "Bearer "+o.Key)
	}
	client := o.Client
	if client == nil {
		client = http.DefaultClient
	}
	start := time.Now()
	resp, err := client.Do(hreq)
	if err != nil {
		r.Err = "openai: " + err.Error()
		return r
	}
	defer resp.Body.Close()
	b, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	r.APIms = float64(time.Since(start).Milliseconds())
	r.WallMS = r.APIms
	var out struct {
		Choices []struct {
			Message struct {
				Content string `json:"content"`
				Refusal string `json:"refusal"`
			} `json:"message"`
			FinishReason string `json:"finish_reason"`
		} `json:"choices"`
		Error *struct {
			Message string `json:"message"`
		} `json:"error"`
	}
	_ = json.Unmarshal(b, &out)
	switch {
	case resp.StatusCode/100 != 2:
		msg := firstLine(string(b))
		if out.Error != nil && out.Error.Message != "" {
			msg = out.Error.Message
		}
		r.Err = fmt.Sprintf("openai: %s: %s", resp.Status, msg)
	case len(out.Choices) == 0:
		r.Err = "openai: no choices in the answer"
	case out.Choices[0].Message.Refusal != "":
		r.Err = "openai: refused: " + out.Choices[0].Message.Refusal
	case out.Choices[0].FinishReason == "length":
		r.Err = "openai: answer cut off at the token limit"
	default:
		answer(&r, []byte(jsonObject(out.Choices[0].Message.Content)))
	}
	return r
}

// jsonObject returns the outermost {...} in s, for servers that wrap the
// JSON answer in prose or a code fence.
func jsonObject(s string) string {
	i, j := strings.IndexByte(s, '{'), strings.LastIndexByte(s, '}')
	if i < 0 || j < i {
		return s
	}
	return s[i : j+1]
}
