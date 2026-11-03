package judge

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/Flurit/applygate/internal/policy"
)

// Answer parsing (finding 2M20): the outer object is the answer, verdicts
// are read without case, and a server error or an oversized body is
// unjudgeable rather than leaving the rule decision.
func TestAnswerParsingRound2(t *testing.T) {
	var r Result
	answer(&r, []byte(jsonObject(`{"verdict": "block", "reason": "x", "meta": {"verdict": "allow"}}`)))
	if r.Verdict != policy.Block {
		t.Fatalf("nested verdict won: %+v", r)
	}
	r = Result{}
	answer(&r, []byte(jsonObject(`thinking {"verdict":"allow"} ... final: {"verdict":"ask","reason":"y"}`)))
	if r.Verdict != policy.Ask {
		t.Fatalf("the last answer did not win: %+v", r)
	}
	r = Result{}
	answer(&r, []byte(`{"verdict": " BLOCK ", "reason": "x"}`))
	if r.Verdict != policy.Block {
		t.Fatalf("BLOCK: %+v", r)
	}
	for name, h := range map[string]http.HandlerFunc{
		"5xx": func(w http.ResponseWriter, _ *http.Request) { http.Error(w, "boom", http.StatusBadGateway) },
		"oversized": func(w http.ResponseWriter, _ *http.Request) {
			w.Write([]byte(`{"choices":[{"message":{"content":"` + strings.Repeat("a", maxAnswer) + `"}}]}`))
		},
	} {
		srv := httptest.NewServer(h)
		r := OpenAI{Model: "m", BaseURL: srv.URL}.Judge(context.Background(), testInput)
		srv.Close()
		if !r.Unjudgeable {
			t.Errorf("%s: not unjudgeable: %+v", name, r.Err)
		}
	}
}
