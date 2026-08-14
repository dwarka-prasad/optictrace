package mock

import (
	"bytes"
	"encoding/json"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"time"

	"github.com/dwarka-prasad/optictrace/internal/spec"
)

// aiClient asks Claude for context-aware mock responses. Strictly optional:
// every failure path falls back to deterministic generation, so the mock
// works fully offline.
type aiClient struct {
	key    string
	model  string
	client *http.Client
	logger *slog.Logger
}

func newAIClient(key string, logger *slog.Logger) *aiClient {
	model := os.Getenv("OPTICTRACE_AI_MODEL")
	if model == "" {
		model = "claude-haiku-4-5-20251001" // fast + cheap; mocks don't need frontier reasoning
	}
	return &aiClient{
		key:    key,
		model:  model,
		client: &http.Client{Timeout: 25 * time.Second},
		logger: logger,
	}
}

type anthropicRequest struct {
	Model     string             `json:"model"`
	MaxTokens int                `json:"max_tokens"`
	System    string             `json:"system"`
	Messages  []anthropicMessage `json:"messages"`
}

type anthropicMessage struct {
	Role    string `json:"role"`
	Content string `json:"content"`
}

type anthropicResponse struct {
	Content []struct {
		Type string `json:"type"`
		Text string `json:"text"`
	} `json:"content"`
	Error *struct {
		Message string `json:"message"`
	} `json:"error"`
}

const aiSystemPrompt = `You are a mock API server. Reply with ONLY a JSON value (no prose, no markdown fences) that is a realistic response for the described API operation. It must conform to the provided JSON schema when one is given, use plausible realistic values consistent with the request payload, and vary naturally between calls.`

func (a *aiClient) generate(r *http.Request, tmpl string, op *spec.Operation,
	schema *spec.Schema, body map[string]any, s *spec.Spec) (any, error) {

	var prompt bytes.Buffer
	fmt.Fprintf(&prompt, "Operation: %s %s\n", r.Method, tmpl)
	if op.Summary != "" {
		fmt.Fprintf(&prompt, "Summary: %s\n", op.Summary)
	}
	if body != nil {
		raw, _ := json.Marshal(body)
		fmt.Fprintf(&prompt, "Request body: %s\n", raw)
	}
	if schema != nil {
		raw, _ := json.Marshal(schema)
		fmt.Fprintf(&prompt, "Response JSON schema: %s\n", raw)
	}
	prompt.WriteString("Respond with only the JSON response body.")

	reqBody, err := json.Marshal(anthropicRequest{
		Model:     a.model,
		MaxTokens: 1024,
		System:    aiSystemPrompt,
		Messages:  []anthropicMessage{{Role: "user", Content: prompt.String()}},
	})
	if err != nil {
		return nil, err
	}

	req, err := http.NewRequestWithContext(r.Context(), http.MethodPost,
		"https://api.anthropic.com/v1/messages", bytes.NewReader(reqBody))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("x-api-key", a.key)
	req.Header.Set("anthropic-version", "2023-06-01")

	resp, err := a.client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	var parsed anthropicResponse
	if err := json.NewDecoder(resp.Body).Decode(&parsed); err != nil {
		return nil, err
	}
	if parsed.Error != nil {
		return nil, fmt.Errorf("anthropic api: %s", parsed.Error.Message)
	}
	if len(parsed.Content) == 0 {
		return nil, fmt.Errorf("anthropic api: empty response")
	}

	text := bytes.TrimSpace([]byte(parsed.Content[0].Text))
	// Tolerate accidental markdown fencing.
	text = bytes.TrimPrefix(text, []byte("```json"))
	text = bytes.TrimPrefix(text, []byte("```"))
	text = bytes.TrimSuffix(bytes.TrimSpace(text), []byte("```"))

	var out any
	if err := json.Unmarshal(text, &out); err != nil {
		return nil, fmt.Errorf("model returned non-JSON: %w", err)
	}
	return out, nil
}
