package compliance

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"

	"github.com/anthropics/anthropic-sdk-go"
	"github.com/anthropics/anthropic-sdk-go/option"
)

// Agent runs compliance analysis via Claude.
type Agent struct {
	client *anthropic.Client
}

// NewAgent creates an Agent with the given Anthropic API key.
func NewAgent(apiKey string) *Agent {
	c := anthropic.NewClient(option.WithAPIKey(apiKey))
	return &Agent{client: &c}
}

// Analyze calls Claude with a structured JSON prompt and returns a gap report.
// The progress channel is accepted for API compatibility but events are not
// emitted in this implementation (tool-use streaming is a future enhancement).
func (a *Agent) Analyze(ctx context.Context, req *AnalysisRequest, progress chan<- ProgressEvent) (*AnalysisResult, error) {
	msg, err := a.client.Messages.New(ctx, anthropic.MessageNewParams{
		Model:     anthropic.Model("claude-opus-4-7"),
		MaxTokens: 16000,
		System: []anthropic.TextBlockParam{
			{Text: systemPrompt()},
		},
		Messages: []anthropic.MessageParam{
			anthropic.NewUserMessage(anthropic.NewTextBlock(userPrompt(req))),
		},
	})
	if err != nil {
		return nil, fmt.Errorf("claude API: %w", err)
	}

	var text string
	for _, block := range msg.Content {
		if block.Type == "text" {
			text += block.Text
		}
	}

	text = stripJSONFences(text)

	var result AnalysisResult
	if err := json.Unmarshal([]byte(text), &result); err != nil {
		return nil, fmt.Errorf("parse response: %w\nraw: %s", err, text)
	}
	if result.Title == "" {
		result.Title = req.Title
	}
	if result.Title == "" {
		result.Title = "Compliance Analysis"
	}

	return &result, nil
}

func stripJSONFences(s string) string {
	s = strings.TrimSpace(s)
	if strings.HasPrefix(s, "```") {
		s = strings.TrimPrefix(s, "```json")
		s = strings.TrimPrefix(s, "```")
		s = strings.TrimSuffix(s, "```")
		s = strings.TrimSpace(s)
	}
	return s
}

func systemPrompt() string {
	return strings.TrimSpace(`
You are a compliance analysis engine for Midnight-Core.

Analyze the provided policy document against every requested framework.
For each framework assess EVERY control and classify it as:
  "covered"  — the document clearly addresses this control
  "partial"  — the document partially addresses it with meaningful gaps
  "gap"      — the document does not address it at all

Return ONLY valid JSON with this exact structure — no markdown, no preamble:
{
  "title": "<document title>",
  "frameworks": [
    {
      "framework": "<framework id>",
      "covered_count": 0,
      "partial_count": 0,
      "gap_count": 0,
      "coverage_percent": 0.0,
      "assessments": [
        {
          "framework": "<framework id>",
          "control_id": "<id>",
          "control_name": "<name>",
          "status": "covered|partial|gap",
          "evidence": "<quote or paraphrase from document>",
          "gap_description": "<what is missing, if partial or gap>"
        }
      ]
    }
  ]
}

coverage_percent = (covered*2 + partial) / (total_controls*2) * 100
`)
}

func userPrompt(req *AnalysisRequest) string {
	frameworks := make([]string, len(req.Frameworks))
	for i, f := range req.Frameworks {
		frameworks[i] = string(f)
	}
	return fmt.Sprintf(
		"Frameworks to assess: %s\n\nDocument title: %s\n\n---\n\n%s\n\n---\n\nReturn only the JSON result.",
		strings.Join(frameworks, ", "),
		req.Title,
		req.Document,
	)
}
