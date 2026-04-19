package compliance

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"

	"github.com/anthropics/anthropic-sdk-go"
	"github.com/anthropics/anthropic-sdk-go/option"
)

// Agent runs the Claude agentic loop for compliance analysis.
type Agent struct {
	client anthropic.Client
}

// NewAgent creates an Agent with the given Anthropic API key.
func NewAgent(apiKey string) *Agent {
	return &Agent{client: anthropic.NewClient(option.WithAPIKey(apiKey))}
}

// Analyze runs the full agentic loop and returns a gap report.
// Pass a non-nil progress channel to receive live ProgressEvents as Claude
// assesses each control; pass nil for a fire-and-forget call.
func (a *Agent) Analyze(ctx context.Context, req *AnalysisRequest, progress chan<- ProgressEvent) (*AnalysisResult, error) {
	var assessments []ControlAssessment

	tools := buildTools()
	messages := []anthropic.MessageParam{
		anthropic.NewUserMessage(anthropic.NewTextBlock(userPrompt(req))),
	}

	for {
		resp, err := a.client.Messages.New(ctx, anthropic.MessageNewParams{
			Model:     anthropic.Model("claude-opus-4-7"),
			MaxTokens: 16000,
			System:    []anthropic.TextBlockParam{{Text: systemPrompt()}},
			Tools:     tools,
			Messages:  messages,
		})
		if err != nil {
			return nil, fmt.Errorf("claude API: %w", err)
		}

		messages = append(messages, resp.ToParam())

		if resp.StopReason != anthropic.StopReasonToolUse {
			break
		}

		var toolResults []anthropic.ContentBlockParamUnion
		for _, block := range resp.Content {
			if tu, ok := block.AsAny().(anthropic.ToolUseBlock); ok {
				out, toolErr := runTool(tu, &assessments, progress)
				if toolErr != nil {
					toolResults = append(toolResults,
						anthropic.NewToolResultBlock(block.ID, toolErr.Error(), true))
				} else {
					toolResults = append(toolResults,
						anthropic.NewToolResultBlock(block.ID, out, false))
				}
			}
		}

		messages = append(messages, anthropic.NewUserMessage(toolResults...))
	}

	return buildResult(req, assessments), nil
}

// runTool dispatches a tool call and optionally emits a progress event.
func runTool(tool anthropic.ToolUseBlock, assessments *[]ControlAssessment, progress chan<- ProgressEvent) (string, error) {
	raw := tool.JSON.Input.Raw()

	switch tool.Name {
	case "get_framework_controls":
		var input struct {
			Framework string `json:"framework"`
		}
		if err := json.Unmarshal([]byte(raw), &input); err != nil {
			return "", fmt.Errorf("parse input: %w", err)
		}
		controls, ok := Frameworks[Framework(input.Framework)]
		if !ok {
			return "", fmt.Errorf("unknown framework: %s", input.Framework)
		}
		if progress != nil {
			progress <- ProgressEvent{
				Type:      "framework_start",
				Framework: Framework(input.Framework),
				Message:   fmt.Sprintf("scanning %d controls", len(controls)),
			}
		}
		b, _ := json.Marshal(controls)
		return string(b), nil

	case "record_control_assessment":
		var a ControlAssessment
		if err := json.Unmarshal([]byte(raw), &a); err != nil {
			return "", fmt.Errorf("parse assessment: %w", err)
		}
		*assessments = append(*assessments, a)
		if progress != nil {
			progress <- ProgressEvent{
				Type:        "control_assessed",
				Framework:   a.Framework,
				ControlID:   a.ControlID,
				ControlName: a.ControlName,
				Status:      a.Status,
			}
		}
		return `{"recorded":true}`, nil

	default:
		return "", fmt.Errorf("unknown tool: %s", tool.Name)
	}
}

// buildResult groups assessments by framework and computes coverage metrics.
func buildResult(req *AnalysisRequest, assessments []ControlAssessment) *AnalysisResult {
	byFramework := make(map[Framework][]ControlAssessment)
	for _, a := range assessments {
		byFramework[a.Framework] = append(byFramework[a.Framework], a)
	}

	var results []FrameworkResult
	for _, fw := range req.Frameworks {
		as := byFramework[fw]
		var covered, partial, gap int
		for _, a := range as {
			switch a.Status {
			case StatusCovered:
				covered++
			case StatusPartial:
				partial++
			case StatusGap:
				gap++
			}
		}
		total := len(as)
		var pct float64
		if total > 0 {
			pct = float64(covered*2+partial) / float64(total*2) * 100
		}
		results = append(results, FrameworkResult{
			Framework:       fw,
			Assessments:     as,
			CoveredCount:    covered,
			PartialCount:    partial,
			GapCount:        gap,
			CoveragePercent: pct,
		})
	}

	title := req.Title
	if title == "" {
		title = "Compliance Analysis"
	}
	return &AnalysisResult{Title: title, Frameworks: results}
}

func buildTools() []anthropic.ToolUnionParam {
	getControls := anthropic.ToolParam{
		Name:        "get_framework_controls",
		Description: anthropic.String("Return the list of controls for a compliance framework."),
		InputSchema: anthropic.ToolInputSchemaParam{
			Properties: map[string]any{
				"framework": map[string]any{
					"type":        "string",
					"enum":        []string{"HIPAA", "SOC2", "PCI_DSS", "ISO_27001", "NIST_CSF", "HITRUST"},
					"description": "The compliance framework identifier.",
				},
			},
		},
	}

	recordAssessment := anthropic.ToolParam{
		Name:        "record_control_assessment",
		Description: anthropic.String("Record your assessment of whether a specific control is addressed in the document."),
		InputSchema: anthropic.ToolInputSchemaParam{
			Properties: map[string]any{
				"framework": map[string]any{
					"type":        "string",
					"description": "The framework this control belongs to (e.g. HIPAA, SOC2).",
				},
				"control_id": map[string]any{
					"type":        "string",
					"description": "The control identifier (e.g. 164.308(a)(1) or CC6.1).",
				},
				"control_name": map[string]any{
					"type":        "string",
					"description": "The human-readable control name.",
				},
				"status": map[string]any{
					"type":        "string",
					"enum":        []string{"covered", "partial", "gap"},
					"description": "covered = document fully addresses the control; partial = addressed but with gaps; gap = not addressed.",
				},
				"evidence": map[string]any{
					"type":        "string",
					"description": "Direct quote or reference from the document supporting the assessment.",
				},
				"gap_description": map[string]any{
					"type":        "string",
					"description": "For partial or gap status: describe specifically what is missing.",
				},
			},
		},
	}

	return []anthropic.ToolUnionParam{
		{OfTool: &getControls},
		{OfTool: &recordAssessment},
	}
}

func systemPrompt() string {
	return strings.TrimSpace(`
You are a compliance analysis agent for Midnight-Core, a compliance document transformation engine.

Your job is to assess policy documents against compliance frameworks and identify gaps.

For EACH requested framework:
1. Call get_framework_controls to retrieve the full list of controls.
2. Read the document carefully and evaluate each control.
3. Call record_control_assessment for EVERY control with an honest assessment:
   - "covered"  — the document clearly and specifically addresses this control
   - "partial"  — the document touches on the control but leaves meaningful gaps
   - "gap"      — the document does not address this control at all

Rules:
- Assess every single control returned — do not skip any.
- Base assessments only on what is explicitly written in the document.
- Provide specific evidence (quote or paraphrase) for covered and partial controls.
- For gaps and partial coverage, describe precisely what is missing.
- Be rigorous: marking a control "covered" when it is only implied counts as audit risk.
`)
}

func userPrompt(req *AnalysisRequest) string {
	frameworks := make([]string, len(req.Frameworks))
	for i, f := range req.Frameworks {
		frameworks[i] = string(f)
	}
	return fmt.Sprintf(
		"Analyze the following document against these compliance frameworks: %s\n\nDocument title: %s\n\n---\n\n%s\n\n---\n\nAssess ALL controls for each framework. Do not skip any.",
		strings.Join(frameworks, ", "),
		req.Title,
		req.Document,
	)
}
