package compliance

// Framework identifies a compliance standard.
type Framework string

const (
	HIPAA    Framework = "HIPAA"
	HITRUST  Framework = "HITRUST"
	PCIDSS   Framework = "PCI_DSS"
	ISO27001 Framework = "ISO_27001"
	NISTCSF  Framework = "NIST_CSF"
	SOC2     Framework = "SOC2"
)

// Control is a single requirement within a framework.
type Control struct {
	ID          string `json:"id"`
	Name        string `json:"name"`
	Description string `json:"description"`
}

// ControlStatus represents how well a document covers a control.
type ControlStatus string

const (
	StatusCovered ControlStatus = "covered"
	StatusPartial ControlStatus = "partial"
	StatusGap     ControlStatus = "gap"
)

// ControlAssessment is Claude's finding for one control.
type ControlAssessment struct {
	Framework      Framework     `json:"framework"`
	ControlID      string        `json:"control_id"`
	ControlName    string        `json:"control_name"`
	Status         ControlStatus `json:"status"`
	Evidence       string        `json:"evidence,omitempty"`
	GapDescription string        `json:"gap_description,omitempty"`
}

// AnalysisRequest is the incoming HTTP payload.
type AnalysisRequest struct {
	Title      string      `json:"title"`
	Document   string      `json:"document"`
	Frameworks []Framework `json:"frameworks"`
}

// FrameworkResult aggregates assessments for one framework.
type FrameworkResult struct {
	Framework       Framework           `json:"framework"`
	Assessments     []ControlAssessment `json:"assessments"`
	CoveredCount    int                 `json:"covered_count"`
	PartialCount    int                 `json:"partial_count"`
	GapCount        int                 `json:"gap_count"`
	CoveragePercent float64             `json:"coverage_percent"`
}

// AnalysisResult is the final HTTP response.
type AnalysisResult struct {
	Title      string            `json:"title"`
	Frameworks []FrameworkResult `json:"frameworks"`
}

// ProgressEvent is streamed over SSE as Claude works through each control.
type ProgressEvent struct {
	Type        string        `json:"type"`         // "framework_start" | "control_assessed"
	Framework   Framework     `json:"framework,omitempty"`
	ControlID   string        `json:"control_id,omitempty"`
	ControlName string        `json:"control_name,omitempty"`
	Status      ControlStatus `json:"status,omitempty"`
	Message     string        `json:"message,omitempty"`
}
