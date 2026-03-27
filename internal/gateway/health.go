package gateway

import (
	"sync"
	"time"
)

type SubsystemState string

const (
	StateStarting     SubsystemState = "starting"
	StateRunning      SubsystemState = "running"
	StateReconnecting SubsystemState = "reconnecting"
	StateStopped      SubsystemState = "stopped"
	StateError        SubsystemState = "error"
	StateDisabled     SubsystemState = "disabled"
)

type SubsystemHealth struct {
	State     SubsystemState         `json:"state"`
	Since     time.Time              `json:"since"`
	LastError string                 `json:"last_error,omitempty"`
	Details   map[string]interface{} `json:"details,omitempty"`
}

type HealthSnapshot struct {
	StartedAt time.Time       `json:"started_at"`
	UptimeMs  int64           `json:"uptime_ms"`
	Gateway   SubsystemHealth `json:"gateway"`
	Watcher   SubsystemHealth `json:"watcher"`
	API       SubsystemHealth `json:"api"`
	Guardrail SubsystemHealth `json:"guardrail"`
	Telemetry SubsystemHealth `json:"telemetry"`
	Splunk    SubsystemHealth `json:"splunk"`
}

type SidecarHealth struct {
	mu        sync.RWMutex
	gateway   SubsystemHealth
	watcher   SubsystemHealth
	api       SubsystemHealth
	guardrail SubsystemHealth
	telemetry SubsystemHealth
	splunk    SubsystemHealth
	startedAt time.Time
}

func NewSidecarHealth() *SidecarHealth {
	now := time.Now()
	initial := SubsystemHealth{State: StateStarting, Since: now}
	disabled := SubsystemHealth{State: StateDisabled, Since: now}
	return &SidecarHealth{
		gateway:   initial,
		watcher:   initial,
		api:       initial,
		guardrail: disabled,
		telemetry: disabled,
		splunk:    disabled,
		startedAt: now,
	}
}

func (h *SidecarHealth) SetGateway(state SubsystemState, lastErr string, details map[string]interface{}) {
	h.mu.Lock()
	defer h.mu.Unlock()
	h.gateway = SubsystemHealth{
		State:     state,
		Since:     time.Now(),
		LastError: lastErr,
		Details:   details,
	}
}

func (h *SidecarHealth) SetWatcher(state SubsystemState, lastErr string, details map[string]interface{}) {
	h.mu.Lock()
	defer h.mu.Unlock()
	h.watcher = SubsystemHealth{
		State:     state,
		Since:     time.Now(),
		LastError: lastErr,
		Details:   details,
	}
}

func (h *SidecarHealth) SetAPI(state SubsystemState, lastErr string, details map[string]interface{}) {
	h.mu.Lock()
	defer h.mu.Unlock()
	h.api = SubsystemHealth{
		State:     state,
		Since:     time.Now(),
		LastError: lastErr,
		Details:   details,
	}
}

func (h *SidecarHealth) SetGuardrail(state SubsystemState, lastErr string, details map[string]interface{}) {
	h.mu.Lock()
	defer h.mu.Unlock()
	h.guardrail = SubsystemHealth{
		State:     state,
		Since:     time.Now(),
		LastError: lastErr,
		Details:   details,
	}
}

func (h *SidecarHealth) SetTelemetry(state SubsystemState, lastErr string, details map[string]interface{}) {
	h.mu.Lock()
	defer h.mu.Unlock()
	h.telemetry = SubsystemHealth{
		State:     state,
		Since:     time.Now(),
		LastError: lastErr,
		Details:   details,
	}
}

func (h *SidecarHealth) SetSplunk(state SubsystemState, lastErr string, details map[string]interface{}) {
	h.mu.Lock()
	defer h.mu.Unlock()
	h.splunk = SubsystemHealth{
		State:     state,
		Since:     time.Now(),
		LastError: lastErr,
		Details:   details,
	}
}

func (h *SidecarHealth) Snapshot() HealthSnapshot {
	h.mu.RLock()
	defer h.mu.RUnlock()
	return HealthSnapshot{
		StartedAt: h.startedAt,
		UptimeMs:  time.Since(h.startedAt).Milliseconds(),
		Gateway:   h.gateway,
		Watcher:   h.watcher,
		API:       h.api,
		Guardrail: h.guardrail,
		Telemetry: h.telemetry,
		Splunk:    h.splunk,
	}
}
