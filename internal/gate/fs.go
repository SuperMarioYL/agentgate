package gate

import (
	"path/filepath"

	agentctx "github.com/SuperMarioYL/agentgate/internal/context"
	"github.com/SuperMarioYL/agentgate/internal/policy"
)

// FSGate enforces filesystem-write scope. It resolves an fs_write action against
// the policy: writes are confined to declared paths, attempts outside are
// denied or asked.
type FSGate struct {
	engine *Engine
}

// NewFSGate builds a filesystem-action gate over an Engine.
func NewFSGate(e *Engine) *FSGate { return &FSGate{engine: e} }

// CheckWrite asks the policy whether the agent may write to path with the given
// intent. It returns true when the write is permitted.
func (g *FSGate) CheckWrite(path, intent, agent string) (bool, error) {
	abs, err := filepath.Abs(path)
	if err != nil {
		abs = path
	}
	req := agentctx.GateRequest{
		Action: agentctx.ActionFSWrite,
		Target: abs,
		Intent: intent,
		Agent:  agent,
	}
	dec, err := g.engine.Decide(req)
	if err != nil {
		return false, err
	}
	return dec == policy.Allow, nil
}
