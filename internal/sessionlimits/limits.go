// Package sessionlimits defines finite operator-selected admission bounds.
// These are not licensing tiers or a hardware capacity certification.
package sessionlimits

const (
	DefaultTotal    = 8
	DefaultPerOwner = 2
	// MaxTotal bounds admission bookkeeping in this implementation. A host's
	// tested capacity can be much lower; kernel resource policy is separate.
	MaxTotal = 128
)

type Limits struct {
	Total    int `json:"total"`
	PerOwner int `json:"per_owner"`
}

func Default() Limits { return Limits{Total: DefaultTotal, PerOwner: DefaultPerOwner} }

func (l Limits) Valid() bool {
	return l.Total >= 1 && l.Total <= MaxTotal && l.PerOwner >= 1 && l.PerOwner <= l.Total
}
