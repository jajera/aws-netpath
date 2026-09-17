package ops

import (
	"github.com/jajera/aws-netpath/internal/query"
)

// QueryRequest asks whether one flow reaches its destination.
type QueryRequest struct {
	SnapshotPath string
	From         string
	To           string
	Proto        string
	Port         int
	// SkipFirewall evaluates routing and NACLs only, which isolates a policy
	// question from a routing question.
	SkipFirewall bool
}

// Query walks a flow from source to destination against a snapshot, reporting
// every layer it met and the resource that decided each one.
//
// Validation happens in a fixed order — required fields, protocol, port,
// addresses, then the snapshot itself — so that an invocation with several
// problems always reports the same one first.
func Query(req QueryRequest) (*query.Result, error) {
	if err := requireFields(
		requiredField{"snapshot", req.SnapshotPath},
		requiredField{"from", req.From},
		requiredField{"to", req.To},
	); err != nil {
		return nil, err
	}

	proto, err := parseProtoPort(req.Proto, req.Port)
	if err != nil {
		return nil, err
	}

	src, dst, err := parseEndpoints(req.From, req.To)
	if err != nil {
		return nil, err
	}

	snap, err := loadSnapshot(req.SnapshotPath)
	if err != nil {
		return nil, err
	}

	return query.Run(query.Options{
		Snapshot:     snap,
		SrcIP:        src,
		DstIP:        dst,
		Proto:        proto,
		Port:         req.Port,
		SkipFirewall: req.SkipFirewall,
	})
}
