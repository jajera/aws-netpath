package collect

import (
	"context"
	"fmt"
	"sync"
	"time"

	"github.com/jajera/aws-netpath/internal/awsx"
	"github.com/jajera/aws-netpath/internal/collect/aws"
	"github.com/jajera/aws-netpath/internal/config"
	"github.com/jajera/aws-netpath/internal/model"
	"golang.org/x/sync/errgroup"
)

// Options configures a collection run.
type Options struct {
	Targets  []config.Target
	External []config.ExternalNetwork
	// Timeout applies per account+region target. Zero means no timeout.
	Timeout int // seconds, set from CLI
}

// Result summarizes what was collected.
type Result struct {
	Snapshot *model.Snapshot
	Targets  int
	Errors   int
}

// Run collects from every target in parallel and merges into one snapshot.
func Run(ctx context.Context, opts Options) (*Result, error) {
	if len(opts.Targets) == 0 {
		return nil, fmt.Errorf("no collection targets")
	}

	snap := model.NewSnapshot()
	mu := sync.Mutex{}
	var totalErrors int

	g, gctx := errgroup.WithContext(ctx)
	g.SetLimit(8) // cap concurrent account+region API calls

	for _, target := range opts.Targets {
		target := target
		g.Go(func() error {
			tctx := gctx
			if opts.Timeout > 0 {
				var cancel context.CancelFunc
				tctx, cancel = context.WithTimeout(gctx, time.Duration(opts.Timeout)*time.Second)
				defer cancel()
			}

			clients, err := awsx.Open(tctx, awsx.OpenOptions{
				Profile:         target.Profile,
				Region:          target.Region,
				AssumeRole:      target.AssumeRole,
				RoleSessionName: target.RoleSessionName,
			})
			if err != nil {
				mu.Lock()
				snap.CollectionErrors = append(snap.CollectionErrors, model.CollectionError{
					Region:   target.Region,
					Account:  target.AccountID,
					Resource: fmt.Sprintf("profile:%s", target.Profile),
					Err:      err.Error(),
				})
				totalErrors++
				mu.Unlock()
				return nil // keep collecting other targets
			}

			if target.AccountID != "" && clients.AccountID != target.AccountID {
				mu.Lock()
				snap.CollectionErrors = append(snap.CollectionErrors, model.CollectionError{
					Region:   target.Region,
					Account:  target.AccountID,
					Resource: fmt.Sprintf("profile:%s", target.Profile),
					Err:      fmt.Sprintf("config account id %q does not match caller identity %q", target.AccountID, clients.AccountID),
				})
				totalErrors++
				mu.Unlock()
				return nil
			}

			partial, errs := aws.CollectRegion(tctx, clients)

			mu.Lock()
			mergeSnapshot(snap, partial)
			snap.CollectionErrors = append(snap.CollectionErrors, errs...)
			totalErrors += len(errs)
			recordAccountRegion(snap, clients.AccountID, clients.Region)
			mu.Unlock()
			return nil
		})
	}

	if err := g.Wait(); err != nil {
		return nil, err
	}

	addExternalNetworks(snap, opts.External)

	return &Result{
		Snapshot: snap,
		Targets:  len(opts.Targets),
		Errors:   totalErrors,
	}, nil
}

func recordAccountRegion(snap *model.Snapshot, account, region string) {
	if account != "" && !contains(snap.Accounts, account) {
		snap.Accounts = append(snap.Accounts, account)
	}
	if region != "" && !contains(snap.Regions, region) {
		snap.Regions = append(snap.Regions, region)
	}
}

func contains(ss []string, v string) bool {
	for _, s := range ss {
		if s == v {
			return true
		}
	}
	return false
}

func addExternalNetworks(snap *model.Snapshot, externals []config.ExternalNetwork) {
	for _, ext := range externals {
		id := ext.Name
		if id == "" {
			continue
		}
		en := &model.ExternalNetwork{
			Meta: model.Meta{
				ID:   id,
				Name: ext.Name,
			},
			ReachedVia:  ext.ReachedVia,
			Description: ext.Description,
		}
		for _, cidr := range ext.CIDRs {
			if p, err := parsePrefix(cidr); err == nil {
				en.CIDRs = append(en.CIDRs, p)
			}
		}
		snap.ExternalNetworks[id] = en
	}
}
