package collect

import (
	"net/netip"

	"github.com/jajera/aws-netpath/internal/model"
)

func parsePrefix(s string) (netip.Prefix, error) {
	if !containsSlash(s) {
		a, err := netip.ParseAddr(s)
		if err != nil {
			return netip.Prefix{}, err
		}
		return netip.PrefixFrom(a, a.BitLen()), nil
	}
	p, err := netip.ParsePrefix(s)
	if err != nil {
		return netip.Prefix{}, err
	}
	return p.Masked(), nil
}

func containsSlash(s string) bool {
	for i := 0; i < len(s); i++ {
		if s[i] == '/' {
			return true
		}
	}
	return false
}

func mergeSnapshot(dst, src *model.Snapshot) {
	mergeMap(dst.VPCs, src.VPCs)
	mergeMap(dst.Subnets, src.Subnets)
	mergeMap(dst.RouteTables, src.RouteTables)
	mergeMap(dst.SecurityGroups, src.SecurityGroups)
	mergeMap(dst.NACLs, src.NACLs)
	mergeMap(dst.NetworkIfaces, src.NetworkIfaces)
	mergeMap(dst.TransitGateways, src.TransitGateways)
	mergeMap(dst.TGWRouteTables, src.TGWRouteTables)
	mergeMap(dst.TGWAttachments, src.TGWAttachments)
	mergeMap(dst.VPCPeerings, src.VPCPeerings)
	mergeMap(dst.Firewalls, src.Firewalls)
	mergeMap(dst.FirewallPolicies, src.FirewallPolicies)
	mergeMap(dst.RuleGroups, src.RuleGroups)
}

func mergeMap[K comparable, V any](dst, src map[K]V) {
	for k, v := range src {
		dst[k] = v
	}
}
