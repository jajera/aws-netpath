package verify

import (
	"net/netip"

	"github.com/jajera/aws-netpath/internal/model"
	"github.com/jajera/aws-netpath/internal/query"
)

// Agreement is whether the offline model and AWS Reachability Analyzer agree.
type Agreement string

const (
	AgreementMatch        Agreement = "MATCH"
	AgreementMismatch     Agreement = "MISMATCH"
	AgreementInconclusive Agreement = "INCONCLUSIVE"
)

// CompareVerdict maps model and AWS outcomes to an agreement label.
func CompareVerdict(model query.Verdict, awsReachable *bool) (Agreement, string) {
	if awsReachable == nil {
		return AgreementInconclusive, "AWS Reachability Analyzer did not return a result"
	}
	modelPermits := model == query.VerdictPermitted
	awsPermits := *awsReachable
	switch {
	case modelPermits && awsPermits:
		return AgreementMatch, "model and AWS both permit the flow"
	case !modelPermits && !awsPermits:
		return AgreementMatch, "model and AWS both block the flow"
	case modelPermits && !awsPermits:
		return AgreementMismatch, "model permits but AWS blocks"
	default:
		return AgreementMismatch, "model blocks but AWS permits"
	}
}

// SubnetForAddr returns the VPC and region containing addr, if any.
func SubnetForAddr(snap *model.Snapshot, addr netip.Addr) (vpcID, region string, ok bool) {
	bestBits := -1
	for _, s := range snap.Subnets {
		if !s.CIDR.Contains(addr) {
			continue
		}
		if s.CIDR.Bits() > bestBits {
			vpcID = s.VPCID
			region = s.Region
			bestBits = s.CIDR.Bits()
			ok = true
		}
	}
	return vpcID, region, ok
}

// SameRegion reports whether both addresses sit in one region according to the snapshot.
func SameRegion(snap *model.Snapshot, src, dst netip.Addr) bool {
	_, srcR, srcOK := SubnetForAddr(snap, src)
	_, dstR, dstOK := SubnetForAddr(snap, dst)
	return srcOK && dstOK && srcR != "" && srcR == dstR
}
