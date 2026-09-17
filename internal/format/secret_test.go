package format

// Requirement 14.7: no credential material or secret value is ever rendered.
//
// The scanner below is deliberately written from scratch rather than reusing the
// redactor's own patterns. A test that asks the redactor whether the redactor
// caught everything proves nothing; this one describes credential material
// independently, and every pattern is exercised against a control corpus first,
// so a scan that finds nothing means the scan works and found nothing.

import (
	"regexp"
	"strings"
	"testing"

	"github.com/jajera/aws-netpath/internal/model"
)

// credentialShapes describes credential material independently of the redactor.
type credentialShape struct {
	name string
	re   *regexp.Regexp
	// control is a string this pattern must match, which is what proves the scan
	// is not vacuous.
	control string
}

func credentialShapes() []credentialShape {
	return []credentialShape{
		{
			"aws access key id",
			regexp.MustCompile(`\b(?:AKIA|ASIA|AIDA|AROA)[0-9A-Z]{16}\b`),
			"AKIAIOSFODNN7EXAMPLE",
		},
		{
			"aws secret access key",
			regexp.MustCompile(`(?i)aws[_-]?secret[_-]?access[_-]?key\s*[:=]\s*[A-Za-z0-9/+=]{20,}`),
			"aws_secret_access_key=wJalrXUtnFEMIK7MDENGbPxRfiCYEXAMPLEKEY",
		},
		{
			"aws session token",
			regexp.MustCompile(`(?i)(?:aws[_-]?)?session[_-]?token\s*[:=]\s*[A-Za-z0-9/+=_-]{16,}`),
			"AWS_SESSION_TOKEN=IQoJb3JpZ2luX2VjEXAMPLETOKENVALUE",
		},
		{
			"authorization value",
			regexp.MustCompile(`(?i)authorization\s*[:=]\s*\S{8,}`),
			"Authorization: AWS4-HMAC-SHA256 Credential=EXAMPLESIGNATUREVALUE",
		},
		{
			"bearer token",
			regexp.MustCompile(`(?i)\bbearer\s+[A-Za-z0-9._~+/=-]{8,}`),
			"bearer eyJhbGciOiJIUzI1NiEXAMPLEJWTVALUE",
		},
		{
			"password or api key",
			regexp.MustCompile(`(?i)\b(?:password|passwd|api[_-]?key|client[_-]?secret)\s*[:=]\s*\S{6,}`),
			"password=correct-horse-battery",
		},
		{
			"private key material",
			regexp.MustCompile(`-----BEGIN[A-Z ]*PRIVATE KEY-----`),
			"-----BEGIN RSA PRIVATE KEY-----",
		},
	}
}

// TestCredentialScannerIsNotVacuous runs the scanner against a control corpus. If
// this fails, the scan below is not looking for anything and its silence means
// nothing.
func TestCredentialScannerIsNotVacuous(t *testing.T) {
	for _, shape := range credentialShapes() {
		t.Run(shape.name, func(t *testing.T) {
			if !shape.re.MatchString(shape.control) {
				t.Fatalf("the %s pattern does not match its own control string %q", shape.name, shape.control)
			}
			if found := scanCredentials(shape.control); len(found) == 0 {
				t.Fatalf("the scan missed a planted %s", shape.name)
			}
		})
	}
}

// TestRenderedOutputCarriesNoCredentialMaterial scans every rendering of every
// fixture. This is the ordinary case: nothing planted, nothing found.
func TestRenderedOutputCarriesNoCredentialMaterial(t *testing.T) {
	reports := map[string]Report{
		"blocked":   FromDiagnosis(blockedDiagnosis(t)),
		"abstained": FromDiagnosis(abstainedDiagnosis(t)),
		"repeated":  FromDiagnosis(repeatedRowsDiagnosis(t)),
		"compared":  FromComparison(comparisonResult(t)),
	}

	for name, report := range reports {
		for _, mode := range []Mode{ModeText, ModeMarkdown, ModeJSON} {
			t.Run(name+" "+string(mode), func(t *testing.T) {
				if found := scanCredentials(render(t, report, Options{Mode: mode})); len(found) > 0 {
					t.Errorf("rendered output carries credential material: %s", strings.Join(found, "; "))
				}
			})
		}
	}
}

// TestPlantedCredentialsAreRedacted is the case the redactor exists for.
//
// Every string a report carries comes from somewhere this package does not
// control — a resource name, a tag, the output of a host command — so the
// guarantee has to hold for input that is not clean. Each planted value goes in
// through a different field, because a redactor that covers the citations and
// misses the notes is not a guarantee.
func TestPlantedCredentialsAreRedacted(t *testing.T) {
	d := blockedDiagnosis(t)
	d.Source = "10.0.1.10 collected with AKIAIOSFODNN7EXAMPLE"
	d.Host = "i-0abcdef123456789a (aws_session_token=IQoJb3JpZ2luX2VjEXAMPLETOKENVALUE)"
	d.Notes = append(d.Notes, "Authorization: AWS4-HMAC-SHA256 Credential=EXAMPLESIGNATUREVALUE")
	d.Verdict.Results[0].Citations = append(d.Verdict.Results[0].Citations,
		model.Citation{
			Kind:       "command",
			Identifier: "firewall-cmd --zone=public --list-all",
			Detail:     "password=correct-horse-battery and aws_secret_access_key=wJalrXUtnFEMIK7MDENGbPxRfiCYEXAMPLEKEY",
		},
		model.Citation{
			Kind:       "command",
			Identifier: "-----BEGIN RSA PRIVATE KEY-----",
			Detail:     "bearer eyJhbGciOiJIUzI1NiEXAMPLEJWTVALUE",
		},
	)

	planted := []string{
		"AKIAIOSFODNN7EXAMPLE",
		"IQoJb3JpZ2luX2VjEXAMPLETOKENVALUE",
		"EXAMPLESIGNATUREVALUE",
		"correct-horse-battery",
		"wJalrXUtnFEMIK7MDENGbPxRfiCYEXAMPLEKEY",
		"eyJhbGciOiJIUzI1NiEXAMPLEJWTVALUE",
		"BEGIN RSA PRIVATE KEY",
	}

	report := FromDiagnosis(d)
	for _, mode := range []Mode{ModeText, ModeMarkdown, ModeJSON} {
		t.Run(string(mode), func(t *testing.T) {
			got := render(t, report, Options{Mode: mode})
			for _, secret := range planted {
				if strings.Contains(got, secret) {
					t.Errorf("planted %q survived rendering:\n%s", secret, got)
				}
			}
			if found := scanCredentials(got); len(found) > 0 {
				t.Errorf("rendered output carries credential material: %s", strings.Join(found, "; "))
			}
			if !strings.Contains(got, redactedMarker) {
				t.Errorf("nothing was marked as withheld, so the reader cannot tell something was:\n%s", got)
			}
			// The evidence around a withheld value has to survive it, or the
			// redaction has cost the reader the citation as well as the secret.
			if !strings.Contains(got, "firewall-cmd --zone=public --list-all") {
				t.Errorf("the citation around a redacted value was lost:\n%s", got)
			}
		})
	}
}

// TestRedactionLeavesEvidenceIntact guards the other failure mode: a redactor
// aggressive enough to eat the resource identifiers and rule references the
// citations exist to carry is no use either.
func TestRedactionLeavesEvidenceIntact(t *testing.T) {
	intact := []string{
		"rtb-0aaa1111bbbb2222c",
		"acl-0123456789abcdef0",
		"sg-0123456789abcdef0",
		"eni-0123456789abcdef0",
		"i-0abcdef123456789a",
		"nfr-allow-east-west sid 3 (priority 6)",
		"firewall-cmd --zone=public --list-rich-rules",
		"ss -tlnp",
		"arn:aws:secretsmanager:us-east-1:111122223333:secret:app-config",
	}

	d := blockedDiagnosis(t)
	d.Notes = append(d.Notes, "arn:aws:secretsmanager:us-east-1:111122223333:secret:app-config")

	got := render(t, FromDiagnosis(d), Options{Mode: ModeText})
	for _, want := range intact {
		if !strings.Contains(got, want) {
			t.Errorf("redaction removed evidence %q:\n%s", want, got)
		}
	}
}

// scanCredentials reports every credential shape found in s.
//
// The redaction marker is removed before scanning. A label whose value has been
// withheld still looks like a labelled credential, and flagging it would make the
// scan complain about the very evidence that the guarantee is holding.
func scanCredentials(s string) []string {
	s = strings.ReplaceAll(s, redactedMarker, "")
	var found []string
	for _, shape := range credentialShapes() {
		for _, m := range shape.re.FindAllString(s, -1) {
			found = append(found, shape.name+": "+m)
		}
	}
	return found
}
