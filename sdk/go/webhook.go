package soroban_pulse

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"strconv"
	"strings"
	"time"
)

// WebhookSignatureHeader is the legacy header Soroban Pulse signs webhook
// deliveries with. It is still sent during the deprecation window.
const WebhookSignatureHeader = "X-Signature-256"

// WebhookSignatureV2Header is the v2 signature header, formatted as
// `t=<unix>,v1=<hex digest>` where the digest is HMAC-SHA256 over
// "<t>.<body>".
const WebhookSignatureV2Header = "X-SorobanPulse-Signature"

// WebhookDeliveryIDHeader carries a unique ID for each delivery.
const WebhookDeliveryIDHeader = "X-SorobanPulse-Delivery-Id"

// DefaultWebhookTolerance is the default maximum age of a v2 signature.
const DefaultWebhookTolerance = 5 * time.Minute

var (
	// ErrMissingSignature means the request carried no signature header.
	ErrMissingSignature = errors.New("webhook: missing signature header")
	// ErrInvalidSignatureFormat means the header is not `sha256=<hex digest>`.
	ErrInvalidSignatureFormat = errors.New("webhook: signature header must be sha256=<hex digest>")
	// ErrSignatureMismatch means no configured secret produced the signature.
	ErrSignatureMismatch = errors.New("webhook: signature mismatch")
	// ErrInvalidSignatureV2Format means the v2 header is not `t=<unix>,v1=<hex digest>`.
	ErrInvalidSignatureV2Format = errors.New("webhook: signature header must be t=<unix>,v1=<hex digest>")
	// ErrTimestampOutOfTolerance means the signed timestamp is too old or too far in the future.
	ErrTimestampOutOfTolerance = errors.New("webhook: signature timestamp outside tolerance window")
)

// VerifyWebhook checks a delivery's X-Signature-256 header against the raw
// request body, as described in docs/webhook_signing.md: the header is
// `sha256=` followed by the hex HMAC-SHA256 of the body keyed with the webhook
// secret. Pass several secrets during rotation; the request is accepted if any
// of them matches. Digests are compared in constant time.
func VerifyWebhook(payload []byte, signatureHeader string, secrets ...string) error {
	if signatureHeader == "" {
		return ErrMissingSignature
	}
	hexDigest, ok := strings.CutPrefix(signatureHeader, "sha256=")
	if !ok {
		return ErrInvalidSignatureFormat
	}
	provided, err := hex.DecodeString(hexDigest)
	if err != nil {
		return ErrInvalidSignatureFormat
	}

	matched := false
	for _, secret := range secrets {
		mac := hmac.New(sha256.New, []byte(secret))
		mac.Write(payload)
		// Check every secret so timing does not reveal which one matched.
		if hmac.Equal(provided, mac.Sum(nil)) {
			matched = true
		}
	}
	if !matched {
		return ErrSignatureMismatch
	}
	return nil
}

// VerifyWebhookV2 checks a delivery's X-SorobanPulse-Signature header against
// the raw request body. The header is `t=<unix>,v1=<hex digest>` where the
// digest is the hex HMAC-SHA256 of "<t>.<body>" keyed with the webhook secret.
// The signed timestamp must be within tolerance of now (pass 0 for
// DefaultWebhookTolerance). Pass several secrets during rotation; the request
// is accepted if any of them matches. Digests are compared in constant time.
func VerifyWebhookV2(payload []byte, signatureHeader string, tolerance time.Duration, secrets ...string) error {
	if signatureHeader == "" {
		return ErrMissingSignature
	}
	if tolerance <= 0 {
		tolerance = DefaultWebhookTolerance
	}

	var timestampStr, hexDigest string
	var haveTimestamp, haveDigest bool
	for _, part := range strings.Split(signatureHeader, ",") {
		part = strings.TrimSpace(part)
		if value, ok := strings.CutPrefix(part, "t="); ok {
			timestampStr = value
			haveTimestamp = true
		} else if value, ok := strings.CutPrefix(part, "v1="); ok {
			hexDigest = value
			haveDigest = true
		}
	}
	if !haveTimestamp || !haveDigest {
		return ErrInvalidSignatureV2Format
	}

	timestamp, err := strconv.ParseInt(timestampStr, 10, 64)
	if err != nil {
		return ErrInvalidSignatureV2Format
	}
	provided, err := hex.DecodeString(hexDigest)
	if err != nil {
		return ErrInvalidSignatureV2Format
	}

	age := time.Since(time.Unix(timestamp, 0))
	if age > tolerance || age < -tolerance {
		return ErrTimestampOutOfTolerance
	}

	signedPayload := fmt.Sprintf("%s.%s", timestampStr, payload)
	matched := false
	for _, secret := range secrets {
		mac := hmac.New(sha256.New, []byte(secret))
		mac.Write([]byte(signedPayload))
		// Check every secret so timing does not reveal which one matched.
		if hmac.Equal(provided, mac.Sum(nil)) {
			matched = true
		}
	}
	if !matched {
		return ErrSignatureMismatch
	}
	return nil
}
