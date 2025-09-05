package awsig

import (
	"bytes"
	"io"
	"strings"
	"testing"

	"github.com/zeebo/assert"
)

func TestIntegrityReader(t *testing.T) {
	const data = "Lorem ipsum dolor sit amet, consectetur adipiscing elit, sed do eiusmod tempor"

	ei := newExpectedIntegrity()
	ei.addEncodedString(algorithmCRC32, "AMHftQ==")
	ei.addEncodedString(algorithmCRC32C, "L9qeQg==")
	ei.addEncodedString(algorithmCRC64NVME, "sa/Hm4j1eiw=")
	ei.addEncodedString(algorithmMD5, "35eb3b58fa38ad797aa89144f54199c3")
	ei.addEncodedString(algorithmSHA1, "kCwbMV39/ST8gj+3T1hnHpxuz6Y=")
	ei.addEncodedString(algorithmSHA256, "HD+Vir2FxUkFyX/o4GKP52SVcRlion2q40AzeBSG2gA=")
	ei.addEncodedString(algorithmHashedPayload, "1c3f958abd85c54905c97fe8e0628fe76495711962a27daae34033781486da00")

	ir := newIntegrityReader(strings.NewReader(data), []checksumAlgorithm{
		algorithmCRC32,
		algorithmCRC32C,
		algorithmCRC64NVME,
		algorithmSHA1,
		algorithmSHA256,
		algorithmHashedPayload,
	})

	buf := bytes.NewBuffer(nil)

	_, err := io.Copy(buf, ir)
	assert.NoError(t, err)

	assert.Equal(t, data, buf.String())
	assert.NoError(t, ir.verify(ei))
}
