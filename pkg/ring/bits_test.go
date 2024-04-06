package ring

import (
	"math/bits"
	"testing"
)

func TestBitsFunc(t *testing.T) {
	last := bits.Len32(0)
	t.Logf("%d\n", last)
	var i uint64 = 1
	for i = 1; ; i++ {
		nl := bits.Len64(i - 1)
		if last != nl {
			last = nl
			t.Logf("%d -> %d\n", i, last)
		}
	}
}
