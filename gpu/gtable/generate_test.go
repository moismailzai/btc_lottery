package gtable

import (
	"math/big"
	"testing"
)

func TestG(t *testing.T) {
	g := G()
	if g.X.Cmp(Gx) != 0 {
		t.Errorf("G.X mismatch")
	}
	if g.Y.Cmp(Gy) != 0 {
		t.Errorf("G.Y mismatch")
	}
}

func TestDouble(t *testing.T) {
	// 2G should be a known value
	g := G()
	twoG := Double(g)

	// Known value for 2G (verified with multiple sources)
	expectedX, _ := new(big.Int).SetString("C6047F9441ED7D6D3045406E95C07CD85C778E4B8CEF3CA7ABAC09B95C709EE5", 16)
	// Compute expected Y: 2G computed via G+G should match
	expectedTwoG := Add(g, g)

	if twoG.X.Cmp(expectedX) != 0 {
		t.Errorf("2G.X mismatch: got %s", twoG.X.Text(16))
	}
	if twoG.X.Cmp(expectedTwoG.X) != 0 || twoG.Y.Cmp(expectedTwoG.Y) != 0 {
		t.Errorf("Double(G) != Add(G,G)")
	}
	t.Logf("2G.X = %s", twoG.X.Text(16))
	t.Logf("2G.Y = %s", twoG.Y.Text(16))
}

func TestAdd(t *testing.T) {
	g := G()

	// G + G should equal 2G
	result := Add(g, g)
	expected := Double(g)

	if result.X.Cmp(expected.X) != 0 {
		t.Errorf("G+G X mismatch")
	}
	if result.Y.Cmp(expected.Y) != 0 {
		t.Errorf("G+G Y mismatch")
	}

	// G + 2G = 3G
	twoG := Double(g)
	threeG := Add(g, twoG)

	// Known value for 3G
	expectedX, _ := new(big.Int).SetString("F9308A019258C31049344F85F89D5229B531C845836F99B08601F113BCE036F9", 16)
	expectedY, _ := new(big.Int).SetString("388F7B0F632DE8140FE337E62A37F3566500A99934C2231B6CB9FD7584B8E672", 16)

	if threeG.X.Cmp(expectedX) != 0 {
		t.Errorf("3G.X mismatch: got %s", threeG.X.Text(16))
	}
	if threeG.Y.Cmp(expectedY) != 0 {
		t.Errorf("3G.Y mismatch: got %s", threeG.Y.Text(16))
	}
}

func TestToBytes(t *testing.T) {
	g := G()
	xBytes, yBytes := g.ToBytes()

	// Reconstruct and verify
	xBig := new(big.Int)
	yBig := new(big.Int)
	for i := 31; i >= 0; i-- {
		xBig.Lsh(xBig, 8)
		xBig.Or(xBig, big.NewInt(int64(xBytes[i])))
		yBig.Lsh(yBig, 8)
		yBig.Or(yBig, big.NewInt(int64(yBytes[i])))
	}

	if xBig.Cmp(Gx) != 0 {
		t.Errorf("ToBytes X roundtrip failed: got %s", xBig.Text(16))
	}
	if yBig.Cmp(Gy) != 0 {
		t.Errorf("ToBytes Y roundtrip failed: got %s", yBig.Text(16))
	}
}

func TestGenerateFirstChunk(t *testing.T) {
	// Generate just the first few points to verify correctness
	gt, err := Generate(nil)
	if err != nil {
		t.Fatalf("Generate failed: %v", err)
	}

	// Verify first point is G
	if err := gt.Verify(); err != nil {
		t.Fatalf("Verify failed: %v", err)
	}

	// Verify second point is 2G
	p1, err := gt.PointAt(1)
	if err != nil {
		t.Fatalf("PointAt(1) failed: %v", err)
	}

	twoG := Double(G())
	if p1.X.Cmp(twoG.X) != 0 || p1.Y.Cmp(twoG.Y) != 0 {
		t.Errorf("Point 1 should be 2G")
	}

	// Verify third point is 3G
	p2, err := gt.PointAt(2)
	if err != nil {
		t.Fatalf("PointAt(2) failed: %v", err)
	}

	threeG := Add(G(), twoG)
	if p2.X.Cmp(threeG.X) != 0 || p2.Y.Cmp(threeG.Y) != 0 {
		t.Errorf("Point 2 should be 3G")
	}

	t.Logf("GTable size: X=%d bytes, Y=%d bytes", len(gt.X), len(gt.Y))
}

func TestScalarMult(t *testing.T) {
	// Test that we can use GTable for scalar multiplication
	gt, err := Generate(nil)
	if err != nil {
		t.Fatalf("Generate failed: %v", err)
	}

	// Simple test: compute 5*G using GTable
	// 5 = 0x0005 in first 16-bit chunk
	// So we should get GTable[4] (index = chunk_value - 1)
	fiveG, err := gt.PointAt(4)
	if err != nil {
		t.Fatalf("PointAt(4) failed: %v", err)
	}

	// Compute 5G directly
	g := G()
	expected := g
	for i := 0; i < 4; i++ {
		expected = Add(expected, g)
	}

	if fiveG.X.Cmp(expected.X) != 0 || fiveG.Y.Cmp(expected.Y) != 0 {
		t.Errorf("5G mismatch")
		t.Logf("Got:      X=%s Y=%s", fiveG.X.Text(16), fiveG.Y.Text(16))
		t.Logf("Expected: X=%s Y=%s", expected.X.Text(16), expected.Y.Text(16))
	}
}
