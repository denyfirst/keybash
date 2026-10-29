package identity

import (
	"net/url"
	"strings"
	"testing"

	"github.com/boombuler/barcode/qr"
)

// formatInfo reads a QR code's 15-bit format information from one of its two
// copies, in the module positions ISO/IEC 18004 gives (x a column, y a row
// from the top). A transposed or mirrored drawing reads back as other bits.
func formatInfo(rows []string, second bool) int {
	n, value := len(rows), 0
	dark := func(x, y int) int {
		if rows[y][x] == '1' {
			return 1
		}
		return 0
	}
	for i := range 15 {
		var bit int
		switch {
		case second && i < 8:
			bit = dark(n-1-i, 8)
		case second:
			bit = dark(8, n-15+i)
		case i < 6:
			bit = dark(8, i)
		case i < 8:
			bit = dark(8, i+1)
		case i == 8:
			bit = dark(7, 8)
		default:
			bit = dark(14-i, 8)
		}
		value |= bit << i
	}
	return value
}

// formatCode is the BCH-protected, masked format word for 5 data bits.
func formatCode(data int) int {
	remainder := data
	for range 10 {
		remainder = remainder<<1 ^ (remainder>>9)*0x537
	}
	return (data<<10 | remainder) ^ 0x5412
}

func TestSeedQRCarriesExactlyTheSeed(t *testing.T) {
	seed, e := newSeed()
	if e != nil {
		t.Fatal("seed failed")
	}
	const user = "alice.ops-1"
	// The key URI names this account and issuer and carries the seed, nothing else.
	u, e := url.Parse(seedURI(user, seed))
	if e != nil || u.Scheme != "otpauth" || u.Host != "totp" || u.Path != "/Keybash:"+user || u.RawQuery != "secret="+seed+"&issuer=Keybash" {
		t.Fatal("key URI is not the account's TOTP seed")
	}
	if q := u.Query(); len(q) != 2 || q.Get("secret") != seed || q.Get("issuer") != "Keybash" {
		t.Fatal("key URI parameters are not exactly secret and issuer")
	}

	rows, e := seedQR(user, seed)
	if e != nil {
		t.Fatal("seed QR refused a valid account and seed")
	}
	// Exactly the QR code of that URI, at error correction level M.
	want, e := qr.Encode("otpauth://totp/Keybash:"+user+"?secret="+seed+"&issuer=Keybash", qr.M, qr.Auto)
	n := len(rows)
	if e != nil || n != want.Bounds().Dx() || n < 21 || n > 57 || (n-17)%4 != 0 {
		t.Fatal("seed QR has the wrong size")
	}
	for y, row := range rows {
		if len(row) != n || strings.Trim(row, "01") != "" {
			t.Fatal("seed QR row is malformed")
		}
		for x := range n {
			gray, _, _, _ := want.At(x, y).RGBA()
			if (row[x] == '1') != (gray == 0) {
				t.Fatal("seed QR does not draw the seed's key URI")
			}
		}
	}

	// Drawn the right way round: finders in three corners, and both copies of
	// the format information valid for level M (00) and the same.
	finder := []string{"1111111", "1000001", "1011101", "1011101", "1011101", "1000001", "1111111"}
	for i, line := range finder {
		if rows[i][:7] != line || rows[i][n-7:] != line || rows[n-7+i][:7] != line {
			t.Fatal("seed QR finder patterns are misplaced")
		}
	}
	first := formatInfo(rows, false)
	if data := (first ^ 0x5412) >> 10; data>>3 != 0 || formatCode(data) != first || formatInfo(rows, true) != first || rows[n-8][8] != '1' {
		t.Fatal("seed QR format information is not level M in reading order")
	}

	other, e := newSeed()
	if e != nil || other == seed {
		t.Fatal("second seed failed")
	}
	if again, e := seedQR(user, other); e != nil || strings.Join(again, "") == strings.Join(rows, "") {
		t.Fatal("another seed drew the same QR code")
	}
	// The longest account name still fits the bound the browser enforces.
	if long, e := seedQR(strings.Repeat("a", 64), seed); e != nil || len(long) > 57 {
		t.Fatal("longest account name does not fit")
	}
	for _, bad := range []struct{ user, seed string }{
		{"", seed}, {"Alice", seed}, {"a?secret=" + other, seed}, {"a/b", seed}, {"a b", seed}, {strings.Repeat("a", 65), seed},
		{"alice", ""}, {"alice", strings.ToLower(seed)}, {"alice", seed + "A"}, {"alice", seed[:31] + "1"}, {"alice", seed + "&issuer=x"},
	} {
		if rows, e := seedQR(bad.user, bad.seed); e == nil || rows != nil {
			t.Fatalf("seed QR drew an unvalidated value %q", bad.user)
		}
	}
}
