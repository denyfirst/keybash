package operatorconfig

import (
	"strings"
	"testing"

	"github.com/denyfirst/keybash/internal/sessionlimits"
)

func TestOperatorCapacityStrictAndLegacy(t *testing.T) {
	seed := fixture(t)
	old, err := ParseCatalog(strings.NewReader(seed))
	if err != nil || old.Capacity != sessionlimits.Default() {
		t.Fatal("legacy catalog lost safe defaults")
	}
	with := func(raw string) string { return strings.Replace(seed, `"version":1`, `"version":1,"capacity":`+raw, 1) }
	for _, raw := range []string{`{"total":16,"per_owner":4}`, `{"total":1,"per_owner":1}`, `{"total":128,"per_owner":128}`} {
		catalog, err := ParseCatalog(strings.NewReader(with(raw)))
		if err != nil || !catalog.Capacity.Valid() || len(catalog.Targets) != 1 {
			t.Fatal("valid operator capacity refused")
		}
		if raw == `{"total":16,"per_owner":4}` && catalog.Capacity != (sessionlimits.Limits{Total: 16, PerOwner: 4}) {
			t.Fatal("operator capacity ignored")
		}
	}
	for _, raw := range []string{`null`, `{}`, `[]`, `"unlimited"`, `{"total":0,"per_owner":1}`, `{"total":8,"per_owner":0}`,
		`{"total":-1,"per_owner":1}`, `{"total":129,"per_owner":1}`, `{"total":8,"per_owner":9}`,
		`{"total":8.0,"per_owner":2}`, `{"total":"8","per_owner":2}`, `{"total":null,"per_owner":2}`,
		`{"total":8,"per_owner":2,"total":16}`, `{"total":8,"per_owner":2,"per\u005fowner":3}`,
		`{"Total":8,"per_owner":2}`, `{"total":8,"per_owner":2,"disabled":true}`, `{"total":1e100,"per_owner":1}`} {
		catalog, err := ParseCatalog(strings.NewReader(with(raw)))
		if err != ErrConfiguration || catalog.Targets != nil || catalog.Capacity.Valid() {
			t.Fatal("malformed operator capacity accepted")
		}
	}
	if _, err := ParseCatalog(strings.NewReader(with(`{"total":8,"per_owner":2}`) + `{}`)); err != ErrConfiguration {
		t.Fatal("trailing capacity catalog accepted")
	}
}
