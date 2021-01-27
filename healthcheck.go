package ldappool

import (
	"fmt"
	hc "github.com/PennState/go-healthcheck/pkg/health"
	"github.com/go-ldap/ldap/v3"
	"time"
)

// Healthcheck ...
type Healthcheck struct {
	Pool            Pool
	SearchDN        string // DN of LDAP entry to search for
	SearchTimeLimit int
	Timeout         time.Duration
}

// Check runs a gitlab client healthcheck
func (c Healthcheck) Check() ([]hc.Check, hc.Status) {
	searchCheck := hc.Check{
		Key: hc.Key{
			ComponentName:   "Search",
			MeasurementName: "Result",
		},
		Output:        "",
		Time:          time.Now().UTC(),
		ComponentType: "component",
		Links:         map[string]string{"dn": c.SearchDN},
		Status:        hc.Pass,
	}

	poolSizeCheck := hc.Check{
		Key: hc.Key{
			ComponentName:   "Pool",
			MeasurementName: "Size",
		},
		Output:        fmt.Sprintf("Pool size: %d", c.Pool.Len()),
		Time:          time.Now().UTC(),
		ComponentType: "component",
		Status:        hc.Pass,
	}

	l, err := c.Pool.Get()
	if err != nil {
		searchCheck.Status = hc.Fail
		searchCheck.Output = err.Error()

		return []hc.Check{searchCheck, poolSizeCheck}, hc.Fail
	}
	defer l.Close()

	l.SetTimeout(c.Timeout)
	res, err := l.Search(&ldap.SearchRequest{
		BaseDN:     c.SearchDN,
		Scope:      ldap.ScopeBaseObject,
		Attributes: []string{},
		SizeLimit:  1,
		TimeLimit:  c.SearchTimeLimit,
		Filter:     "(objectclass=*)",
	})
	if err != nil {
		l.MarkUnusable()
		searchCheck.Status = hc.Fail
		searchCheck.Output = err.Error()

		return []hc.Check{searchCheck, poolSizeCheck}, hc.Fail
	}

	if len(res.Entries) != 1 {
		searchCheck.Status = hc.Fail
		searchCheck.Output = fmt.Sprintf("Search returned %d entries", len(res.Entries))

		return []hc.Check{searchCheck, poolSizeCheck}, hc.Fail
	}
	searchCheck.Output = fmt.Sprintf("Found entry for %s", res.Entries[0].DN)

	return []hc.Check{searchCheck, poolSizeCheck}, hc.Pass
}
