// gokev - свежие advisory из github + cisa kev, сшитые в один отчёт.
// идея и логика из cvedigest (python), переписано на go ради одного бинарника
package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"net/http"
	"os"
	"sort"
	"strings"
	"sync"
)

const (
	apiURL  = "https://api.github.com/advisories?per_page="
	kevURL  = "https://raw.githubusercontent.com/cisagov/kev-data/main/known_exploited_vulnerabilities.json"
	uaToken = "gokev"
)

var sevRank = map[string]int{"low": 1, "moderate": 2, "high": 3, "critical": 4}

type Advisory struct {
	GHSAID      string `json:"ghsa_id"`
	CVEID       string `json:"cve_id"`
	Severity    string `json:"severity"`
	Summary     string `json:"summary"`
	PublishedAt string `json:"published_at"`
	HTMLURL     string `json:"html_url"`
	CVSS        struct {
		Score float64 `json:"score"`
	} `json:"cvss"`
	Vulnerabilities []struct {
		Package struct {
			Ecosystem string `json:"ecosystem"`
			Name      string `json:"name"`
		} `json:"package"`
		Range string `json:"vulnerable_version_range"`
	} `json:"vulnerabilities"`
}

type kevCatalog struct {
	Vulnerabilities []struct {
		CveID string `json:"cveID"`
	} `json:"vulnerabilities"`
}

// фильтр "не ниже" + выкидывание не-KEV. отдельная функция чтобы тестировать
func filterAdvisories(all []Advisory, min string, kev map[string]bool) []Advisory {
	var kept []Advisory
	if min != "" {
		want := sevRank[strings.ToLower(min)]
		for _, a := range all {
			if sevRank[strings.ToLower(a.Severity)] >= want {
				kept = append(kept, a)
			}
		}
	} else {
		kept = all
	}
	if kev != nil {
		var only []Advisory
		for _, a := range kept {
			if kev[a.CVEID] {
				only = append(only, a)
			}
		}
		kept = only
	}
	return kept
}

func getJSON(url string, out interface{}) error {
	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		return err
	}
	req.Header.Set("User-Agent", uaToken)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		return fmt.Errorf("http %d from %s", resp.StatusCode, hostOf(url))
	}
	return json.NewDecoder(resp.Body).Decode(out)
}

func hostOf(url string) string {
	i := strings.Index(url, "//")
	rest := url[i+2:]
	if j := strings.Index(rest, "/"); j >= 0 {
		rest = rest[:j]
	}
	return rest
}

func main() {
	eco := flag.String("eco", "", "ecosystem: pip, npm, go...")
	min := flag.String("min", "", "minimum severity: low, moderate, high, critical")
	limit := flag.Int("limit", 10, "how many to show")
	asJSON := flag.Bool("json", false, "machine readable output")
	flag.Parse()

	if *min != "" && sevRank[strings.ToLower(*min)] == 0 {
		fmt.Println("severity: low, moderate, high, critical")
		os.Exit(1)
	}

	// оба фида качаем параллельно, kev весит 1.7МБ и не надо ждать advisory
	var advisories []Advisory
	var kev map[string]bool
	var advErr, kevErr error
	var wg sync.WaitGroup
	wg.Add(2)

	go func() {
		defer wg.Done()
		url := fmt.Sprintf("%s%d", apiURL, *limit*3)
		if *eco != "" {
			url += "&ecosystem=" + *eco
		}
		if *min != "" {
			url += "&severity=" + strings.ToLower(*min)
		}
		advErr = getJSON(url, &advisories)
	}()

	go func() {
		defer wg.Done()
		var cat kevCatalog
		kevErr = getJSON(kevURL, &cat)
		if kevErr != nil {
			return
		}
		kev = make(map[string]bool)
		for _, v := range cat.Vulnerabilities {
			kev[v.CveID] = true
		}
	}()
	wg.Wait()

	if advErr != nil {
		fmt.Println("advisories:", advErr)
		os.Exit(1)
	}
	if kevErr != nil {
		// kev не скачался - работаем без меток, это не повод умирать
		fmt.Fprintln(os.Stderr, "kev feed failed, going without KEV marks")
	}

	// фильтр "не ниже" - api отдаёт только точную severity
	advisories = filterAdvisories(advisories, *min, kev)
	if len(advisories) > *limit {
		advisories = advisories[:*limit]
	}

	// свежие сверху на всякий, api обычно и так отдаёт
	sort.Slice(advisories, func(i, j int) bool {
		return advisories[i].PublishedAt > advisories[j].PublishedAt
	})

	if *asJSON {
		enc := json.NewEncoder(os.Stdout)
		enc.SetIndent("", "  ")
		enc.Encode(advisories)
		return
	}

	if len(advisories) == 0 {
		fmt.Println("nothing found, try another ecosystem")
		return
	}

	for _, a := range advisories {
		mark := "     "
		if kev != nil && kev[a.CVEID] {
			mark = "[KEV]"
		}
		fmt.Printf("%s [%s %.1f] %s\n", mark, strings.ToUpper(a.Severity), a.CVSS.Score, a.Summary)
		fmt.Printf("  %s  published %s\n", orGhsa(a), a.PublishedAt[:10])
		for _, v := range a.Vulnerabilities {
			if v.Package.Name == "" {
				continue
			}
			fmt.Printf("  - %s/%s %s\n", strings.ToLower(v.Package.Ecosystem), v.Package.Name, v.Range)
		}
		fmt.Println("  ->", a.HTMLURL)
		fmt.Println()
	}
}

func orGhsa(a Advisory) string {
	if a.CVEID != "" {
		return a.CVEID
	}
	return a.GHSAID
}
