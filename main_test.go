package main

import "testing"

func adv(sev, cve string) Advisory {
	return Advisory{Severity: sev, CVEID: cve}
}

func TestFilterMinHigh(t *testing.T) {
	all := []Advisory{adv("high", "CVE-1"), adv("low", "CVE-2"), adv("critical", "CVE-3")}
	got := filterAdvisories(all, "high", nil)
	if len(got) != 2 {
		t.Fatalf("want 2, got %d", len(got))
	}
	if got[0].CVEID != "CVE-1" || got[1].CVEID != "CVE-3" {
		t.Fatal("wrong ones kept")
	}
}

func TestFilterCaseInsensitive(t *testing.T) {
	// api отдаёт lowercase, флаг человек пишет как хочет
	all := []Advisory{adv("HIGH", "CVE-1"), adv("Low", "CVE-2")}
	got := filterAdvisories(all, "HIGH", nil)
	if len(got) != 1 || got[0].CVEID != "CVE-1" {
		t.Fatal("case broke the filter")
	}
}

func TestFilterKevOnly(t *testing.T) {
	all := []Advisory{adv("high", "CVE-KEV"), adv("high", "CVE-NOPE")}
	kev := map[string]bool{"CVE-KEV": true}
	got := filterAdvisories(all, "", kev)
	if len(got) != 1 || got[0].CVEID != "CVE-KEV" {
		t.Fatal("kev filter broken")
	}
}

func TestFilterNoMinKeepsAll(t *testing.T) {
	all := []Advisory{adv("low", "CVE-1"), adv("critical", "CVE-2")}
	got := filterAdvisories(all, "", nil)
	if len(got) != 2 {
		t.Fatal("no-min filter lost items")
	}
}
