package server

import (
	"testing"
	"time"
)

func TestWhoHost(t *testing.T) {
	cases := map[string]string{
		"laurs    pts/0        2026-08-18 12:19 (5.12.237.84)": "5.12.237.84",
		"root     pts/2        2026-08-18 09:00 (10.0.0.5)":     "10.0.0.5",
		"laurs    tty1         2026-08-18 08:00":                "",   // local console, no host
		"laurs    pts/3        2026-08-18 08:00 (:0)":           "",   // X display, not a remote
	}
	for line, want := range cases {
		if got := whoHost(line); got != want {
			t.Errorf("whoHost(%q) = %q, want %q", line, got, want)
		}
	}
}

// TestMarkActiveMembership: every ledger record whose (user, IP) has a live session is
// flagged active (membership, not "k most recent"); others are not.
func TestMarkActiveMembership(t *testing.T) {
	base := time.Date(2026, 8, 18, 12, 0, 0, 0, time.UTC)
	recent := []loginEvent{
		{User: "laurs", IP: "5.12.237.84", When: base.Add(-3 * time.Hour)},
		{User: "laurs", IP: "5.12.237.84", When: base},
		{User: "bob", IP: "9.9.9.9", When: base}, // no live session
	}
	markActiveMembership(recent, map[string]int{"laurs\x005.12.237.84": 2})
	if !recent[0].Active || !recent[1].Active {
		t.Error("all laurs@IP records should be flagged when a live session exists")
	}
	if recent[2].Active {
		t.Error("bob has no live session -> not active")
	}
}

// TestBuildActiveSessions: one row per (user, IP) with the live count and the NEWEST
// matching login time — a stale (17d-old) record must not become the shown time.
func TestBuildActiveSessions(t *testing.T) {
	base := time.Date(2026, 8, 18, 12, 0, 0, 0, time.UTC)
	recent := []loginEvent{
		{User: "laurs", IP: "5.12.237.84", When: base.Add(-17 * 24 * time.Hour)}, // stale
		{User: "laurs", IP: "5.12.237.84", When: base},                           // newest
	}
	got := buildActiveSessions(recent, map[string]int{"laurs\x005.12.237.84": 3})
	if len(got) != 1 {
		t.Fatalf("want 1 active row, got %d", len(got))
	}
	if got[0].User != "laurs" || got[0].IP != "5.12.237.84" || got[0].Count != 3 {
		t.Errorf("unexpected row: %+v", got[0])
	}
	if !got[0].When.Equal(base) {
		t.Errorf("When should be the NEWEST matching login (%v), got %v", base, got[0].When)
	}
}

func TestBuildActiveSessionsNone(t *testing.T) {
	if got := buildActiveSessions(nil, map[string]int{}); len(got) != 0 {
		t.Errorf("no sessions => empty, got %d", len(got))
	}
}
