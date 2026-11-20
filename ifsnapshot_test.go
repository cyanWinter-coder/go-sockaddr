// Copyright IBM Corp. 2016, 2026
// SPDX-License-Identifier: MPL-2.0

package sockaddr_test

import (
	"context"
	"errors"
	"math/big"
	"net"
	"slices"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	sockaddr "github.com/hashicorp/go-sockaddr"
	socktmpl "github.com/hashicorp/go-sockaddr/template"
)

// fakeIfSnapshotSource is a scriptable IfSnapshotSource.  Every call is
// counted so tests can assert that snapshot selection never re-reads the
// source.
type fakeIfSnapshotSource struct {
	interfaces    []net.Interface
	addrs         map[string][]net.Addr
	defaultIfName string
	addrsErr      map[string]error
	ifacesErr     error
	routeErr      error
	routeBlock    bool

	interfacesCalls atomic.Int64
	addrsCalls      atomic.Int64
	routeCalls      atomic.Int64
}

func (s *fakeIfSnapshotSource) Interfaces() ([]net.Interface, error) {
	s.interfacesCalls.Add(1)
	if s.ifacesErr != nil {
		return nil, s.ifacesErr
	}
	return slices.Clone(s.interfaces), nil
}

func (s *fakeIfSnapshotSource) InterfaceAddrs(iface net.Interface) ([]net.Addr, error) {
	s.addrsCalls.Add(1)
	if err, found := s.addrsErr[iface.Name]; found {
		return nil, err
	}
	return slices.Clone(s.addrs[iface.Name]), nil
}

func (s *fakeIfSnapshotSource) DefaultInterfaceName(ctx context.Context) (string, error) {
	s.routeCalls.Add(1)
	if s.routeBlock {
		<-ctx.Done()
		return "", ctx.Err()
	}
	return s.defaultIfName, s.routeErr
}

func mustCIDR(t *testing.T, cidr string) *net.IPNet {
	t.Helper()
	ip, network, err := net.ParseCIDR(cidr)
	if err != nil {
		t.Fatalf("unable to parse CIDR %q: %v", cidr, err)
	}
	// net.Interface.Addrs reports the host address with the network mask, so
	// build the same shape rather than returning ParseCIDR's masked network.
	return &net.IPNet{IP: ip, Mask: network.Mask}
}

func newFakeSource(t *testing.T) *fakeIfSnapshotSource {
	t.Helper()
	return &fakeIfSnapshotSource{
		interfaces: []net.Interface{
			{
				Index:        2,
				MTU:          1500,
				Name:         "eth0",
				HardwareAddr: net.HardwareAddr{0x02, 0x42, 0xac, 0x11, 0x00, 0x02},
				Flags:        net.FlagUp | net.FlagBroadcast | net.FlagMulticast,
			},
			{
				Index:        1,
				MTU:          65536,
				Name:         "lo",
				HardwareAddr: nil,
				Flags:        net.FlagUp | net.FlagLoopback,
			},
		},
		addrs: map[string][]net.Addr{
			"eth0": {
				mustCIDR(t, "192.168.50.10/24"),
				mustCIDR(t, "fe80::2/64"),
			},
			"lo": {
				mustCIDR(t, "127.0.0.1/8"),
				mustCIDR(t, "::1/128"),
			},
		},
		defaultIfName: "eth0",
		addrsErr:      map[string]error{},
	}
}

func mustCapture(t *testing.T, src sockaddr.IfSnapshotSource, cfg sockaddr.IfSnapshotConfig) *sockaddr.IfSnapshot {
	t.Helper()
	snapshot, err := sockaddr.CaptureIfSnapshotFrom(context.Background(), src, cfg)
	if err != nil {
		t.Fatalf("unable to capture snapshot: %v", err)
	}
	return snapshot
}

func entriesByAddress(t *testing.T, entries []sockaddr.IfSnapshotEntry) map[string]sockaddr.IfSnapshotEntry {
	t.Helper()
	index := make(map[string]sockaddr.IfSnapshotEntry, len(entries))
	for _, entry := range entries {
		if _, found := index[entry.Address()]; found {
			t.Fatalf("duplicate address %q in snapshot", entry.Address())
		}
		index[entry.Address()] = entry
	}
	return index
}

func TestCaptureIfSnapshot(t *testing.T) {
	src := newFakeSource(t)
	snapshot := mustCapture(t, src, sockaddr.IfSnapshotConfig{})

	if got, want := snapshot.Len(), 4; got != want {
		t.Fatalf("wrong number of entries: got %d; want %d", got, want)
	}
	if !snapshot.HasRouteInfo() {
		t.Fatalf("expected route information to be available")
	}
	if got, want := snapshot.DefaultInterfaceName(), "eth0"; got != want {
		t.Fatalf("wrong default interface: got %q; want %q", got, want)
	}
	if snapshot.CapturedAt().IsZero() {
		t.Fatalf("captured at timestamp was not set")
	}

	entries := entriesByAddress(t, snapshot.Entries())
	for addr, wantFamily := range map[string]sockaddr.AddressFamily{
		"192.168.50.10/24": sockaddr.AddressFamilyIPv4,
		"fe80::2/64":       sockaddr.AddressFamilyIPv6,
		"127.0.0.1/8":      sockaddr.AddressFamilyIPv4,
		"::1":              sockaddr.AddressFamilyIPv6,
	} {
		entry, found := entries[addr]
		if !found {
			t.Fatalf("missing entry for %q", addr)
		}
		if got := entry.Family; got != wantFamily {
			t.Errorf("%q: wrong family: got %v; want %v", addr, got, wantFamily)
		}
	}

	if got, want := entries["192.168.50.10/24"].Key, sockaddr.InterfaceKey("eth0"); got != want {
		t.Errorf("wrong interface key: got %q; want %q", got, want)
	}
	if got, want := entries["127.0.0.1/8"].Key, sockaddr.InterfaceKey("lo"); got != want {
		t.Errorf("wrong interface key: got %q; want %q", got, want)
	}

	if !entries["192.168.50.10/24"].DefaultRoute {
		t.Errorf("expected eth0 addresses to be marked as the default route")
	}
	if entries["127.0.0.1/8"].DefaultRoute {
		t.Errorf("did not expect lo addresses to be marked as the default route")
	}
}

func TestCaptureIfSnapshotGeneration(t *testing.T) {
	src := newFakeSource(t)
	first := mustCapture(t, src, sockaddr.IfSnapshotConfig{})
	second := mustCapture(t, src, sockaddr.IfSnapshotConfig{})

	if first.Generation() == 0 {
		t.Fatalf("generation must be non-zero")
	}
	if second.Generation() <= first.Generation() {
		t.Fatalf("generations must increase: first %d; second %d", first.Generation(), second.Generation())
	}
	if got := first.Select().Generation(); got != first.Generation() {
		t.Fatalf("selection generation: got %d; want %d", got, first.Generation())
	}
}

func TestCaptureIfSnapshotDedupe(t *testing.T) {
	src := &fakeIfSnapshotSource{
		interfaces: []net.Interface{
			{Index: 2, MTU: 1500, Name: "eth0", Flags: net.FlagUp},
			{Index: 3, MTU: 1500, Name: "eth1", Flags: net.FlagUp},
		},
		addrs: map[string][]net.Addr{
			"eth0": {mustCIDR(t, "10.0.0.5/24"), mustCIDR(t, "10.0.0.5/24")},
			"eth1": {mustCIDR(t, "10.0.0.5/24")},
		},
		defaultIfName: "eth0",
	}

	preserved := mustCapture(t, src, sockaddr.IfSnapshotConfig{})
	if got, want := preserved.Len(), 3; got != want {
		t.Fatalf("without dedupe: got %d entries; want %d", got, want)
	}

	deduped := mustCapture(t, src, sockaddr.IfSnapshotConfig{DedupeAddresses: true})
	if got, want := deduped.Len(), 1; got != want {
		t.Fatalf("with dedupe: got %d entries; want %d", got, want)
	}

	selection := deduped.Select().DedupeByAddress()
	if got, want := selection.Len(), 1; got != want {
		t.Fatalf("selection dedupe: got %d entries; want %d", got, want)
	}
}

func TestIfSelectionReadsOnlySnapshot(t *testing.T) {
	src := newFakeSource(t)
	snapshot := mustCapture(t, src, sockaddr.IfSnapshotConfig{})

	interfacesCalls := src.interfacesCalls.Load()
	addrsCalls := src.addrsCalls.Load()
	routeCalls := src.routeCalls.Load()

	// Change the source after capture; nothing below may consult it again.
	src.interfaces = nil
	src.addrs = nil
	src.defaultIfName = "lo"
	src.routeErr = errors.New("route table disappeared")

	included, err := snapshot.Include("name", "^eth0$")
	if err != nil {
		t.Fatalf("include failed: %v", err)
	}
	if got, want := included.Len(), 2; got != want {
		t.Fatalf("include: got %d entries; want %d", got, want)
	}
	if included.Generation() != snapshot.Generation() {
		t.Fatalf("include lost generation tag")
	}

	excluded, err := snapshot.Exclude("type", "IPv6")
	if err != nil {
		t.Fatalf("exclude failed: %v", err)
	}
	if got, want := excluded.Len(), 2; got != want {
		t.Fatalf("exclude: got %d entries; want %d", got, want)
	}

	sorted, err := snapshot.Sort("default,type,-size,address")
	if err != nil {
		t.Fatalf("sort failed: %v", err)
	}
	if got, want := sorted.Len(), 4; got != want {
		t.Fatalf("sort: got %d entries; want %d", got, want)
	}
	first := sorted.Entries()[0]
	if first.Key != "eth0" {
		t.Fatalf("default sort did not use captured route info: first entry is %q", first.Key)
	}

	chained, err := snapshot.Select().Include("type", "IP")
	if err != nil {
		t.Fatalf("chained selection include failed: %v", err)
	}
	chained, err = chained.Exclude("flags", "loopback")
	if err != nil {
		t.Fatalf("chained selection exclude failed: %v", err)
	}
	chained, err = chained.Sort("default,-address")
	if err != nil {
		t.Fatalf("chained selection sort failed: %v", err)
	}
	if got, want := chained.Len(), 2; got != want {
		t.Fatalf("chained selection: got %d entries; want %d", got, want)
	}
	for _, entry := range chained.Entries() {
		if entry.Key != "eth0" {
			t.Fatalf("chained selection returned unexpected entry %v", entry)
		}
	}

	if got, want := src.interfacesCalls.Load(), interfacesCalls; got != want {
		t.Fatalf("snapshot selection re-read interfaces: got %d calls; want %d", got, want)
	}
	if got, want := src.addrsCalls.Load(), addrsCalls; got != want {
		t.Fatalf("snapshot selection re-read interface addresses: got %d calls; want %d", got, want)
	}
	if got, want := src.routeCalls.Load(), routeCalls; got != want {
		t.Fatalf("snapshot selection re-read route info: got %d calls; want %d", got, want)
	}
}

func TestIfSelectionSortValidation(t *testing.T) {
	src := newFakeSource(t)
	snapshot := mustCapture(t, src, sockaddr.IfSnapshotConfig{})

	if _, err := snapshot.Sort("bogus"); err == nil {
		t.Fatalf("expected an error for an unknown sort clause")
	}
	if _, err := snapshot.Include("bogus", "x"); err == nil {
		t.Fatalf("expected an error for an unknown include selector")
	}
	if _, err := snapshot.Exclude("bogus", "x"); err == nil {
		t.Fatalf("expected an error for an unknown exclude selector")
	}
}

func TestIfSelectionSortClauses(t *testing.T) {
	src := newFakeSource(t)
	snapshot := mustCapture(t, src, sockaddr.IfSnapshotConfig{})

	clauses := []string{
		"address", "+address", "-address",
		"default", "+default", "-default",
		"name", "+name", "-name",
		"port", "+port", "-port",
		"private", "+private", "-private",
		"size", "+size", "-size",
		"type", "+type", "-type",
	}
	for _, clause := range clauses {
		t.Run(clause, func(t *testing.T) {
			sorted, err := snapshot.Sort(clause)
			if err != nil {
				t.Fatalf("sort %q failed: %v", clause, err)
			}
			if got, want := sorted.Len(), snapshot.Len(); got != want {
				t.Fatalf("sort %q changed entry count: got %d; want %d", clause, got, want)
			}
			if sorted.Generation() != snapshot.Generation() {
				t.Fatalf("sort %q lost generation", clause)
			}
		})
	}

	ascending, err := snapshot.Sort("+default")
	if err != nil {
		t.Fatalf("sort failed: %v", err)
	}
	descending, err := snapshot.Sort("-default")
	if err != nil {
		t.Fatalf("sort failed: %v", err)
	}
	if ascending.Entries()[0].Key != "eth0" {
		t.Fatalf("ascending default sort did not put the default interface first")
	}
	if got := descending.Entries()[len(descending.Entries())-1].Key; got != "eth0" {
		t.Fatalf("descending default sort did not put the default interface last: got %q", got)
	}
}

func TestIfSnapshotEntryAttrs(t *testing.T) {
	src := newFakeSource(t)
	snapshot := mustCapture(t, src, sockaddr.IfSnapshotConfig{})

	entries := entriesByAddress(t, snapshot.Entries())
	entry := entries["192.168.50.10/24"]

	if got, want := entry.Name(), "eth0"; got != want {
		t.Fatalf("wrong name: got %q; want %q", got, want)
	}
	if got, want := entry.Address(), "192.168.50.10/24"; got != want {
		t.Fatalf("wrong address: got %q; want %q", got, want)
	}

	if got, err := entry.Attr("address"); err != nil || got != "192.168.50.10" {
		t.Fatalf("Attr(address): got %q, %v", got, err)
	}
	if got, err := entry.Attr("flags"); err != nil || got == "" {
		t.Fatalf("Attr(flags): got %q, %v", got, err)
	}
	if _, err := entry.Attr("bogus"); err == nil {
		t.Fatalf("expected an error for an unknown attribute")
	}
}

func TestIfSelectionPreservesDuplicateAddresses(t *testing.T) {
	src := &fakeIfSnapshotSource{
		interfaces: []net.Interface{
			{Index: 2, MTU: 1500, Name: "eth0", Flags: net.FlagUp},
			{Index: 3, MTU: 1500, Name: "eth1", Flags: net.FlagUp},
			{Index: 4, MTU: 1500, Name: "eth2", Flags: net.FlagUp},
		},
		addrs: map[string][]net.Addr{
			"eth0": {mustCIDR(t, "10.0.0.5/24")},
			"eth1": {mustCIDR(t, "10.0.0.5/24")},
			"eth2": {mustCIDR(t, "10.0.0.5/24")},
		},
		defaultIfName: "eth0",
	}

	snapshot := mustCapture(t, src, sockaddr.IfSnapshotConfig{})
	if got, want := snapshot.Len(), 3; got != want {
		t.Fatalf("snapshot: got %d entries; want %d", got, want)
	}

	// A selector that matches every duplicate must keep every entry, each with
	// its own interface key.
	selection, err := snapshot.Select().Include("network", "10.0.0.0/24")
	if err != nil {
		t.Fatalf("include failed: %v", err)
	}
	if got, want := selection.Len(), 3; got != want {
		t.Fatalf("include dropped duplicates: got %d entries; want %d", got, want)
	}

	keys := make(map[sockaddr.InterfaceKey]struct{}, selection.Len())
	for _, entry := range selection.Entries() {
		keys[entry.Key] = struct{}{}
	}
	for _, want := range []sockaddr.InterfaceKey{"eth0", "eth1", "eth2"} {
		if _, found := keys[want]; !found {
			t.Fatalf("include lost entry for interface %q", want)
		}
	}

	// Deduplicating the selection collapses them, keeping the first.
	deduped := selection.DedupeByAddress()
	if got, want := deduped.Len(), 1; got != want {
		t.Fatalf("selection dedupe: got %d entries; want %d", got, want)
	}
}

func TestIfSnapshotDiff(t *testing.T) {
	beforeSrc := newFakeSource(t)
	before := mustCapture(t, beforeSrc, sockaddr.IfSnapshotConfig{})

	afterSrc := newFakeSource(t)
	// Remove the IPv6 address from eth0, add a new address to lo, change the
	// MTU and flags of eth0, and move the default route to lo.
	afterSrc.addrs["eth0"] = []net.Addr{mustCIDR(t, "192.168.50.10/24")}
	afterSrc.addrs["lo"] = []net.Addr{
		mustCIDR(t, "127.0.0.1/8"),
		mustCIDR(t, "::1/128"),
		mustCIDR(t, "127.0.0.2/8"),
	}
	afterSrc.interfaces[0].MTU = 9000
	afterSrc.interfaces[0].Flags = net.FlagUp | net.FlagMulticast
	afterSrc.defaultIfName = "lo"
	after := mustCapture(t, afterSrc, sockaddr.IfSnapshotConfig{})

	diff := after.DiffFrom(before)
	if diff.Empty() {
		t.Fatalf("expected a non-empty diff")
	}
	if diff.BeforeGeneration != before.Generation() || diff.AfterGeneration != after.Generation() {
		t.Fatalf("diff generations do not match snapshots")
	}

	if got, want := len(diff.Added), 1; got != want {
		t.Fatalf("added: got %d; want %d", got, want)
	}
	if got, want := diff.Added[0].Address(), "127.0.0.2/8"; got != want {
		t.Errorf("unexpected added entry: got %q; want %q", got, want)
	}

	if got, want := len(diff.Removed), 1; got != want {
		t.Fatalf("removed: got %d; want %d", got, want)
	}
	if got, want := diff.Removed[0].Address(), "fe80::2/64"; got != want {
		t.Errorf("unexpected removed entry: got %q; want %q", got, want)
	}

	if got, want := len(diff.Changed), 3; got != want {
		t.Fatalf("changed: got %d; want %d: %+v", got, want, diff.Changed)
	}

	changesByAddress := make(map[string][]string, len(diff.Changed))
	for _, change := range diff.Changed {
		names := make([]string, 0, len(change.Changes))
		for _, attrChange := range change.Changes {
			names = append(names, attrChange.Name)
		}
		changesByAddress[change.Address] = names
	}

	if names := changesByAddress["192.168.50.10"]; !slices.Contains(names, "mtu") || !slices.Contains(names, "flags") || !slices.Contains(names, "default_route") {
		t.Errorf("eth0 IPv4 changes missing attributes: %v", names)
	}
	if names := changesByAddress["127.0.0.1"]; !slices.Contains(names, "default_route") {
		t.Errorf("lo IPv4 changes missing default_route: %v", names)
	}
	if names := changesByAddress["::1"]; !slices.Contains(names, "default_route") {
		t.Errorf("lo IPv6 changes missing default_route: %v", names)
	}

	if empty := sockaddr.CompareIfSnapshots(after, after); !empty.Empty() {
		t.Fatalf("expected an empty diff for identical snapshots: %+v", empty)
	}
}

func TestIfSnapshotDiffUsesOnlyCapturedData(t *testing.T) {
	beforeSrc := newFakeSource(t)
	before := mustCapture(t, beforeSrc, sockaddr.IfSnapshotConfig{})
	afterSrc := newFakeSource(t)
	after := mustCapture(t, afterSrc, sockaddr.IfSnapshotConfig{})

	beforeSrc.interfaces = nil
	afterSrc.interfaces = nil
	beforeSrc.routeCalls.Store(0)
	afterSrc.routeCalls.Store(0)

	if diff := sockaddr.CompareIfSnapshots(before, after); !diff.Empty() {
		t.Fatalf("expected identical snapshots to compare equal: %+v", diff)
	}
	if beforeSrc.routeCalls.Load() != 0 || afterSrc.routeCalls.Load() != 0 {
		t.Fatalf("diff re-read the host")
	}
}

func TestCaptureIfSnapshotErrors(t *testing.T) {
	t.Run("interface list failure", func(t *testing.T) {
		src := newFakeSource(t)
		src.ifacesErr = errors.New("boom")
		snapshot, err := sockaddr.CaptureIfSnapshotFrom(context.Background(), src, sockaddr.IfSnapshotConfig{})
		if snapshot != nil {
			t.Fatalf("expected no snapshot on failure")
		}
		if !errors.Is(err, sockaddr.ErrSnapshotIncomplete) {
			t.Fatalf("wrong error: %v", err)
		}
	})

	t.Run("address failure", func(t *testing.T) {
		src := newFakeSource(t)
		src.addrsErr["eth0"] = errors.New("boom")
		snapshot, err := sockaddr.CaptureIfSnapshotFrom(context.Background(), src, sockaddr.IfSnapshotConfig{})
		if snapshot != nil {
			t.Fatalf("expected no snapshot on failure")
		}
		if !errors.Is(err, sockaddr.ErrSnapshotIncomplete) {
			t.Fatalf("wrong error: %v", err)
		}
	})

	t.Run("route info failure", func(t *testing.T) {
		src := newFakeSource(t)
		src.routeErr = errors.New("boom")
		snapshot, err := sockaddr.CaptureIfSnapshotFrom(context.Background(), src, sockaddr.IfSnapshotConfig{})
		if snapshot != nil || !errors.Is(err, sockaddr.ErrSnapshotIncomplete) {
			t.Fatalf("expected a complete failure, got snapshot %v, err %v", snapshot, err)
		}
	})

	t.Run("route info failure ignored", func(t *testing.T) {
		src := newFakeSource(t)
		src.routeErr = errors.New("boom")
		snapshot, err := sockaddr.CaptureIfSnapshotFrom(context.Background(), src, sockaddr.IfSnapshotConfig{IgnoreRouteInfoErrors: true})
		if err != nil {
			t.Fatalf("expected route info to be optional: %v", err)
		}
		if snapshot.HasRouteInfo() {
			t.Fatalf("expected route info to be unavailable")
		}
		for _, entry := range snapshot.Entries() {
			if entry.DefaultRoute {
				t.Fatalf("expected no default route entries when route info is unavailable")
			}
		}
	})

	t.Run("nil source", func(t *testing.T) {
		if _, err := sockaddr.CaptureIfSnapshotFrom(context.Background(), nil, sockaddr.IfSnapshotConfig{}); !errors.Is(err, sockaddr.ErrSnapshotSourceNil) {
			t.Fatalf("wrong error: %v", err)
		}
	})
}

func TestCaptureIfSnapshotContext(t *testing.T) {
	t.Run("canceled before capture", func(t *testing.T) {
		ctx, cancel := context.WithCancel(context.Background())
		cancel()

		src := newFakeSource(t)
		snapshot, err := sockaddr.CaptureIfSnapshotFrom(ctx, src, sockaddr.IfSnapshotConfig{})
		if snapshot != nil {
			t.Fatalf("expected no snapshot")
		}
		if !errors.Is(err, sockaddr.ErrSnapshotIncomplete) || !errors.Is(err, context.Canceled) {
			t.Fatalf("wrong error: %v", err)
		}
		if src.interfacesCalls.Load() != 0 {
			t.Fatalf("expected no collection to occur after cancellation")
		}
	})

	t.Run("deadline during route lookup", func(t *testing.T) {
		src := newFakeSource(t)
		src.routeBlock = true

		ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
		defer cancel()

		snapshot, err := sockaddr.CaptureIfSnapshotFrom(ctx, src, sockaddr.IfSnapshotConfig{
			IgnoreRouteInfoErrors: true,
		})
		if snapshot != nil {
			t.Fatalf("expected no snapshot")
		}
		if !errors.Is(err, sockaddr.ErrSnapshotIncomplete) || !errors.Is(err, context.DeadlineExceeded) {
			t.Fatalf("wrong error: %v", err)
		}
	})
}

func TestIfSnapshotImmutable(t *testing.T) {
	src := newFakeSource(t)
	snapshot := mustCapture(t, src, sockaddr.IfSnapshotConfig{})

	original := snapshot.Entries()

	// Mutate the returned copy's mutable fields; the snapshot must be
	// unaffected.
	entries := snapshot.Entries()
	var hwIndex, v6Index = -1, -1
	for i, entry := range entries {
		if hwIndex < 0 && len(entry.IfAddr.HardwareAddr) > 0 {
			hwIndex = i
		}
		if v6Index < 0 && sockaddr.ToIPv6Addr(entry.IfAddr.SockAddr) != nil {
			v6Index = i
		}
	}
	if hwIndex < 0 || v6Index < 0 {
		t.Fatalf("test fixtures did not provide a hardware address and an IPv6 entry")
	}

	entries[hwIndex].IfAddr.HardwareAddr[0] = 0xff
	entries[hwIndex].DefaultRoute = !entries[hwIndex].DefaultRoute
	entries[hwIndex].Key = "mutated"
	v6 := sockaddr.ToIPv6Addr(entries[v6Index].IfAddr.SockAddr)
	v6.Address = sockaddr.IPv6Address(big.NewInt(0))

	again := snapshot.Entries()
	for i := range original {
		if original[i].Key != again[i].Key ||
			original[i].DefaultRoute != again[i].DefaultRoute ||
			original[i].Address() != again[i].Address() {
			t.Fatalf("snapshot changed after mutation of returned entries: %v != %v", original[i], again[i])
		}
		if !slices.Equal(original[i].IfAddr.HardwareAddr, again[i].IfAddr.HardwareAddr) {
			t.Fatalf("snapshot hardware address changed after mutation of returned entries")
		}
	}

	ifAddrs := snapshot.IfAddrs()
	if got, want := ifAddrs[hwIndex].HardwareAddr[0], original[hwIndex].IfAddr.HardwareAddr[0]; got != want {
		t.Fatalf("snapshot changed after mutation of returned IfAddrs")
	}
	ifAddrs[hwIndex].HardwareAddr[0] = 0xee
	if got, want := snapshot.IfAddrs()[hwIndex].HardwareAddr[0], original[hwIndex].IfAddr.HardwareAddr[0]; got != want {
		t.Fatalf("snapshot changed after mutation of returned IfAddrs")
	}
}

func TestIfSnapshotConcurrentReads(t *testing.T) {
	src := newFakeSource(t)
	snapshot := mustCapture(t, src, sockaddr.IfSnapshotConfig{})

	var wg sync.WaitGroup
	for range 16 {
		wg.Go(func() {
			for range 200 {
				if got, want := snapshot.Len(), 4; got != want {
					t.Errorf("wrong length: got %d; want %d", got, want)
					return
				}
				selection := snapshot.Select()
				if selection.Generation() != snapshot.Generation() {
					t.Errorf("selection generation mismatch")
					return
				}
				sorted, err := selection.Sort("default,type,address")
				if err != nil {
					t.Errorf("sort failed: %v", err)
					return
				}
				if sorted.Len() != 4 {
					t.Errorf("wrong sorted length: %d", sorted.Len())
					return
				}
				if diff := sockaddr.CompareIfSnapshots(snapshot, snapshot); !diff.Empty() {
					t.Errorf("expected empty self diff")
					return
				}
				ips, err := selection.Include("type", "IP")
				if err != nil {
					t.Errorf("include failed: %v", err)
					return
				}
				for _, entry := range ips.Entries() {
					_ = entry.Address()
				}
			}
		})
	}
	wg.Wait()
}

func TestIfSnapshotTemplateCompatibility(t *testing.T) {
	src := newFakeSource(t)
	snapshot := mustCapture(t, src, sockaddr.IfSnapshotConfig{})

	out, err := socktmpl.ParseIfAddrs(`{{ . | include "type" "IPv4" | exclude "flags" "loopback" | sort "type,-address" | join "address" " " }}`, snapshot.IfAddrs())
	if err != nil {
		t.Fatalf("template parse failed: %v", err)
	}
	if got, want := out, "192.168.50.10"; got != want {
		t.Fatalf("wrong template output: got %q; want %q", got, want)
	}
}

func TestIfSnapshotLegacyViews(t *testing.T) {
	src := newFakeSource(t)
	snapshot := mustCapture(t, src, sockaddr.IfSnapshotConfig{})

	defaults := snapshot.DefaultSelection()
	if got, want := defaults.Len(), 2; got != want {
		t.Fatalf("default selection: got %d entries; want %d", got, want)
	}
	for _, entry := range defaults.Entries() {
		if entry.Key != "eth0" {
			t.Fatalf("default selection returned non-default entry %v", entry)
		}
	}

	private, err := snapshot.PrivateSelection()
	if err != nil {
		t.Fatalf("private selection failed: %v", err)
	}
	if got, want := private.Len(), 1; got != want {
		t.Fatalf("private selection: got %d entries; want %d", got, want)
	}
	if got, want := private.Entries()[0].Address(), "192.168.50.10/24"; got != want {
		t.Fatalf("private selection: got %q; want %q", got, want)
	}

	public, err := snapshot.PublicSelection()
	if err != nil {
		t.Fatalf("public selection failed: %v", err)
	}
	if got, want := public.Len(), 0; got != want {
		t.Fatalf("public selection: got %d entries; want %d", got, want)
	}
}

func TestCaptureIfSnapshotSystemMatchesLegacyViews(t *testing.T) {
	snapshot, err := sockaddr.CaptureIfSnapshot(context.Background(), sockaddr.IfSnapshotConfig{
		IgnoreRouteInfoErrors: true,
	})
	if err != nil {
		t.Fatalf("unable to capture host snapshot: %v", err)
	}
	if !snapshot.HasRouteInfo() {
		t.Skip("host route information is unavailable")
	}

	defaultIfs, err := sockaddr.GetDefaultInterfaces()
	if err != nil {
		t.Skipf("unable to get default interfaces: %v", err)
	}
	selection := snapshot.DefaultSelection()
	if got, want := selection.Len(), len(defaultIfs); got != want {
		t.Fatalf("default selection mismatch: got %d entries; want %d", got, want)
	}
	snapshotAddrs := make(map[string]struct{}, selection.Len())
	for _, entry := range selection.Entries() {
		snapshotAddrs[entry.Address()] = struct{}{}
	}
	for _, ifAddr := range defaultIfs {
		if _, found := snapshotAddrs[ifAddr.SockAddr.String()]; !found {
			t.Fatalf("snapshot default selection is missing %q", ifAddr.SockAddr.String())
		}
	}
}

func TestIfSnapshotNilSafety(t *testing.T) {
	var snapshot *sockaddr.IfSnapshot

	if snapshot.Generation() != 0 || !snapshot.CapturedAt().IsZero() || snapshot.DefaultInterfaceName() != "" ||
		snapshot.HasRouteInfo() || snapshot.Len() != 0 || snapshot.Entries() != nil || snapshot.IfAddrs() != nil {
		t.Fatalf("nil snapshot returned values")
	}
	if got := snapshot.Select().Len(); got != 0 {
		t.Fatalf("nil snapshot selection returned %d entries", got)
	}
	if _, err := snapshot.Include("type", "IP"); err != nil {
		t.Fatalf("nil snapshot include failed: %v", err)
	}
	if diff := snapshot.DiffFrom(nil); !diff.Empty() {
		t.Fatalf("nil snapshot diff was not empty")
	}
}

func TestIfSelectionIncludePreservesEntries(t *testing.T) {
	src := newFakeSource(t)
	snapshot := mustCapture(t, src, sockaddr.IfSnapshotConfig{})

	selection, err := snapshot.Select().Include("network", "192.168.0.0/16")
	if err != nil {
		t.Fatalf("include failed: %v", err)
	}
	if got, want := selection.Len(), 1; got != want {
		t.Fatalf("wrong number of entries: got %d; want %d", got, want)
	}
	entry := selection.Entries()[0]
	if entry.Key != "eth0" || entry.Family != sockaddr.AddressFamilyIPv4 {
		t.Fatalf("selection dropped entry metadata: %+v", entry)
	}
	if !entry.DefaultRoute {
		t.Fatalf("selection dropped captured route metadata")
	}
}

func TestInterfaceKeyFor(t *testing.T) {
	tests := []struct {
		iface net.Interface
		want  sockaddr.InterfaceKey
	}{
		{iface: net.Interface{Name: "eth0", Index: 3}, want: "eth0"},
		{iface: net.Interface{Index: 7}, want: "index:7"},
	}

	for _, tc := range tests {
		if got := sockaddr.InterfaceKeyFor(tc.iface); got != tc.want {
			t.Errorf("InterfaceKeyFor(%v): got %q; want %q", tc.iface, got, tc.want)
		}
	}
}

func TestAddressFamilyOf(t *testing.T) {
	tests := []struct {
		sa   sockaddr.SockAddr
		want sockaddr.AddressFamily
	}{
		{sa: sockaddr.MustIPv4Addr("10.0.0.1"), want: sockaddr.AddressFamilyIPv4},
		{sa: sockaddr.MustIPv6Addr("fe80::1"), want: sockaddr.AddressFamilyIPv6},
		{sa: sockaddr.MustUnixSock("/tmp/sock"), want: sockaddr.AddressFamilyUnix},
		{sa: nil, want: sockaddr.AddressFamilyUnknown},
	}

	for _, tc := range tests {
		if got := sockaddr.AddressFamilyOf(tc.sa); got != tc.want {
			t.Errorf("AddressFamilyOf(%v): got %v; want %v", tc.sa, got, tc.want)
		}
		if tc.want != sockaddr.AddressFamilyUnknown && tc.want.String() == "" {
			t.Errorf("AddressFamily.String() is empty")
		}
	}

	if got, want := sockaddr.AddressFamilyUnknown.String(), "unknown"; got != want {
		t.Errorf("unknown family: got %q; want %q", got, want)
	}
	if got, want := sockaddr.AddressFamily(200).String(), "AddressFamily(200)"; got != want {
		t.Errorf("invalid family: got %q; want %q", got, want)
	}
}

func TestCaptureIfSnapshotSystem(t *testing.T) {
	snapshot, err := sockaddr.CaptureIfSnapshot(context.Background(), sockaddr.IfSnapshotConfig{
		IgnoreRouteInfoErrors: true,
	})
	if err != nil {
		t.Fatalf("unable to capture host snapshot: %v", err)
	}
	if snapshot.Len() == 0 {
		t.Skipf("no interfaces available on this host")
	}
	if snapshot.Generation() == 0 {
		t.Fatalf("missing generation")
	}

	selection, err := snapshot.Sort("type,address")
	if err != nil {
		t.Fatalf("unable to sort host snapshot: %v", err)
	}
	if got, want := selection.Len(), snapshot.Len(); got != want {
		t.Fatalf("sort changed entry count: got %d; want %d", got, want)
	}

	// Concurrently observing the host's interface list must not affect reads.
	done := make(chan struct{})
	go func() {
		defer close(done)
		for range 25 {
			_, _ = net.Interfaces()
			_, _ = net.InterfaceAddrs()
		}
	}()
	for range 25 {
		if got, want := snapshot.Len(), selection.Len(); got != want {
			t.Errorf("snapshot length changed while the host changed: got %d; want %d", got, want)
		}
	}
	<-done
}
