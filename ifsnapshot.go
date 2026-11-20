// Copyright IBM Corp. 2016, 2026
// SPDX-License-Identifier: MPL-2.0

package sockaddr

import (
	"cmp"
	"context"
	"errors"
	"fmt"
	"math/big"
	"net"
	"slices"
	"strconv"
	"strings"
	"sync/atomic"
	"time"
)

var (
	// ErrSnapshotIncomplete is returned when an interface snapshot cannot be
	// collected in full.  A snapshot is only returned when every interface and
	// address was captured successfully; callers never receive a partial view.
	ErrSnapshotIncomplete = errors.New("interface snapshot incomplete")

	// ErrSnapshotSourceNil is returned when CaptureIfSnapshotFrom is called
	// without a source.
	ErrSnapshotSourceNil = errors.New("interface snapshot source is nil")
)

// InterfaceKey is a stable identifier for an interface within a snapshot.  It
// is derived from the interface name so that it remains usable when comparing
// snapshots taken at different times.  On platforms that do not report an
// interface name, a synthetic index-based key is used instead.
type InterfaceKey string

// InterfaceKeyFor returns the stable key for iface.
func InterfaceKeyFor(iface net.Interface) InterfaceKey {
	if iface.Name != "" {
		return InterfaceKey(iface.Name)
	}
	return InterfaceKey(fmt.Sprintf("index:%d", iface.Index))
}

// AddressFamily identifies the address family of a snapshot entry.
type AddressFamily uint8

const (
	// AddressFamilyUnknown is used for address types this package does not know.
	AddressFamilyUnknown AddressFamily = iota

	// AddressFamilyIPv4 identifies an IPv4 address.
	AddressFamilyIPv4

	// AddressFamilyIPv6 identifies an IPv6 address.
	AddressFamilyIPv6

	// AddressFamilyUnix identifies a UNIX socket path.
	AddressFamilyUnix
)

// String returns the human readable name of the address family.
func (f AddressFamily) String() string {
	switch f {
	case AddressFamilyIPv4:
		return "IPv4"
	case AddressFamilyIPv6:
		return "IPv6"
	case AddressFamilyUnix:
		return "UNIX"
	case AddressFamilyUnknown:
		return "unknown"
	default:
		return fmt.Sprintf("AddressFamily(%d)", uint8(f))
	}
}

// AddressFamilyOf returns the address family of sa.
func AddressFamilyOf(sa SockAddr) AddressFamily {
	if sa == nil {
		return AddressFamilyUnknown
	}

	switch sa.Type() {
	case TypeIPv4:
		return AddressFamilyIPv4
	case TypeIPv6:
		return AddressFamilyIPv6
	case TypeUnix:
		return AddressFamilyUnix
	default:
		return AddressFamilyUnknown
	}
}

// IfSnapshotEntry is a single interface address captured in an IfSnapshot.
// Key and Family identify the result independently of the address value, which
// makes entries stable across snapshot comparisons.
type IfSnapshotEntry struct {
	// Key is the stable interface identifier.
	Key InterfaceKey

	// Family is the address family of IfAddr's SockAddr.
	Family AddressFamily

	// IfAddr is the captured address and interface attributes.
	IfAddr IfAddr

	// DefaultRoute reports whether the address is attached to the interface
	// carrying the default route, as observed when the snapshot was captured.
	DefaultRoute bool
}

// Name returns the interface name.
func (e IfSnapshotEntry) Name() string {
	return e.IfAddr.Name
}

// Address returns the captured address in its string form.
func (e IfSnapshotEntry) Address() string {
	if e.IfAddr.SockAddr == nil {
		return ""
	}
	return e.IfAddr.SockAddr.String()
}

// Attr returns the named attribute of the captured address.
func (e IfSnapshotEntry) Attr(attrName AttrName) (string, error) {
	return e.IfAddr.Attr(attrName)
}

// IfSnapshotConfig controls how an IfSnapshot is collected.
type IfSnapshotConfig struct {
	// DedupeAddresses collapses entries that share an address family and host
	// address.  The first entry in canonical order is kept.  When false,
	// duplicate addresses are preserved.  The default preserves the behavior of
	// the existing Get*Interfaces functions.
	DedupeAddresses bool

	// IgnoreRouteInfoErrors records route information as unavailable instead of
	// failing when the default route cannot be determined.  When false (the
	// default), a route information failure fails the snapshot.  Context
	// cancellation is always reported as an error, regardless of this setting.
	IgnoreRouteInfoErrors bool
}

// IfSnapshotSource supplies the raw data used to build an IfSnapshot.  The
// interface exists so callers can provide deterministic or synthetic data,
// and so collection can be tested without touching the host.
type IfSnapshotSource interface {
	// Interfaces returns the interfaces to capture.
	Interfaces() ([]net.Interface, error)

	// InterfaceAddrs returns the addresses configured on iface.
	InterfaceAddrs(iface net.Interface) ([]net.Addr, error)

	// DefaultInterfaceName returns the name of the interface carrying the
	// default route.  Implementations should honor ctx cancellation.
	DefaultInterfaceName(ctx context.Context) (string, error)
}

type systemIfSnapshotSource struct{}

func (systemIfSnapshotSource) Interfaces() ([]net.Interface, error) {
	return net.Interfaces()
}

func (systemIfSnapshotSource) InterfaceAddrs(iface net.Interface) ([]net.Addr, error) {
	return iface.Addrs()
}

func (systemIfSnapshotSource) DefaultInterfaceName(ctx context.Context) (string, error) {
	ri, err := NewRouteInfo()
	if err != nil {
		return "", err
	}

	if ctx == nil {
		ctx = context.Background()
	}
	if err := ctx.Err(); err != nil {
		return "", err
	}

	type result struct {
		name string
		err  error
	}

	// GetDefaultInterfaceName has no context-aware variant, so run it in a
	// goroutine and stop waiting as soon as the caller cancels.  The buffered
	// channel lets the goroutine finish without blocking if we return early.
	done := make(chan result, 1)
	go func() {
		name, err := ri.GetDefaultInterfaceName()
		done <- result{name: name, err: err}
	}()

	select {
	case <-ctx.Done():
		return "", ctx.Err()
	case res := <-done:
		return res.name, res.err
	}
}

// IfSnapshot is an immutable view of the host's interfaces, addresses, flags,
// and default-route attributes captured at a single point in time.  Once
// captured, its contents never change: include, exclude, sort, and diff
// operations read only the captured data and never consult the host again.
//
// All read methods are safe for concurrent use without locking.  Entries are
// returned by value (including copies of mutable fields), so callers cannot
// mutate the snapshot through a returned result.
type IfSnapshot struct {
	generation         uint64
	capturedAt         time.Time
	entries            []IfSnapshotEntry
	defaultIfName      string
	routeInfoAvailable bool
}

var ifSnapshotGeneration atomic.Uint64

func nextIfSnapshotGeneration() uint64 {
	for {
		if generation := ifSnapshotGeneration.Add(1); generation != 0 {
			return generation
		}
	}
}

// CaptureIfSnapshot collects the host's interfaces, addresses, flags, and
// default-route information and returns them as an immutable snapshot.  The
// snapshot is all-or-nothing: if any part of the collection fails, or ctx is
// canceled, an error wrapping ErrSnapshotIncomplete is returned and the
// snapshot is nil.
func CaptureIfSnapshot(ctx context.Context, cfg IfSnapshotConfig) (*IfSnapshot, error) {
	return CaptureIfSnapshotFrom(ctx, systemIfSnapshotSource{}, cfg)
}

// CaptureIfSnapshotFrom is identical to CaptureIfSnapshot but reads from src
// instead of the host.
func CaptureIfSnapshotFrom(ctx context.Context, src IfSnapshotSource, cfg IfSnapshotConfig) (*IfSnapshot, error) {
	if src == nil {
		return nil, ErrSnapshotSourceNil
	}
	if ctx == nil {
		ctx = context.Background()
	}
	if err := ctx.Err(); err != nil {
		return nil, snapshotAborted(err)
	}

	ifaces, err := src.Interfaces()
	if err != nil {
		return nil, snapshotFailed("unable to list network interfaces", err)
	}
	if err := ctx.Err(); err != nil {
		return nil, snapshotAborted(err)
	}

	entries := make([]IfSnapshotEntry, 0, len(ifaces))
	for _, iface := range ifaces {
		if err := ctx.Err(); err != nil {
			return nil, snapshotAborted(err)
		}

		addrs, err := src.InterfaceAddrs(iface)
		if err != nil {
			return nil, snapshotFailed(fmt.Sprintf("unable to read addresses for interface %q", iface.Name), err)
		}

		capturedIface := cloneInterface(iface)
		key := InterfaceKeyFor(capturedIface)
		for _, addr := range addrs {
			if err := ctx.Err(); err != nil {
				return nil, snapshotAborted(err)
			}

			ipAddr, err := NewIPAddr(addr.String())
			if err != nil {
				return nil, snapshotFailed(fmt.Sprintf("unable to parse address %q on interface %q", addr.String(), capturedIface.Name), err)
			}

			entries = append(entries, IfSnapshotEntry{
				Key:    key,
				Family: AddressFamilyOf(ipAddr),
				IfAddr: IfAddr{
					SockAddr:  cloneSockAddr(ipAddr),
					Interface: capturedIface,
				},
			})
		}
	}

	defaultIfName, routeInfoAvailable, err := captureRouteInfo(ctx, src, cfg)
	if err != nil {
		return nil, err
	}
	for i := range entries {
		entries[i].DefaultRoute = routeInfoAvailable && defaultIfName != "" && entries[i].Name() == defaultIfName
	}

	// Canonical ordering makes snapshots reproducible and gives dedupe a stable
	// winner.  The sort is stable so identical entries keep their relative
	// order.
	sortSnapshotEntriesCanonical(entries)
	if cfg.DedupeAddresses {
		entries = dedupeSnapshotEntries(entries)
	}

	if err := ctx.Err(); err != nil {
		return nil, snapshotAborted(err)
	}

	return &IfSnapshot{
		generation:         nextIfSnapshotGeneration(),
		capturedAt:         time.Now().UTC(),
		entries:            entries,
		defaultIfName:      defaultIfName,
		routeInfoAvailable: routeInfoAvailable,
	}, nil
}

func captureRouteInfo(ctx context.Context, src IfSnapshotSource, cfg IfSnapshotConfig) (string, bool, error) {
	defaultIfName, err := src.DefaultInterfaceName(ctx)
	if err != nil {
		if errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
			return "", false, snapshotAborted(err)
		}
		if ctxErr := ctx.Err(); ctxErr != nil {
			return "", false, snapshotAborted(ctxErr)
		}
		if cfg.IgnoreRouteInfoErrors {
			return "", false, nil
		}
		return "", false, snapshotFailed("unable to read default-route information", err)
	}
	if err := ctx.Err(); err != nil {
		return "", false, snapshotAborted(err)
	}

	return defaultIfName, true, nil
}

func snapshotFailed(msg string, err error) error {
	return fmt.Errorf("%w: %s: %w", ErrSnapshotIncomplete, msg, err)
}

func snapshotAborted(err error) error {
	return fmt.Errorf("%w: interface snapshot aborted: %w", ErrSnapshotIncomplete, err)
}

// Generation returns the generation assigned to the snapshot when it was
// captured.  Generations increase monotonically for snapshots captured by the
// process.
func (s *IfSnapshot) Generation() uint64 {
	if s == nil {
		return 0
	}
	return s.generation
}

// CapturedAt returns the wall-clock time at which the snapshot completed.
func (s *IfSnapshot) CapturedAt() time.Time {
	if s == nil {
		return time.Time{}
	}
	return s.capturedAt
}

// DefaultInterfaceName returns the interface name observed for the default
// route when the snapshot was captured.  It is empty if route information was
// unavailable.
func (s *IfSnapshot) DefaultInterfaceName() string {
	if s == nil {
		return ""
	}
	return s.defaultIfName
}

// HasRouteInfo reports whether default-route information was captured
// successfully.
func (s *IfSnapshot) HasRouteInfo() bool {
	if s == nil {
		return false
	}
	return s.routeInfoAvailable
}

// Len returns the number of captured entries.
func (s *IfSnapshot) Len() int {
	if s == nil {
		return 0
	}
	return len(s.entries)
}

// Entries returns copies of all captured entries in canonical order.
func (s *IfSnapshot) Entries() []IfSnapshotEntry {
	if s == nil {
		return nil
	}
	return cloneSnapshotEntries(s.entries)
}

// IfAddrs returns copies of all captured addresses in canonical order.  This is
// the snapshot equivalent of GetAllInterfaces and is suitable for callers that
// only need the legacy representation.
func (s *IfSnapshot) IfAddrs() IfAddrs {
	if s == nil {
		return nil
	}

	ifAddrs := make(IfAddrs, 0, len(s.entries))
	for _, entry := range s.entries {
		ifAddrs = append(ifAddrs, cloneIfAddr(entry.IfAddr))
	}
	return ifAddrs
}

// Select starts a generation-tagged selection over the snapshot.  Every
// include, exclude, and sort operation on the returned selection reads only
// the snapshot's captured data.
func (s *IfSnapshot) Select() IfSelection {
	if s == nil {
		return IfSelection{}
	}
	return IfSelection{
		generation: s.generation,
		entries:    cloneSnapshotEntries(s.entries),
	}
}

// Include returns the entries matching the selector.  It is a snapshot-backed
// equivalent of IncludeIfs.
func (s *IfSnapshot) Include(selectorName, selectorParam string) (IfSelection, error) {
	return s.Select().Include(selectorName, selectorParam)
}

// Exclude returns the entries not matching the selector.  It is a
// snapshot-backed equivalent of ExcludeIfs.
func (s *IfSnapshot) Exclude(selectorName, selectorParam string) (IfSelection, error) {
	return s.Select().Exclude(selectorName, selectorParam)
}

// Sort returns the entries sorted according to selectorParam.  It accepts the
// same syntax as SortIfBy but resolves the "default" clause from the captured
// route information instead of querying the host again.
func (s *IfSnapshot) Sort(selectorParam string) (IfSelection, error) {
	return s.Select().Sort(selectorParam)
}

// DiffFrom compares before with the receiver and returns the differences.
func (s *IfSnapshot) DiffFrom(before *IfSnapshot) IfSnapshotDiff {
	return CompareIfSnapshots(before, s)
}

// DefaultSelection returns the entries attached to the captured default route.
// It is the snapshot equivalent of GetDefaultInterfaces and never re-reads the
// host's route table.
func (s *IfSnapshot) DefaultSelection() IfSelection {
	selection := s.Select()
	defaults := make([]IfSnapshotEntry, 0, len(selection.entries))
	for _, entry := range selection.entries {
		if entry.DefaultRoute {
			defaults = append(defaults, entry)
		}
	}
	return IfSelection{
		generation: selection.generation,
		entries:    defaults,
	}
}

// PrivateSelection returns the entries included in RFC 6890 that are attached
// to the captured default route and are forwardable.  It is the snapshot
// equivalent of GetPrivateInterfaces.
func (s *IfSnapshot) PrivateSelection() (IfSelection, error) {
	selection, err := s.privatePublicSelection()
	if err != nil {
		return IfSelection{generation: s.Generation()}, err
	}
	return selection.Include("rfc", "6890")
}

// PublicSelection returns the entries that are not part of RFC 6890 but are
// attached to the captured default route and are forwardable.  It is the
// snapshot equivalent of GetPublicInterfaces.
func (s *IfSnapshot) PublicSelection() (IfSelection, error) {
	selection, err := s.privatePublicSelection()
	if err != nil {
		return IfSelection{generation: s.Generation()}, err
	}
	return selection.Exclude("rfc", "6890")
}

func (s *IfSnapshot) privatePublicSelection() (IfSelection, error) {
	selection, err := s.Select().Include("type", "ip")
	if err != nil {
		return IfSelection{generation: s.Generation()}, err
	}
	if selection, err = selection.Include("flags", "forwardable"); err != nil {
		return IfSelection{generation: s.Generation()}, err
	}
	if selection, err = selection.Include("flags", "up"); err != nil {
		return IfSelection{generation: s.Generation()}, err
	}
	return selection.Sort("default,type,size")
}

// IfSelection is a generation-tagged list of entries selected from an
// IfSnapshot.  The generation lets callers verify that chained operations all
// refer to the same captured view.
type IfSelection struct {
	generation uint64
	entries    []IfSnapshotEntry
}

// Generation returns the generation of the snapshot this selection came from.
func (sel IfSelection) Generation() uint64 {
	return sel.generation
}

// Len returns the number of selected entries.
func (sel IfSelection) Len() int {
	return len(sel.entries)
}

// Entries returns copies of the selected entries in their current order.
func (sel IfSelection) Entries() []IfSnapshotEntry {
	return cloneSnapshotEntries(sel.entries)
}

// IfAddrs returns copies of the selected addresses in their current order.
func (sel IfSelection) IfAddrs() IfAddrs {
	ifAddrs := make(IfAddrs, 0, len(sel.entries))
	for _, entry := range sel.entries {
		ifAddrs = append(ifAddrs, cloneIfAddr(entry.IfAddr))
	}
	return ifAddrs
}

// Include returns the subset of the selection matching the selector.
func (sel IfSelection) Include(selectorName, selectorParam string) (IfSelection, error) {
	matched, err := IncludeIfs(selectorName, selectorParam, sel.IfAddrs())
	if err != nil {
		return IfSelection{generation: sel.generation}, err
	}

	return IfSelection{
		generation: sel.generation,
		entries:    snapshotEntriesForIfAddrs(sel.entries, matched),
	}, nil
}

// Exclude returns the subset of the selection not matching the selector.
func (sel IfSelection) Exclude(selectorName, selectorParam string) (IfSelection, error) {
	excluded, err := ExcludeIfs(selectorName, selectorParam, sel.IfAddrs())
	if err != nil {
		return IfSelection{generation: sel.generation}, err
	}

	return IfSelection{
		generation: sel.generation,
		entries:    snapshotEntriesForIfAddrs(sel.entries, excluded),
	}, nil
}

// Sort returns the selection sorted according to selectorParam.  The "default"
// clause is resolved from the snapshot's captured route information.
func (sel IfSelection) Sort(selectorParam string) (IfSelection, error) {
	comparators, err := snapshotSortComparators(selectorParam)
	if err != nil {
		return IfSelection{generation: sel.generation}, err
	}

	sorted := slices.Clone(sel.entries)
	slices.SortStableFunc(sorted, func(a, b IfSnapshotEntry) int {
		for _, compare := range comparators {
			if result := compare(a, b); result != sortDeferDecision {
				return result
			}
		}
		return sortDeferDecision
	})

	return IfSelection{
		generation: sel.generation,
		entries:    sorted,
	}, nil
}

// DedupeByAddress removes entries whose address family and host address match
// an earlier entry, preserving the existing order.
func (sel IfSelection) DedupeByAddress() IfSelection {
	return IfSelection{
		generation: sel.generation,
		entries:    dedupeSnapshotEntries(slices.Clone(sel.entries)),
	}
}

func snapshotSortComparators(selectorParam string) ([]func(IfSnapshotEntry, IfSnapshotEntry) int, error) {
	clauses := strings.Split(selectorParam, ",")
	comparators := make([]func(IfSnapshotEntry, IfSnapshotEntry) int, 0, len(clauses))

	for _, clause := range clauses {
		switch strings.TrimSpace(strings.ToLower(clause)) {
		case "+address", "address":
			comparators = append(comparators, snapshotIfAddrComparator(AscIfAddress))
		case "-address":
			comparators = append(comparators, snapshotIfAddrComparator(DescIfAddress))
		case "+default", "default":
			comparators = append(comparators, ascSnapshotDefault)
		case "-default":
			comparators = append(comparators, descSnapshotDefault)
		case "+name", "name":
			comparators = append(comparators, snapshotIfAddrComparator(AscIfName))
		case "-name":
			comparators = append(comparators, snapshotIfAddrComparator(DescIfName))
		case "+port", "port":
			comparators = append(comparators, snapshotIfAddrComparator(AscIfPort))
		case "-port":
			comparators = append(comparators, snapshotIfAddrComparator(DescIfPort))
		case "+private", "private":
			comparators = append(comparators, snapshotIfAddrComparator(AscIfPrivate))
		case "-private":
			comparators = append(comparators, snapshotIfAddrComparator(DescIfPrivate))
		case "+size", "size":
			comparators = append(comparators, snapshotIfAddrComparator(AscIfNetworkSize))
		case "-size":
			comparators = append(comparators, snapshotIfAddrComparator(DescIfNetworkSize))
		case "+type", "type":
			comparators = append(comparators, snapshotIfAddrComparator(AscIfType))
		case "-type":
			comparators = append(comparators, snapshotIfAddrComparator(DescIfType))
		default:
			return nil, fmt.Errorf("unknown sort type: %q", clause)
		}
	}

	return comparators, nil
}

func snapshotIfAddrComparator(cmpFunc CmpIfAddrFunc) func(IfSnapshotEntry, IfSnapshotEntry) int {
	return func(a, b IfSnapshotEntry) int {
		return cmpFunc(&a.IfAddr, &b.IfAddr)
	}
}

func ascSnapshotDefault(a, b IfSnapshotEntry) int {
	switch {
	case a.DefaultRoute && b.DefaultRoute:
		return sortDeferDecision
	case a.DefaultRoute:
		return sortReceiverBeforeArg
	case b.DefaultRoute:
		return sortArgBeforeReceiver
	default:
		return sortDeferDecision
	}
}

func descSnapshotDefault(a, b IfSnapshotEntry) int {
	return -1 * ascSnapshotDefault(a, b)
}

func sortSnapshotEntriesCanonical(entries []IfSnapshotEntry) {
	slices.SortStableFunc(entries, func(a, b IfSnapshotEntry) int {
		if result := strings.Compare(string(a.Key), string(b.Key)); result != 0 {
			return result
		}
		if result := cmp.Compare(a.Family, b.Family); result != 0 {
			return result
		}
		if result := strings.Compare(a.Address(), b.Address()); result != 0 {
			return result
		}
		return cmp.Compare(a.IfAddr.Index, b.IfAddr.Index)
	})
}

type snapshotAddressToken struct {
	family  AddressFamily
	address string
}

func snapshotAddressOf(entry IfSnapshotEntry) snapshotAddressToken {
	return snapshotAddressToken{
		family:  entry.Family,
		address: hostAddress(entry.IfAddr.SockAddr),
	}
}

func dedupeSnapshotEntries(entries []IfSnapshotEntry) []IfSnapshotEntry {
	seen := make(map[snapshotAddressToken]struct{}, len(entries))
	deduped := make([]IfSnapshotEntry, 0, len(entries))
	for _, entry := range entries {
		token := snapshotAddressOf(entry)
		if _, found := seen[token]; found {
			continue
		}
		seen[token] = struct{}{}
		deduped = append(deduped, entry)
	}
	return deduped
}

func hostAddress(sa SockAddr) string {
	switch v := sa.(type) {
	case IPv4Addr:
		return v.NetIP().String()
	case IPv6Addr:
		return v.NetIP().String()
	case UnixSock:
		return v.Path()
	default:
		if sa == nil {
			return ""
		}
		return sa.String()
	}
}

// snapshotEntriesForIfAddrs maps filtered IfAddrs back to their snapshot
// entries.  Filters preserve input order and never synthesize addresses, so
// matching on the full IfAddr value is sufficient to recover the key and
// family metadata.
//
// The legacy filters can report the same input more than once (for example,
// IfByType with multiple types appends a match once per type).  Those repeated
// results are mapped back onto the same entry so a selection reproduces the
// filter's multiplicity instead of silently collapsing it.
func snapshotEntriesForIfAddrs(entries []IfSnapshotEntry, ifAddrs IfAddrs) []IfSnapshotEntry {
	candidates := make(map[string][]IfSnapshotEntry, len(entries))
	used := make(map[string]int, len(entries))
	for _, entry := range entries {
		token := snapshotIfAddrToken(entry.IfAddr)
		candidates[token] = append(candidates[token], entry)
	}

	matched := make([]IfSnapshotEntry, 0, len(ifAddrs))
	for _, ifAddr := range ifAddrs {
		token := snapshotIfAddrToken(ifAddr)
		available := candidates[token]
		if len(available) == 0 {
			continue
		}

		index := min(used[token], len(available)-1)
		used[token]++
		matched = append(matched, available[index])
	}
	return matched
}

func snapshotIfAddrToken(ifAddr IfAddr) string {
	var sb strings.Builder
	sb.WriteString(hostAddress(ifAddr.SockAddr))
	sb.WriteByte(0)
	sb.WriteString(ifAddr.SockAddr.String())
	sb.WriteByte(0)
	sb.WriteString(string(InterfaceKeyFor(ifAddr.Interface)))
	sb.WriteByte(0)
	sb.WriteString(strconv.Itoa(ifAddr.Index))
	sb.WriteByte(0)
	sb.WriteString(strconv.Itoa(ifAddr.MTU))
	sb.WriteByte(0)
	sb.WriteString(ifAddr.Flags.String())
	sb.WriteByte(0)
	sb.WriteString(ifAddr.HardwareAddr.String())
	return sb.String()
}

// IfSnapshotDiff describes the difference between two snapshots.
type IfSnapshotDiff struct {
	// BeforeGeneration and AfterGeneration identify the compared snapshots.
	BeforeGeneration uint64
	AfterGeneration  uint64

	// Added contains entries present only in the later snapshot.
	Added []IfSnapshotEntry

	// Removed contains entries present only in the earlier snapshot.
	Removed []IfSnapshotEntry

	// Changed contains entries present in both snapshots whose attributes
	// differ.
	Changed []IfSnapshotEntryChange
}

// Empty reports whether the snapshots were identical.
func (d IfSnapshotDiff) Empty() bool {
	return len(d.Added) == 0 && len(d.Removed) == 0 && len(d.Changed) == 0
}

// IfSnapshotEntryChange describes an entry that exists in both snapshots but
// whose attributes changed.
type IfSnapshotEntryChange struct {
	// Key, Family, and Address identify the stable entry that changed.
	Key     InterfaceKey
	Family  AddressFamily
	Address string

	// Before and After are copies of the entry on each side of the comparison.
	Before IfSnapshotEntry
	After  IfSnapshotEntry

	// Changes lists the attributes that differ.
	Changes []IfAttributeChange
}

// IfAttributeChange is a single attribute difference between two entries.
type IfAttributeChange struct {
	Name   string
	Before string
	After  string
}

type snapshotEntryIdentity struct {
	key     InterfaceKey
	family  AddressFamily
	address string
}

func snapshotEntryIdentityOf(entry IfSnapshotEntry) snapshotEntryIdentity {
	return snapshotEntryIdentity{
		key:     entry.Key,
		family:  entry.Family,
		address: hostAddress(entry.IfAddr.SockAddr),
	}
}

// CompareIfSnapshots compares before and after and returns the entries that
// were added, removed, or whose attributes changed.  Entries are matched by
// stable interface key, address family, and host address.  The comparison
// reads only the captured snapshots and does not rescan the host.
func CompareIfSnapshots(before, after *IfSnapshot) IfSnapshotDiff {
	diff := IfSnapshotDiff{
		BeforeGeneration: before.Generation(),
		AfterGeneration:  after.Generation(),
	}

	beforeGroups := groupSnapshotEntries(before)
	afterGroups := groupSnapshotEntries(after)

	identities := make([]snapshotEntryIdentity, 0, len(beforeGroups)+len(afterGroups))
	seen := make(map[snapshotEntryIdentity]struct{}, len(beforeGroups)+len(afterGroups))
	for identity := range beforeGroups {
		seen[identity] = struct{}{}
		identities = append(identities, identity)
	}
	for identity := range afterGroups {
		if _, found := seen[identity]; found {
			continue
		}
		identities = append(identities, identity)
	}
	slices.SortFunc(identities, compareSnapshotEntryIdentities)

	for _, identity := range identities {
		beforeEntries := beforeGroups[identity]
		afterEntries := afterGroups[identity]

		paired := min(len(beforeEntries), len(afterEntries))
		for i := range paired {
			changes := compareSnapshotEntries(beforeEntries[i], afterEntries[i])
			if len(changes) == 0 {
				continue
			}
			diff.Changed = append(diff.Changed, IfSnapshotEntryChange{
				Key:     identity.key,
				Family:  identity.family,
				Address: identity.address,
				Before:  cloneSnapshotEntry(beforeEntries[i]),
				After:   cloneSnapshotEntry(afterEntries[i]),
				Changes: changes,
			})
		}

		for _, entry := range afterEntries[paired:] {
			diff.Added = append(diff.Added, cloneSnapshotEntry(entry))
		}
		for _, entry := range beforeEntries[paired:] {
			diff.Removed = append(diff.Removed, cloneSnapshotEntry(entry))
		}
	}

	return diff
}

func groupSnapshotEntries(snapshot *IfSnapshot) map[snapshotEntryIdentity][]IfSnapshotEntry {
	if snapshot == nil {
		return nil
	}

	groups := make(map[snapshotEntryIdentity][]IfSnapshotEntry, len(snapshot.entries))
	for _, entry := range snapshot.entries {
		identity := snapshotEntryIdentityOf(entry)
		groups[identity] = append(groups[identity], entry)
	}
	return groups
}

func compareSnapshotEntryIdentities(a, b snapshotEntryIdentity) int {
	if result := strings.Compare(string(a.key), string(b.key)); result != 0 {
		return result
	}
	if result := cmp.Compare(a.family, b.family); result != 0 {
		return result
	}
	return strings.Compare(a.address, b.address)
}

type snapshotEntryAttribute struct {
	name  string
	value string
}

func snapshotEntryAttributes(entry IfSnapshotEntry) []snapshotEntryAttribute {
	attributes := []snapshotEntryAttribute{
		{name: "address", value: entry.Address()},
		{name: "flags", value: entry.IfAddr.Flags.String()},
		{name: "index", value: strconv.Itoa(entry.IfAddr.Index)},
		{name: "mtu", value: strconv.Itoa(entry.IfAddr.MTU)},
		{name: "hardware_addr", value: entry.IfAddr.HardwareAddr.String()},
		{name: "default_route", value: strconv.FormatBool(entry.DefaultRoute)},
	}

	if ip := ToIPAddr(entry.IfAddr.SockAddr); ip != nil {
		attributes = append(attributes,
			snapshotEntryAttribute{name: "mask_bits", value: strconv.Itoa((*ip).Maskbits())},
			snapshotEntryAttribute{name: "port", value: strconv.Itoa(int((*ip).IPPort()))},
		)
	}

	return attributes
}

func compareSnapshotEntries(before, after IfSnapshotEntry) []IfAttributeChange {
	beforeAttrs := snapshotEntryAttributes(before)
	afterAttrs := snapshotEntryAttributes(after)

	if len(beforeAttrs) != len(afterAttrs) {
		return []IfAttributeChange{{
			Name:   "attributes",
			Before: fmt.Sprint(beforeAttrs),
			After:  fmt.Sprint(afterAttrs),
		}}
	}

	changes := make([]IfAttributeChange, 0, len(beforeAttrs))
	for i := range beforeAttrs {
		if beforeAttrs[i].name != afterAttrs[i].name || beforeAttrs[i].value == afterAttrs[i].value {
			continue
		}
		changes = append(changes, IfAttributeChange{
			Name:   beforeAttrs[i].name,
			Before: beforeAttrs[i].value,
			After:  afterAttrs[i].value,
		})
	}
	return changes
}

func cloneSnapshotEntries(entries []IfSnapshotEntry) []IfSnapshotEntry {
	if entries == nil {
		return nil
	}

	cloned := make([]IfSnapshotEntry, len(entries))
	for i, entry := range entries {
		cloned[i] = cloneSnapshotEntry(entry)
	}
	return cloned
}

func cloneSnapshotEntry(entry IfSnapshotEntry) IfSnapshotEntry {
	entry.IfAddr = cloneIfAddr(entry.IfAddr)
	return entry
}

func cloneIfAddr(ifAddr IfAddr) IfAddr {
	ifAddr.SockAddr = cloneSockAddr(ifAddr.SockAddr)
	ifAddr.Interface = cloneInterface(ifAddr.Interface)
	return ifAddr
}

func cloneInterface(iface net.Interface) net.Interface {
	iface.HardwareAddr = slices.Clone(iface.HardwareAddr)
	return iface
}

func cloneSockAddr(sa SockAddr) SockAddr {
	switch v := sa.(type) {
	case IPv4Addr:
		return v
	case IPv6Addr:
		cloned := v
		if v.Address != nil {
			cloned.Address = IPv6Address(new(big.Int).Set(v.Address))
		}
		if v.Mask != nil {
			cloned.Mask = IPv6Mask(new(big.Int).Set(v.Mask))
		}
		return cloned
	case UnixSock:
		return v
	default:
		return sa
	}
}
