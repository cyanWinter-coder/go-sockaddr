## Unreleased

### Improvements

* Add `CaptureIfSnapshot` / `CaptureIfSnapshotFrom` for immutable, point-in-time
  interface snapshots covering addresses, flags, and default-route attributes.
* Add generation-tagged `IfSelection` pipelines where `include`, `exclude`, and
  `sort` read only the captured snapshot, including a captured "default" sort.
* Add stable `InterfaceKey` and `AddressFamily` metadata to snapshot entries,
  plus optional duplicate-address deduplication.
* Add `CompareIfSnapshots` / `IfSnapshot.DiffFrom` to report added, removed, and
  changed entries without rescanning the host.
* Add snapshot-backed `DefaultSelection`, `PrivateSelection`, and
  `PublicSelection` views.

### Changes

### Fixed

### Security
