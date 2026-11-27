# Windows scanner assessment

## Baseline at the start of this assessment

The scanner is implemented directly against POSIX descriptor-relative APIs.
Windows lacks the required Python `dir_fd`, descriptor-based directory
enumeration and no-follow support, so scans fail closed before opening the
target. The CLI's report writer also depends on those APIs. No Windows native
filesystem layer exists. The current development host is macOS; neither a
Windows execution environment nor a running Linux container is available.

## Existing controls and weaknesses

- POSIX path components are opened relative to directory descriptors with
  `O_NOFOLLOW`; file identity, size and timestamps are compared before and
  after streaming. Files are read-only and links are not intentionally followed.
- File size, chunk size and directory entry count are bounded; scans are
  sequential and cancellable between operations.
- These checks are not a snapshot: directory renames, hard links, mount points,
  hostile filesystems and metadata-preserving changes remain limitations.
  Directory nesting and operation duration lack explicit configurable limits;
  a blocked filesystem call can delay cancellation.
- Symlinks and special objects discovered during traversal incremented
  a skip counter without recording the individual path or reason. That is not
  sufficient for an auditable report.
- Discovery, safe access, traversal and POSIX-specific calls are coupled in the
  scan orchestrator. There is no filesystem adapter contract.
- `Path.is_symlink()` does not cover all Windows reparse points. Checking an
  ancestor by pathname and then calling `CreateFileW` on a full path does not
  prevent the ancestor being replaced with a junction between the two steps.
  `FILE_FLAG_OPEN_REPARSE_POINT` alone must not be treated as a guarantee for
  every ancestor.
- Windows network paths, alternate streams, device names, file identities,
  sharing violations and safe report creation have not been implemented or
  tested. All Windows scanning and report writing remain unsupported.

## Proposed Windows design

Introduce a narrow filesystem adapter whose operations own and close their
native handles; shared scanning consumes entries and readable file handles
without using Windows flags. Preserve the existing POSIX checks behind the
corresponding adapter. Fail closed if a filesystem cannot supply required
identity or no-reparse guarantees.

Before any integration, evaluate handle-relative opening of each *single*
component using Windows native directory handles. Microsoft's
[`NtCreateFile`](https://learn.microsoft.com/en-us/windows/win32/api/winternl/nf-winternl-ntcreatefile)
documents `OBJECT_ATTRIBUTES.RootDirectory` for relative opens. Its user-mode
ABI, reparse options, directory enumeration, filesystem compatibility and
support lifecycle require dedicated review and real Windows validation.
`CreateFileW` with `FILE_FLAG_OPEN_REPARSE_POINT` is useful for opening a
reparse point itself, not a sufficient replacement for anchored traversal;
see Microsoft's [symbolic-link API behavior](https://learn.microsoft.com/en-us/windows/win32/fileio/symbolic-link-effects-on-file-systems-functions).
Use `GetFileInformationByHandleEx` to evaluate `FILE_ID_INFO`,
`FILE_STANDARD_INFO`, `FILE_BASIC_INFO` and attribute/tag information where
supported; verify file type, volume/file ID, size, attributes and change times
on the handle before and after the read, and check the directory entry again.
Explicitly reject unavailable identity information. All failures and opened
handles must be accounted for. The implementation must not enable an unsafe
path-based fallback or claim snapshot consistency.

Initially reject UNC/network paths, device namespaces and explicit alternate
data streams. Scanning the unnamed data stream does **not** assess alternate
streams; reporting must state this limitation. Consider mapped network drives,
mount points and volume types too, not only UNC syntax. Long path and Unicode
behavior require native tests. Windows report creation needs its own
handle-relative, exclusive-create design and must not reuse POSIX code.

## Required tests and implementation plan

1. Record each skipped POSIX link or special object with an explicit reason;
   preserve existing classification and report counters.
2. Add CI for macOS/Linux regression and Windows fail-closed behavior; do not
   treat an unexecuted Windows-native test as evidence of Windows support.
3. Design and review the adapter contract and Windows native API use before
   integrating it into shared traversal. Then implement and test the complete
   handle lifecycle on Windows 10 and 11, including deterministic replacement
   races, junctions, all reparse types, long/Unicode paths, access failures,
   stream/network policy, handle cleanup and secure report creation.
4. Validate on real local filesystems and document unsupported filesystems,
   residual races, resource bounds, and benchmark conditions.

The critical blocker is that secure Windows traversal requires an anchored
native enumeration/opening design and tests on Windows; neither exists in this
environment. An unvalidated `CreateFileW` wrapper or pathname traversal would
weaken the existing boundary. Do not enable Windows scanning or describe it as
implemented until that design is reviewed and the native tests pass. No new
dependency is justified by the current assessment.
