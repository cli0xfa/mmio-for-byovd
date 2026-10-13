# Release checklist

- Run the driver-free test suite in MSVC x64 Debug and Release under C++20 and C++23.
- Review `/analyze` output and explain any warnings; do not suppress warnings without a reason.
- Attach Windows build, build number, privilege result, paging mode, and range-provider details to any runtime compatibility claim.
- Test VBS/HVCI, Hyper-V, and driver policy only in an authorized disposable VM. Report policy blocks as environment constraints; do not add bypass code.
- Keep `integration/winio/WinIo.sys` out of CI artifacts and ordinary consumer packages. The integration harness is opt-in and must not be run on a production host.
- Review licenses, source provenance, and vulnerability status of any driver resource before redistribution.
- Update README, compatibility notes, and CHANGELOG with tested evidence before tagging a release.
