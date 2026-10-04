# Linux file erase and backup restore, usb-flash, 2026-09-28 and 2026-09-29

Two runs on one device. They validate `linux / file_erase / usb-flash` and
`linux / backup_restore / usb-flash` and nothing else.

| | |
|---|---|
| Device | TOSHIBA TransMemory, serial `B103B9C19DE1CCC1BD535ACB`, 7,759,462,400 bytes, USB, designated test media |
| Host | Fedora Linux 44, kernel 6.19.10-300.fc44.x86_64 |
| Build | unpackaged development tree; the ledger records `tool_version` 0.0.0 and no commit, so the commit is not recorded |
| Evidence | `ledger-excerpt.jsonl` (ledger entries 15-27 and 172-206, hash chain intact) and the result blobs the entries point to, in `blobs/` |

The evidence comes from the operator's local ledger. No signed report was saved
for either job, so neither run has a report hash.

## File erase (2026-09-28)

* Job `erase-files-9d78dbec154e` erased one file, `img01.jpg` (22,973 bytes), on
  the mounted vfat volume `SANCTUMREC`. It cleansed JPEG metadata, overwrote
  22,973 bytes, truncated in four steps, renamed eight times, unlinked, and
  erased one thumbnail-cache copy. `ok` is true.
* An earlier job, `erase-files-d7d281692fb6`, used a relative path and failed
  with `ENOENT`. It erased nothing.

**Read-back verification did not happen.** vfat gives no extent map, so
`verification.passed` is null (`strategy: not_possible`, 0 bytes checked). The
report claims nothing about the medium. The inspection also recorded FILE_SLACK
(1,603 bytes of slack in the last cluster) that a file handle cannot reach.
The cell reads SUPPORTED because a run completed on real hardware of this class,
not because the old bytes were shown to be gone. Flash wear-levelling may have
kept older pages.

## Backup restore (2026-09-29)

* Job `restore-00b0e02a18df` wrote backup `bk-40549f6d27c0b9f8` back to
  `/dev/sda`, the device it was taken from (`identity_relation: same_device`),
  7,759,462,400 of 7,759,462,400 bytes. The target was not mounted and not a
  system disk.
* Result `RESTORED_VERIFIED`. The read-back of every byte hashes to the image
  SHA-256 `d4e1181b1d96783a97fdc44ae29d170a14c381d58d8176b523df6c572f630a91`,
  with 0 mismatched and 0 unreadable chunks.
* An earlier restore attempt (entries 138-169) has no completion entry. It did
  not finish.

## What this does not establish

* The read-back goes through the operating system after a flush. A volatile
  write cache can still answer it, so it shows what the device returns now, not
  what survives a power cut.
* The backup image is operator-supplied. Its hashes prove it has not changed
  since it was hashed, not where it came from.
* One USB flash stick, one FAT32 file, one same-device restore. Nothing here
  says anything about ext4, btrfs or xfs, cross-device restore, internal disks,
  other device classes, Windows or macOS.
* The operator identity is a local account, not a person.

## Withheld

The `restore.authorize` blobs (the authorization parameters and result) are not
copied here. The ledger excerpt keeps their hashes, so the chain still verifies.
