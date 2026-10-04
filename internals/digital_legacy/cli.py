"""Command line entry point.

The old scripts could only be run by a human sitting at a terminal: both blocked
on ``input()`` and opened Tk dialogs, so nothing could exercise them -- which is
why bugs like "[Step 6 of 5]" and the extension-mangling shipped.  Every
operation here is reachable with flags as well as through the wizard, so the
test suite drives the real code paths rather than approximations of them.

The wizards remain the default, because the people this tool is built for will
never type a command.
"""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

from . import __version__, agekeys, doctor, handoff, operations
from .console import Console, plain_console
from .errors import DigitalLegacyError, OperationCancelled
from .layout import Layout
from .policy import Policy
from .toolchain import Toolchain
from .vault import Manifest, Vault, now_iso
from .wizards import DecryptWizard, EncryptWizard

PROGRAM = "digital-legacy"


def build_parser() -> argparse.ArgumentParser:
    # Global flags live on a parent parser attached to every subcommand as well
    # as to the top level, so `--no-colour doctor` and `doctor --no-colour` both
    # work. argparse otherwise accepts a global flag only before the
    # subcommand, which is a trap for anyone driving this from a script.
    common = argparse.ArgumentParser(add_help=False)
    common.add_argument(
        "--no-colour",
        "--no-color",
        action="store_true",
        default=argparse.SUPPRESS,
        dest="no_colour",
        help="plain text output, for logs and scripts",
    )
    common.add_argument(
        "--quiet",
        action="store_true",
        default=argparse.SUPPRESS,
        help="suppress animation and pauses",
    )

    parser = argparse.ArgumentParser(
        prog=PROGRAM,
        parents=[common],
        description=(
            "Encrypt a document so that it can only be opened later when "
            "several keyholders bring their keys together."
        ),
    )
    parser.add_argument(
        "--version", action="version", version=f"{PROGRAM} {__version__}"
    )
    sub = parser.add_subparsers(dest="command")

    def add(name: str, **kwargs) -> argparse.ArgumentParser:
        return sub.add_parser(name, parents=[common], **kwargs)

    enc = add("encrypt", help="encrypt a document (wizard by default)")
    enc.add_argument("--file", type=Path, help="document to encrypt")
    enc.add_argument("--shares", type=int, help="how many keys to create")
    enc.add_argument(
        "--threshold", type=int, help="how many keys are needed to open it"
    )
    enc.add_argument(
        "--name",
        action="append",
        default=[],
        dest="names",
        metavar="LABEL",
        help="keyholder name; repeat once per share",
    )
    enc.add_argument("--owner", default="", help="your name, for the letters")
    enc.add_argument(
        "--use-existing-keys",
        action="store_true",
        help="encrypt to the recipients.yaml already in the vault",
    )
    enc.add_argument(
        "--key-prefix",
        help="start of each key file name (default: 'Key for Digital Legacy - ')",
    )
    enc.add_argument(
        "--shared-folder",
        action="store_true",
        default=None,
        help="keys are kept in a shared cloud folder, each shared with its holder",
    )
    enc.add_argument(
        "--key-notes",
        type=Path,
        metavar="FILE",
        help="text file whose lines are added to every key file as comments",
    )
    enc.add_argument(
        "--allow-unverified",
        action="store_true",
        help="do not fail when recovery cannot be demonstrated",
    )

    dec = add("decrypt", help="open an encrypted document (wizard by default)")
    dec.add_argument(
        "--key",
        action="append",
        default=[],
        dest="keys",
        type=Path,
        metavar="PATH",
        help="key file; repeat until the threshold is met",
    )
    dec.add_argument("--output", type=Path, help="folder to write the document into")
    dec.add_argument(
        "--document", help="which encrypted file to open, when there are several"
    )

    res = add(
        "reseal",
        help="re-encrypt for a different set of keyholders",
        description=(
            "Replace the keyholders on an existing document. Needs enough of "
            "the current keys to open it. The old encrypted file is deleted, "
            "because anyone holding an old key could still open it otherwise."
        ),
    )
    res.add_argument(
        "--key",
        action="append",
        default=[],
        dest="keys",
        type=Path,
        metavar="PATH",
        help="a current key file; repeat until the threshold is met",
    )
    res.add_argument("--shares", type=int, help="how many keys to create")
    res.add_argument("--threshold", type=int, help="how many of them are needed")
    res.add_argument(
        "--name", action="append", default=[], dest="names", metavar="LABEL",
        help="new keyholder name; repeat once per share",
    )
    res.add_argument("--owner", default="", help="your name, for the letters")
    res.add_argument(
        "--key-prefix",
        help="start of each key file name (default: 'Key for Digital Legacy - ')",
    )
    res.add_argument(
        "--shared-folder",
        action="store_true",
        default=None,
        help="keys are kept in a shared cloud folder, each shared with its holder",
    )
    res.add_argument(
        "--key-notes",
        type=Path,
        metavar="FILE",
        help="text file whose lines are added to every key file as comments",
    )
    res.add_argument(
        "--keep-old-file",
        action="store_true",
        help="do not delete the previous encrypted file (leaves old keys working)",
    )
    res.add_argument(
        "--document", help="which encrypted file to reseal, when there are several"
    )

    doc = add("doctor", help="check this installation and vault")
    doc.add_argument(
        "--deep",
        action="store_true",
        help="also test any key files still on this machine",
    )

    key = add("check-key", help="is this file a key for this document?")
    key.add_argument("path", type=Path)

    add("inspect", help="show what the encrypted file itself requires")

    hand = add("handoff", help="rewrite the keyholder letters")
    hand.add_argument("--output", type=Path, help="folder to write them into")

    return parser


def main(argv: list[str] | None = None, *, layout: Layout | None = None) -> int:
    """Run one command.  ``layout`` overrides where the project folder is found.

    Passing it explicitly is how the test suite guarantees a run cannot reach
    the real vault; ordinary use leaves it None and discovers from the package
    location or the DIGITAL_LEGACY_ROOT environment variable.
    """
    parser = build_parser()
    args = parser.parse_args(argv)
    layout = layout or Layout.discover()
    plain = getattr(args, "no_colour", False)
    quiet = getattr(args, "quiet", False)
    console = (
        plain_console()
        if plain
        else Console(animate=False if quiet else None, interactive=not quiet)
    )

    command = args.command or "decrypt"
    try:
        if command == "encrypt":
            return cmd_encrypt(args, layout, console)
        if command == "decrypt":
            return cmd_decrypt(args, layout, console)
        if command == "reseal":
            return cmd_reseal(args, layout, console)
        if command == "doctor":
            return cmd_doctor(args, layout, console)
        if command == "check-key":
            return cmd_check_key(args, layout, console)
        if command == "inspect":
            return cmd_inspect(args, layout, console)
        if command == "handoff":
            return cmd_handoff(args, layout, console)
    except OperationCancelled as exc:
        console.warn(exc.message)
        return 1
    except DigitalLegacyError as exc:
        console.problem(exc)
        return 1
    except KeyboardInterrupt:
        console.warn("\nStopped.")
        return 130

    parser.print_help()
    return 2


# --------------------------------------------------------------------------
# Commands
# --------------------------------------------------------------------------


def cmd_encrypt(args, layout: Layout, console: Console) -> int:
    scripted = bool(args.file or args.shares or args.use_existing_keys)
    if not scripted:
        return EncryptWizard(layout, console).run()

    if not args.file:
        raise DigitalLegacyError("--file is required when encrypting from flags.")

    toolchain = Toolchain.discover(layout.binaries_dir)
    vault = Vault(layout.encrypted_dir)
    vault.ensure()

    keypairs = []
    if args.use_existing_keys:
        policy = vault.load_policy()
    else:
        total = args.shares or 3
        threshold = args.threshold if args.threshold is not None else min(2, total)
        names = list(args.names) or [f"Key{i + 1}" for i in range(total)]
        if len(names) != total:
            raise DigitalLegacyError(
                f"--shares is {total} but {len(names)} --name value(s) were given."
            )
        keypairs = [
            agekeys.generate(toolchain, label=agekeys.sanitise_label(n)) for n in names
        ]
        policy = Policy(
            threshold=threshold, shares=[k.public_key for k in keypairs]
        ).validate()

    profile = _handoff_profile(args, vault)
    result = operations.encrypt_and_verify(
        toolchain,
        args.file,
        vault,
        policy,
        keypairs,
        progress=lambda message: console.info(f"  {message}"),
        require_verification=not args.allow_unverified,
    )

    policy.save(vault.path / "recipients.yaml")
    vault.save_manifest(
        Manifest(
            owner=args.owner,
            threshold=policy.threshold,
            keyholders=[
                {
                    "label": k.label,
                    "public_key": k.public_key,
                    "fingerprint": k.fingerprint(),
                }
                for k in keypairs
            ],
            binaries=toolchain.fingerprints(),
            handoff=_saved(profile),
            entries=[result.entry],
        )
    )

    if keypairs:
        _write_shares_and_letters(
            layout,
            vault,
            policy,
            keypairs,
            result.entry.display_name,
            args.owner,
            result.entry.encrypted_at or now_iso(),
            profile,
        )

    console.ok(f"Encrypted to {result.path}")
    if result.verified:
        console.ok(f"Recovery proven: {result.verification_detail}")
    elif result.verification_detail:
        console.warn(result.verification_detail)
    if keypairs:
        console.info(f"Key files: {layout.keys_out_dir}")
        console.info(f"Letters:   {layout.handoff_dir}")
    return 0


def cmd_decrypt(args, layout: Layout, console: Console) -> int:
    if not args.keys:
        return DecryptWizard(layout, console, output_dir=args.output).run()

    toolchain = Toolchain.discover(layout.binaries_dir)
    vault = Vault(layout.encrypted_dir)
    policy = vault.load_policy()

    entry = _select_entry(vault, args.document)
    secrets = _collect_secrets(toolchain, policy, args.keys, console)

    output = operations.decrypt_entry(
        toolchain,
        vault,
        entry,
        secrets,
        args.output or operations.default_output_dir(),
        progress=lambda message: console.info(f"  {message}"),
    )
    console.ok(f"Decrypted to {output}")
    return 0


def _collect_secrets(toolchain, policy, paths, console) -> list[str]:
    """Validate key files against the policy and return their secrets."""
    secrets: list[str] = []
    seen: set[str] = set()
    for path in paths:
        parsed = agekeys.read_key_file(path)
        public_key = agekeys.derive_public_key(toolchain, parsed.secret_key)
        if public_key not in policy.shares:
            raise DigitalLegacyError(
                f"{Path(path).name} is not one of the keys for this document."
            )
        if public_key in seen:
            raise DigitalLegacyError(
                f"{Path(path).name} is a duplicate of a key already provided."
            )
        seen.add(public_key)
        secrets.append(parsed.secret_key)

    if len(secrets) < policy.threshold:
        given = len(secrets)
        raise DigitalLegacyError(
            f"{policy.threshold} keys are needed to open this document, but "
            f"{given} {'was' if given == 1 else 'were'} given.",
            hint="Add another --key for each missing keyholder.",
        )
    return secrets


def _write_shares_and_letters(
    layout: Layout,
    vault: Vault,
    policy: Policy,
    keypairs: list,
    document: str,
    owner: str,
    created: str,
    profile: dict | None = None,
) -> None:
    """Write the key files, the per-keyholder letters, and READ ME FIRST."""
    handoff.write_shares_and_letters(
        layout.keys_out_dir,
        layout.handoff_dir,
        vault.path,
        handoff.HandoffContext(
            owner=owner,
            document=document,
            policy=policy,
            keypairs=keypairs,
            created=created[:10],
            **(profile or {}),
        ),
    )


def _handoff_profile(args, vault: Vault) -> dict:
    """How keys are handed out: this run's flags over what the vault recorded.

    Inheriting from the existing ``vault.json`` is the point. An owner sets the
    key naming and wording once; a later re-encryption that silently went back
    to the defaults would hand their family files that no longer match the
    instructions they were given.
    """
    try:
        manifest = vault.load_manifest()
    except DigitalLegacyError:
        manifest = None
    profile = handoff.stored_profile(manifest) or {
        "key_prefix": "",
        "shared_folder": False,
        "key_notes": "",
    }

    if getattr(args, "key_prefix", None):
        profile["key_prefix"] = args.key_prefix
    if getattr(args, "shared_folder", None):
        profile["shared_folder"] = True
    notes_file = getattr(args, "key_notes", None)
    if notes_file:
        try:
            profile["key_notes"] = Path(notes_file).read_text(encoding="utf-8-sig")
        except OSError as exc:
            raise DigitalLegacyError(
                f"Could not read the key notes file: {notes_file}",
                hint="Check the path given to --key-notes.",
            ) from exc
    return profile


def _saved(profile: dict) -> dict:
    return handoff.HandoffContext(**profile).profile()


def _select_entry(vault: Vault, name: str | None):
    if not name:
        return vault.sole_entry()
    matches = [e for e in vault.entries() if e.ciphertext_name == name]
    if not matches:
        raise DigitalLegacyError(
            f"No encrypted document named {name!r} in {vault.path}."
        )
    return matches[0]


def cmd_reseal(args, layout: Layout, console: Console) -> int:
    """Re-encrypt an existing document for a new set of keyholders."""
    if not args.keys:
        raise DigitalLegacyError(
            "Resealing needs the current keys.",
            hint="Pass one --key for each of the keyholders taking part, at "
            "least as many as the current threshold.",
        )

    toolchain = Toolchain.discover(layout.binaries_dir)
    vault = Vault(layout.encrypted_dir)
    old_policy = vault.load_policy()
    profile = _handoff_profile(args, vault)
    entry = _select_entry(vault, args.document)
    secrets = _collect_secrets(toolchain, old_policy, args.keys, console)

    total = args.shares or old_policy.total_shares
    threshold = args.threshold if args.threshold is not None else old_policy.threshold
    names = list(args.names) or [f"Key{i + 1}" for i in range(total)]
    if len(names) != total:
        raise DigitalLegacyError(
            f"--shares is {total} but {len(names)} --name value(s) were given."
        )

    keypairs = [
        agekeys.generate(toolchain, label=agekeys.sanitise_label(n)) for n in names
    ]
    new_policy = Policy(
        threshold=threshold, shares=[k.public_key for k in keypairs]
    ).validate()

    result = operations.reseal_entry(
        toolchain,
        vault,
        entry,
        secrets,
        new_policy,
        keypairs,
        remove_old=not args.keep_old_file,
        progress=lambda message: console.info(f"  {message}"),
    )

    new_policy.save(vault.path / "recipients.yaml")
    vault.save_manifest(
        Manifest(
            owner=args.owner,
            threshold=new_policy.threshold,
            keyholders=[
                {
                    "label": k.label,
                    "public_key": k.public_key,
                    "fingerprint": k.fingerprint(),
                }
                for k in keypairs
            ],
            binaries=toolchain.fingerprints(),
            handoff=_saved(profile),
            entries=[result.encrypt.entry],
        )
    )
    _write_shares_and_letters(
        layout,
        vault,
        new_policy,
        keypairs,
        result.encrypt.entry.display_name,
        args.owner,
        result.encrypt.entry.encrypted_at or now_iso(),
        profile,
    )

    console.ok(f"Resealed as {result.encrypt.path.name}")
    if result.encrypt.verified:
        console.ok(f"Recovery proven: {result.encrypt.verification_detail}")
    if result.old_ciphertext_removed:
        console.info(f"Removed the previous file: {result.replaced}")
    if result.warning:
        console.warn(result.warning)
    console.blank()
    console.warn(
        "Every previously issued key is now useless. Hand out the new key "
        f"files in {layout.keys_out_dir} and tell the old keyholders their "
        "copy no longer works."
    )
    stale = operations.stale_key_files(layout.keys_out_dir, new_policy)
    if stale:
        console.blank()
        console.warn(
            "These key files are left over from the old arrangement and no "
            "longer open anything. Delete them so nobody hands one out:"
        )
        console.bullets([p.name for p in stale], "dark_yellow")
    return 0


def cmd_doctor(args, layout: Layout, console: Console) -> int:
    report = doctor.run_checks(layout, deep=args.deep)
    doctor.render(report, console)
    return report.exit_code


def cmd_check_key(args, layout: Layout, console: Console) -> int:
    belongs, message = doctor.check_key_file(layout, args.path)
    (console.ok if belongs else console.warn)(message)
    return 0 if belongs else 1


def cmd_inspect(args, layout: Layout, console: Console) -> int:
    from . import sss

    toolchain = Toolchain.discover(layout.binaries_dir)
    vault = Vault(layout.encrypted_dir)
    for entry in vault.entries():
        console.heading(entry.ciphertext_name)
        console.info(sss.inspect(toolchain, vault.entry_path(entry)))
    return 0


def cmd_handoff(args, layout: Layout, console: Console) -> int:
    """Rewrite the letters from what the vault already records.

    Only names and counts are recoverable this way -- private keys are long
    gone, and rightly so -- but the letters and READ ME FIRST are exactly the
    parts an owner is most likely to want to reprint years later.
    """
    vault = Vault(layout.encrypted_dir)
    policy = vault.load_policy()
    manifest = vault.load_manifest()

    keypairs = [
        agekeys.KeyPair(
            public_key=holder.get("public_key", ""),
            secret_key="",
            label=holder.get("label", ""),
        )
        for holder in (manifest.keyholders if manifest else [])
    ]
    if not keypairs:
        keypairs = [
            agekeys.KeyPair(public_key=key, secret_key="", label=f"Key {i + 1}")
            for i, key in enumerate(policy.shares)
        ]

    entries = vault.entries()
    context = handoff.HandoffContext(
        owner=manifest.owner if manifest else "",
        document=entries[0].display_name if entries else "",
        policy=policy,
        keypairs=keypairs,
        created=(manifest.created_at[:10] if manifest else ""),
        **handoff.stored_profile(manifest),
    )
    destination = args.output or layout.handoff_dir
    written = handoff.write_handoff_packet(destination, context)
    readme = handoff.vault_readme(context)
    (vault.path / "READ ME FIRST.txt").write_bytes(readme.encode("utf-8"))
    console.ok(f"Wrote {len(written)} file(s) to {destination}")
    return 0


if __name__ == "__main__":  # pragma: no cover
    sys.exit(main())
