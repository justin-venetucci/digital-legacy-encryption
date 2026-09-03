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
            entries=[result.entry],
        )
    )

    if keypairs:
        for keypair in keypairs:
            agekeys.write_key_file(
                layout.keys_out_dir / agekeys.key_file_name(keypair.label),
                agekeys.render_key_file(
                    keypair,
                    threshold=policy.threshold,
                    total_shares=policy.total_shares,
                    owner=args.owner,
                    document=result.entry.display_name,
                ),
            )
        context = handoff.HandoffContext(
            owner=args.owner,
            document=result.entry.display_name,
            policy=policy,
            keypairs=keypairs,
            created=(result.entry.encrypted_at or now_iso())[:10],
        )
        handoff.write_handoff_packet(layout.handoff_dir, context)
        (vault.path / "READ ME FIRST.txt").write_text(
            handoff.vault_readme(context), encoding="utf-8", newline="\n"
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

    entries = vault.entries()
    if args.document:
        matches = [e for e in entries if e.ciphertext_name == args.document]
        if not matches:
            raise DigitalLegacyError(
                f"No encrypted document named {args.document!r} in {vault.path}."
            )
        entry = matches[0]
    else:
        entry = vault.sole_entry()

    secrets: list[str] = []
    seen: set[str] = set()
    for path in args.keys:
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
    )
    destination = args.output or layout.handoff_dir
    written = handoff.write_handoff_packet(destination, context)
    (vault.path / "READ ME FIRST.txt").write_text(
        handoff.vault_readme(context), encoding="utf-8", newline="\n"
    )
    console.ok(f"Wrote {len(written)} file(s) to {destination}")
    return 0


if __name__ == "__main__":  # pragma: no cover
    sys.exit(main())
