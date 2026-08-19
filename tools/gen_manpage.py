#!/usr/bin/env python3
"""Generate man/bastion.1 from the live argparse parser.

Single source of truth: the man page is DERIVED from `bastion.cli.build_parser()`,
so every subcommand, flag, and help string in `man bastion` is exactly what the CLI
accepts — no hand-maintained roff to drift out of sync. Regenerate on any release
that changes the CLI (part of the docs-sweep):

    make man                       # writes man/bastion.1
    python tools/gen_manpage.py    # same, from the repo root

The date field is left blank on purpose: the page's identity is the version, and a
blank date keeps regeneration byte-stable regardless of the day it runs.
"""
from __future__ import annotations

import argparse
import sys
from pathlib import Path

# Import the real parser + version from the package.
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
from bastion import __version__  # noqa: E402
from bastion.cli import build_parser  # noqa: E402


# Unicode punctuation that appears in CLI help strings -> portable roff glyphs,
# so `man`/groff render it correctly instead of mojibake under an ascii locale.
_UNICODE_ROFF = {
    "—": "\\(em",  # — em dash
    "–": "\\(en",  # – en dash
    "→": "->",     # → right arrow
    "≥": ">=",     # ≥
    "≤": "<=",     # ≤
    "‘": "`", "’": "'",   # ‘ ’ curly single quotes
    "“": '"', "”": '"',   # “ ” curly double quotes
    " ": " ",      # non-breaking space
}


def roff(text: str) -> str:
    """Escape a string for roff body text."""
    if text is None:
        return ""
    # Escape roff metacharacters FIRST (backslash, then hyphen -> explicit minus),
    # THEN substitute Unicode punctuation with roff glyphs that carry their own
    # (intentionally un-escaped) backslashes.
    out = text.replace("\\", "\\\\").replace("-", "\\-")
    for uni, repl in _UNICODE_ROFF.items():
        out = out.replace(uni, repl)
    # A line that starts with '.' or "'" is a roff control line; neutralise it.
    if out[:1] in (".", "'"):
        out = "\\&" + out
    return out


def _subparsers_action(parser: argparse.ArgumentParser):
    for action in parser._actions:  # noqa: SLF001 — argparse has no public accessor
        if isinstance(action, argparse._SubParsersAction):  # noqa: SLF001
            return action
    return None


def _option_label(action: argparse.Action) -> str:
    """The bold header for one argument (positional or optional)."""
    if action.option_strings:
        parts = []
        for opt in action.option_strings:
            if action.nargs == 0 or isinstance(action, argparse._StoreTrueAction):  # noqa: SLF001
                parts.append(opt)
            else:
                metavar = action.metavar or action.dest.upper()
                parts.append(f"{opt} {metavar}")
        return ", ".join(parts)
    # Positional.
    if action.choices:
        return "{" + " | ".join(str(c) for c in action.choices) + "}"
    return action.metavar or action.dest


def _emit_arguments(parser: argparse.ArgumentParser, out: list[str]) -> None:
    """Emit a .TP list of a parser's own positionals + optionals (skip -h)."""
    rows = []
    for action in parser._actions:  # noqa: SLF001
        if isinstance(action, (argparse._HelpAction, argparse._SubParsersAction)):  # noqa: SLF001
            continue
        help_text = action.help or ""
        rows.append((_option_label(action), help_text))
    if not rows:
        return
    for label, help_text in rows:
        out.append(".TP")
        out.append(f"\\fB{roff(label)}\\fR")
        out.append(roff(help_text) if help_text else "\\&")


def _command_synopsis(name: str, parser: argparse.ArgumentParser) -> str:
    """A compact one-line synopsis for a subcommand."""
    bits = [f"\\fBbastion {name}\\fR"]
    sub = _subparsers_action(parser)
    if sub is not None:
        bits.append("{" + " | ".join(sub.choices.keys()) + "}")
    for action in parser._actions:  # noqa: SLF001
        if isinstance(action, (argparse._HelpAction, argparse._SubParsersAction)):  # noqa: SLF001
            continue
        if action.option_strings:
            continue  # options collapsed into [options]
        bits.append(f"\\fI{roff(_option_label(action))}\\fR")
    bits.append("[options]")
    return " ".join(bits)


def generate() -> str:
    parser = build_parser()
    top_sub = _subparsers_action(parser)
    out: list[str] = []

    # --- header ---
    out.append(f'.TH BASTION 1 "" "bastion {__version__}" "Bastion Manual"')
    out.append(".SH NAME")
    out.append("bastion \\- modular, layered Linux firewall framework")
    out.append(".SH SYNOPSIS")
    out.append(".B bastion")
    out.append("[\\fB\\-\\-version\\fR] \\fICOMMAND\\fR [\\fIarguments\\fR]")
    out.append(".SH DESCRIPTION")
    out.append(
        "Bastion is a modular, layered Linux firewall framework built on nftables. It provides "
        "an operator CLI, an optional AI analysis layer, and a guided setup wizard, and secures "
        "the full spectrum of hosts \\(em a defense\\-in\\-depth endpoint, a routing edge "
        "firewall, or a server that already runs another firewall manager (libvirt, Docker)."
    )
    out.append(".PP")
    out.append(
        "Configuration lives in \\fI/etc/bastion/machine.conf\\fR; \\fBbastion generate\\fR renders "
        "it into the live config files. See \\fBbastion \\fICOMMAND\\fB \\-\\-help\\fR for the exact "
        "flags of any command."
    )

    # --- commands ---
    out.append(".SH COMMANDS")
    # Help strings for each top command come from the subparsers' pseudo-actions.
    help_by_name = {}
    for pseudo in top_sub._choices_actions:  # noqa: SLF001
        help_by_name[pseudo.dest] = pseudo.help or ""

    for name, subparser in top_sub.choices.items():
        out.append(".SS " + name)
        summary = help_by_name.get(name, "")
        if summary:
            out.append(roff(summary))
            out.append(".PP")
        out.append(_command_synopsis(name, subparser))

        nested = _subparsers_action(subparser)
        if nested is not None:
            # Command with sub-subcommands (e.g. `config`): describe each.
            nested_help = {p.dest: (p.help or "") for p in nested._choices_actions}  # noqa: SLF001
            for sub_name, sub_sp in nested.choices.items():
                out.append(".TP")
                out.append(f"\\fBbastion {name} {roff(sub_name)}\\fR")
                out.append(roff(nested_help.get(sub_name, "")) or "\\&")
                # Sub-subcommand arguments, indented one more level.
                inner: list[str] = []
                _emit_arguments(sub_sp, inner)
                if inner:
                    out.append(".RS")
                    out.extend(inner)
                    out.append(".RE")
        else:
            _emit_arguments(subparser, out)

    # --- common options / files / see also ---
    out.append(".SH COMMON OPTIONS")
    out.append(
        "Most commands accept \\fB\\-\\-root \\fIDIR\\fR (operate under a staged tree instead of "
        "\\fI/\\fR, touching no live kernel or systemd state) and \\fB\\-\\-conf \\fIPATH\\fR "
        "(use a specific machine.conf). Read\\-only inspection commands accept \\fB\\-\\-json\\fR."
    )
    out.append(".SH FILES")
    out.append(".TP")
    out.append("\\fI/etc/bastion/machine.conf\\fR")
    out.append("Per\\-machine configuration (topology, zones, layer selection). Never contains secrets.")
    out.append(".TP")
    out.append("\\fI/etc/bastion/machine.env\\fR")
    out.append("Flat variables rendered from machine.conf, read by the operational scripts.")
    out.append(".TP")
    out.append("\\fI/etc/nftables.conf\\fR")
    out.append("The rendered ruleset. Fully rewritten by \\fBbastion generate\\fR \\(em do not hand\\-edit; put rules in \\fB[zones]\\fR.")
    out.append(".SH SEE ALSO")
    out.append("Project documentation at \\fIhttps://github.com/indyfive11/bastion\\fR, including "
               "the getting\\-started guide, command reference, and troubleshooting docs.")
    out.append(".SH AUTHOR")
    out.append("The Bastion project.")
    return "\n".join(out) + "\n"


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description="Generate the bastion(1) man page from the CLI parser.")
    ap.add_argument("-o", "--output", default="man/bastion.1",
                    help="output path (default: man/bastion.1; '-' for stdout)")
    args = ap.parse_args(argv)
    text = generate()
    if args.output == "-":
        sys.stdout.write(text)
    else:
        dest = Path(args.output)
        dest.parent.mkdir(parents=True, exist_ok=True)
        dest.write_text(text, encoding="utf-8")
        print(f"wrote {dest} ({len(text)} bytes, bastion {__version__})")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
