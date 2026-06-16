"""The Textual front-end for `bastion tui`.

Isolated in its own module so importing it (and thus ``textual``) is what fails when the optional
runtime dep is missing — ``tui.run_tui`` catches that and prints a friendly hint. This file is the
thin VIEW: the dashboard data/format lives in :mod:`bastion.tui` and the command surface +
risk-gating lives in :mod:`bastion.actions`, both fully unit-tested without a terminal. Everything
here needs a live TTY + Textual, so it is excluded from coverage.
"""
from __future__ import annotations

import os  # pragma: no cover

from textual import work  # pragma: no cover
from textual.app import App, ComposeResult  # pragma: no cover
from textual.containers import Grid, VerticalScroll  # pragma: no cover
from textual.screen import ModalScreen  # pragma: no cover
from textual.widgets import (Button, Footer, Header, Input, Label, OptionList,  # pragma: no cover
                             Static)
from textual.widgets.option_list import Option  # pragma: no cover

from . import actions as actmod  # pragma: no cover
from .tui import gather_dashboard, render_dashboard  # pragma: no cover


class ParamScreen(ModalScreen):  # pragma: no cover
    """Collect one parameter value (with an optional choices hint). Returns the string, or None."""
    def __init__(self, action, param):
        super().__init__()
        self._action, self._param = action, param

    def compose(self) -> ComposeResult:
        hint = f" ({', '.join(self._param.choices)})" if self._param.choices else ""
        opt = "" if self._param.required else "  [dim]— optional, leave blank to skip[/dim]"
        with Grid(id="dialog"):
            yield Label(f"[b]{self._action.label}[/b]")
            yield Label(f"{self._param.label}{hint}{opt}")
            yield Input(placeholder=self._param.placeholder or self._param.name, id="value")
            yield Button("OK", variant="primary", id="ok")
            yield Button("Cancel", id="cancel")

    def on_button_pressed(self, event: Button.Pressed) -> None:
        if event.button.id == "cancel":
            self.dismiss(None)
        else:
            self.dismiss(self.query_one("#value", Input).value)

    def on_input_submitted(self, _event: Input.Submitted) -> None:
        self.dismiss(self.query_one("#value", Input).value)


class ConfirmScreen(ModalScreen):  # pragma: no cover
    """Confirmation gate. CAUTION = yes/no; DESTRUCTIVE = type the phrase to enable Proceed."""
    def __init__(self, action, phrase):
        super().__init__()
        self._action, self._phrase = action, phrase

    def compose(self) -> ComposeResult:
        with Grid(id="dialog"):
            yield Label(f"[b]{self._action.label}[/b]  [dim]({self._action.risk})[/dim]")
            if self._action.warn:
                yield Label(f"[yellow]⚠ {self._action.warn}[/yellow]")
            if self._action.needs_typed_confirm:
                yield Label(f"Type [b]{self._phrase.replace('[', chr(92) + '[')}[/b] to proceed:")
                yield Input(id="typed")
            yield Button("Proceed", variant="error", id="ok")
            yield Button("Cancel", variant="primary", id="cancel")

    def on_button_pressed(self, event: Button.Pressed) -> None:
        if event.button.id == "cancel":
            self.dismiss(False)
            return
        if self._action.needs_typed_confirm:
            if self.query_one("#typed", Input).value.strip() != self._phrase:
                self.app.notify("phrase did not match — cancelled", severity="error")
                self.dismiss(False)
                return
        self.dismiss(True)


class ResultScreen(ModalScreen):  # pragma: no cover
    """Show a command's combined output + return code."""
    BINDINGS = [("escape", "dismiss", "close"), ("enter", "dismiss", "close")]

    def __init__(self, action, result):
        super().__init__()
        self._action, self._result = action, result

    def compose(self) -> ComposeResult:
        tag = "[green]rc=0[/green]" if self._result.ok else f"[red]rc={self._result.returncode}[/red]"
        # captured command output is raw text — escape '[' so it isn't parsed as markup
        body = (self._result.output or "(no output)").replace("[", "\\[")
        with VerticalScroll(id="dialog"):
            yield Label(f"[b]{self._action.label}[/b]  {tag}")
            yield Static(body)
            yield Button("Close", variant="primary", id="ok")

    def on_button_pressed(self, _event: Button.Pressed) -> None:
        self.dismiss(None)

    def action_dismiss(self) -> None:
        self.dismiss(None)


class ActionsScreen(ModalScreen):  # pragma: no cover
    """Grouped palette of every action. Returns the chosen Action, or None."""
    BINDINGS = [("escape", "dismiss", "close")]

    def compose(self) -> ComposeResult:
        ol = OptionList(id="palette")
        for group, items in actmod.by_group().items():
            ol.add_option(Option(f"[b]{group}[/b]", disabled=True))
            for a in items:
                marks = {actmod.READ: "", actmod.CAUTION: " [yellow]•[/yellow]",
                         actmod.DESTRUCTIVE: " [red]‼[/red]"}
                ol.add_option(Option(f"  {a.label}{marks[a.risk]}", id=a.id))
        with VerticalScroll(id="dialog"):
            yield Label("[b]Commands[/b]  ([yellow]•[/yellow] confirm  [red]‼[/red] typed confirm)")
            yield ol

    def on_option_list_option_selected(self, event: OptionList.OptionSelected) -> None:
        self.dismiss(actmod.get(event.option.id) if event.option.id else None)

    def action_dismiss(self) -> None:
        self.dismiss(None)


class BastionTUI(App):  # pragma: no cover
    TITLE = "bastion"
    CSS = """
    Static#body { padding: 1 2; }
    #dialog { padding: 1 2; width: 90; max-height: 80%; background: $panel; border: tall $primary; }
    """
    BINDINGS = [
        ("r", "refresh", "refresh"),
        ("a", "actions", "commands"),
        ("q", "quit", "quit"),
    ]

    def __init__(self, ctx):
        super().__init__()
        self._ctx = ctx

    def compose(self) -> ComposeResult:
        yield Header()
        with VerticalScroll():
            yield Static(id="body")
        yield Footer()

    def on_mount(self) -> None:
        self._refresh()
        self.set_interval(5.0, self._refresh)

    def _refresh(self) -> None:
        self.query_one("#body", Static).update(render_dashboard(gather_dashboard(self._ctx)))

    def action_refresh(self) -> None:
        self._refresh()

    def action_actions(self) -> None:
        self._command_flow()

    @work
    async def _command_flow(self) -> None:
        action = await self.push_screen_wait(ActionsScreen())
        if action is None:
            return
        values: dict = {}
        for p in action.params:
            v = await self.push_screen_wait(ParamScreen(action, p))
            if v is None:                      # cancelled
                return
            values[p.name] = v
        if action.needs_confirm:
            ok = await self.push_screen_wait(ConfirmScreen(action, action.confirm_phrase(values)))
            if not ok:
                return
        if action.interactive:
            # the wizard needs the real terminal — drop out of the TUI, run it, come back
            with self.suspend():
                os.system(" ".join(actmod.resolve_entrypoint() + list(action.argv)))
            self._refresh()
            return
        try:
            result = actmod.run_action(self._ctx, action, values)
        except actmod.ActionError as exc:
            self.notify(str(exc), severity="error")
            return
        await self.push_screen_wait(ResultScreen(action, result))
        self._refresh()


def launch(ctx) -> int:  # pragma: no cover
    BastionTUI(ctx).run()
    return 0
