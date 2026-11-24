import os
import typer
from rich.console import Console
from rich.table import Table
from rich.panel import Panel
from rich.syntax import Syntax
from patchforge.scanner import CodeScanner
from patchforge.patcher import PatchAgent
from patchforge.validator import SandboxValidator

app = typer.Typer(
    name="patchforge",
    help="PatchForge: Autonomous Security Patching & Code Refactoring Agent",
    add_completion=False
)
console = Console()

@app.command()
def scan(
    path: str = typer.Argument(".", help="Directory or file to scan for vulnerabilities")
):
    """Scan a codebase and display detected security vulnerabilities."""
    scanner = CodeScanner()
    if os.path.isfile(path):
        issues = scanner.scan_file(path)
    else:
        issues = scanner.scan_directory(path)

    console.rule("[bold cyan]PatchForge Security Scan[/bold cyan]")
    if not issues:
        console.print("[green]✓ No vulnerabilities detected![/green]")
        return

    table = Table(title=f"Detected Issues ({len(issues)})", show_header=True, header_style="bold magenta")
    table.add_column("Issue ID", style="bold")
    table.add_column("Type")
    table.add_column("Severity")
    table.add_column("Location")
    table.add_column("Description")

    for i in issues:
        sev_color = "red" if i.severity in ("critical", "high") else "yellow"
        table.add_row(
            i.id,
            i.vuln_type.value,
            f"[{sev_color}]{i.severity.value.upper()}[/{sev_color}]",
            f"{os.path.basename(i.file_path)}:{i.line_number}",
            i.description
        )

    console.print(table)

@app.command()
def fix(
    target_file: str = typer.Argument(..., help="Path to vulnerable python file"),
    apply: bool = typer.Option(False, "--apply", "-a", help="Apply the patch directly to the file"),
    output_diff: str = typer.Option(None, "--diff-out", "-d", help="Save unified git diff patch to file")
):
    """Scan file, generate AST security patches, validate in sandbox, and output diff."""
    if not os.path.exists(target_file):
        console.print(f"[red]Error: File '{target_file}' does not exist.[/red]")
        raise typer.Exit(code=1)

    scanner = CodeScanner()
    patcher = PatchAgent()
    validator = SandboxValidator()

    issues = scanner.scan_file(target_file)
    if not issues:
        console.print("[green]No vulnerabilities found to patch.[/green]")
        return

    with open(target_file, "r", encoding="utf-8") as f:
        current_code = f.read()

    console.print(f"[bold cyan]Found {len(issues)} issue(s) in {target_file}. Generating patches...[/bold cyan]\n")

    combined_diffs = []
    working_code = current_code

    for issue in issues:
        patch = patcher.generate_patch(issue, working_code)
        validation = validator.validate_patch(patch)

        console.print(Panel(
            f"[bold]Issue:[/bold] {issue.description}\n"
            f"[bold]Remediation:[/bold] {patch.explanation}\n"
            f"[bold]Validation Status:[/bold] {'[green]PASSED (Syntax & Safety)[/green]' if validation.security_check_passed else '[red]FAILED[/red]'}",
            title=f"Patch for {issue.id}",
            border_style="green" if validation.security_check_passed else "red"
        ))

        if patch.diff:
            console.print(Syntax(patch.diff, "diff", theme="monokai", line_numbers=False))
            combined_diffs.append(patch.diff)

        if validation.security_check_passed:
            working_code = patch.patched_code

    if output_diff and combined_diffs:
        with open(output_diff, "w", encoding="utf-8") as df:
            df.write("\n".join(combined_diffs))
        console.print(f"[green]Unified diff saved to {output_diff}[/green]")

    if apply:
        with open(target_file, "w", encoding="utf-8") as f:
            f.write(working_code)
        console.print(f"[bold green]✓ Successfully applied validated security patch to {target_file}![/bold green]")

if __name__ == "__main__":
    app()
