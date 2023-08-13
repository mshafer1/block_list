"""IP address manipulation tools."""
import pathlib
import typing

import click

import ip_calc


@click.command()
@click.option("--print-graph", help="Print binary search tree using DOT syntax (user can utilize graphviz to render as image)", is_flag=True)
@click.option(
    "--output", metavar="FILE", default="output.json", type=click.Path(path_type=pathlib.Path)
)
@click.option("--pretty", is_flag=True, help="pretty-print the output file (else, minify)")
@click.argument("files", metavar="FILE", nargs=-1, type=click.Path(path_type=pathlib.Path))
def _main(files: typing.List[pathlib.Path], print_graph: bool, output: pathlib.Path, pretty: bool):
    ip_calc.merge_and_simplify(files, print_graph, output=output, pretty=pretty)


if __name__ == "__main__":
    _main()
