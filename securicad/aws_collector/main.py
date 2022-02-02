# Copyright 2019-2022 Foreseeti AB <https://foreseeti.com>
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     https://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

from __future__ import annotations

import ast
import inspect
import json
import logging
import sys
import time
from pathlib import Path
from threading import Lock
from typing import Any, Callable, Optional

import botocore.client
import jsonschema
import typer
from jsonschema.exceptions import ValidationError

from securicad.aws_collector import account_collector, schemas, utils
from securicad.aws_collector.exceptions import (
    AwsCollectorError,
    AwsCollectorInputError,
    AwsCredentialsError,
)

PARSER_VERSION = 9
PARSER_VERSION_FIELD = "parser_version"

log = logging.getLogger("securicad-aws-collector")
app = typer.Typer()
_OLD_METHOD = None


def _patch_botocore(
    limit_per_second: Optional[float] = None, total_limit: Optional[int] = None
) -> None:
    def _api_call(self, *args, **kwargs):
        # pylint: disable=global-variable-undefined
        # pylint: disable=undefined-variable
        # pylint: disable=used-before-assignment
        # pylint: disable=protected-access
        global TOTAL_CALLS

        if args:
            raise TypeError(f"{py_operation_name}() only accepts keyword arguments.")  # type: ignore

        with LOCK:  # type: ignore
            if TOTAL_LIMIT:  # type: ignore
                if TOTAL_CALLS >= TOTAL_LIMIT:  # type: ignore
                    raise AwsRateLimitError("Maximum number of API calls exceeded")  # type: ignore
            TOTAL_CALLS += 1  # type: ignore
            if DELAY:  # type: ignore
                time.sleep(DELAY)  # type: ignore
                return self._make_api_call(operation_name, kwargs)  # type: ignore
        return self._make_api_call(operation_name, kwargs)  # type: ignore

    def _get_ast(obj: Callable) -> ast.Module:
        lines = inspect.getsource(obj).splitlines()
        indent = len(lines[0]) - len(lines[0].lstrip())
        return ast.parse("\n".join(line[indent:] for line in lines))

    # pylint: disable=global-statement
    global _OLD_METHOD
    if _OLD_METHOD is None:
        # pylint: disable=protected-access
        # pylint: disable=exec-used
        _OLD_METHOD = botocore.client.ClientCreator._create_api_method  # type: ignore
        outer_func_ast = _get_ast(botocore.client.ClientCreator._create_api_method)  # type: ignore
        inner_func_ast = _get_ast(_api_call)

        assert len(outer_func_ast.body) == 1
        assert isinstance(outer_func_ast.body[0], ast.FunctionDef)
        assert outer_func_ast.body[0].name == "_create_api_method"

        for i, node in enumerate(outer_func_ast.body[0].body):
            if isinstance(node, ast.FunctionDef) and node.name == "_api_call":
                outer_func_ast.body[0].body[i] = inner_func_ast.body[0]
                break
        else:
            raise RuntimeError("Inner function _api_call not found")

        lines = [
            "import time",
            "from botocore.docs.docstring import ClientMethodDocstring",
            "from securicad.aws_collector.exceptions import AwsRateLimitError",
        ]
        for line in reversed(lines):
            outer_func_ast.body[0].body.insert(0, ast.parse(line).body[0])

        _globals: dict[str, Any] = {
            "LOCK": Lock(),
            "DELAY": 1 / limit_per_second if limit_per_second else None,
            "TOTAL_CALLS": 0,
            "TOTAL_LIMIT": total_limit,
        }
        _locals: dict[str, Any] = {}
        exec(compile(outer_func_ast, "<string>", "exec"), _globals, _locals)
        botocore.client.ClientCreator._create_api_method = _locals["_create_api_method"]  # type: ignore


def _unpatch_botocore():
    # pylint: disable=global-statement
    global _OLD_METHOD
    if _OLD_METHOD is not None:
        # pylint: disable=protected-access
        botocore.client.ClientCreator._create_api_method = _OLD_METHOD  # type: ignore
        _OLD_METHOD = None


def collect(
    config: dict[str, Any],
    include_inspector: bool = False,
    include_guardduty: bool = False,
    threads: Optional[int] = None,
    limit_per_second: Optional[float] = None,
    total_limit: Optional[int] = None,
    account_done_callback: Optional[
        Callable[[dict[str, Any]], Any]
    ] = None,  # Callable[[args], return type]
) -> dict[str, Any]:
    try:
        jsonschema.validate(instance=config, schema=schemas.get_config_schema())
    except ValidationError as e:
        raise AwsCollectorInputError(f"Invalid config file: {e.message}") from e

    try:
        _patch_botocore(limit_per_second, total_limit)

        data: dict[str, Any] = {PARSER_VERSION_FIELD: PARSER_VERSION, "accounts": []}
        account_ids = set()
        for account in config["accounts"]:
            credentials = utils.get_credentials(account)
            if credentials is None:
                continue
            regions = utils.get_regions(account)
            if regions is None:
                continue
            account_data = account_collector.get_account_data(credentials, threads)
            if account_data is None:
                continue
            if "account_aliases" not in account_data:
                account_data["account_aliases"] = []
            if account_data["account_id"] in account_ids:
                log.warning(
                    f'Duplicate AWS Account "{account_data["account_id"]}", {account_data["account_aliases"]}'
                )
                continue
            log.info(
                f'Collecting AWS environment information of account "{account_data["account_id"]}", {account_data["account_aliases"]}'
            )
            account_collector.collect(
                credentials,
                regions,
                account_data,
                include_inspector,
                include_guardduty,
                threads,
            )
            data["accounts"].append(account_data)
            account_ids.add(account_data["account_id"])
            if account_done_callback:
                account_done_callback(account)
        if not data["accounts"]:
            raise AwsCredentialsError("No valid AWS credentials found")
        log.info("Finished collecting AWS environment information")

        # pylint: disable=protected-access
        _globals = botocore.client.ClientCreator._create_api_method.__globals__  # type: ignore
        if "TOTAL_CALLS" in _globals:
            log.info(f"Total number of API calls: {_globals['TOTAL_CALLS']}")
        else:
            log.warning("Failed to get total number of API calls")
    finally:
        _unpatch_botocore()

    try:
        jsonschema.validate(instance=data, schema=schemas.get_data_schema())
    except ValidationError as e:
        raise ValueError(f"Invalid output data: {e.message}") from e

    return json.loads(
        json.dumps(data, allow_nan=False, cls=utils.CustomJSONEncoder),
        parse_constant=utils.parse_constant,
    )


def init_logging(quiet: bool, verbose: bool) -> None:
    if verbose:
        log.setLevel(logging.DEBUG)
    elif quiet:
        log.setLevel(logging.WARNING)
    else:
        log.setLevel(logging.INFO)
    handler = logging.StreamHandler()
    handler.setLevel(log.getEffectiveLevel())
    formatter = logging.Formatter(
        fmt="{asctime} - {name} - {levelname} - {message}",
        datefmt="%Y-%m-%dT%H:%M:%SZ",
        style="{",
    )
    formatter.converter = time.gmtime  # type: ignore
    handler.setFormatter(formatter)
    log.addHandler(handler)


def get_config_data(
    profile: Optional[str] = None,
    access_key: Optional[str] = None,
    secret_key: Optional[str] = None,
    session_token: Optional[str] = None,
    role: Optional[str] = None,
    region: Optional[str] = None,
    config: Optional[Path] = None,
) -> dict[str, Any]:
    if config:
        return utils.read_json(config)
    account: dict[str, Any] = {}
    if profile:
        account["profile"] = profile
    elif access_key or secret_key:
        if not access_key or not secret_key or not region:
            raise AwsCollectorInputError(
                "When specifying access keys, AWS Access Key, AWS Secret Key, and AWS Region must be set"
            )
        account["access_key"] = access_key
        account["secret_key"] = secret_key
        if session_token:
            account["session_token"] = session_token
    if region:
        account["regions"] = [region]
    if role:
        account["role"] = role
    return {"accounts": [account]}


@app.command()
def main(
    profile: Optional[str] = typer.Option(
        None, "--profile", "-p", metavar="PROFILE", help="AWS Profile"
    ),
    access_key: Optional[str] = typer.Option(
        None, "--access-key", "-a", metavar="KEY", help="AWS Access Key"
    ),
    secret_key: Optional[str] = typer.Option(
        None, "--secret-key", "-s", metavar="KEY", help="AWS Secret Key"
    ),
    session_token: Optional[str] = typer.Option(
        None, "--session-token", "-S", metavar="TOKEN", help="AWS Session Token"
    ),
    role: Optional[str] = typer.Option(
        None, "--role", "-R", metavar="ARN", help="AWS Role"
    ),
    region: Optional[str] = typer.Option(
        None, "--region", "-r", metavar="REGION", help="AWS Region"
    ),
    config: Optional[Path] = typer.Option(
        None,
        "--config",
        "-c",
        help="Configuration File",
        exists=True,
        file_okay=True,
        dir_okay=False,
        writable=False,
        readable=True,
        allow_dash=True,
    ),
    inspector: bool = typer.Option(
        False, "--inspector", "-i", show_default=False, help="Include Amazon Inspector"
    ),
    guardduty: bool = typer.Option(
        False, "--guardduty", "-g", show_default=False, help="Include Amazon GuardDuty"
    ),
    threads: Optional[int] = typer.Option(
        None, "--threads", "-t", metavar="THREADS", help="Number of concurrent threads"
    ),
    limit_per_second: Optional[float] = typer.Option(
        None,
        "--limit-per-second",
        metavar="LIMIT",
        help="Maximum number of API calls per second",
    ),
    total_limit: Optional[int] = typer.Option(
        None, "--total-limit", metavar="LIMIT", help="Maximum number of API calls"
    ),
    output: Path = typer.Option(
        Path("aws.json"),
        "--output",
        "-o",
        help="Output JSON file",
        file_okay=True,
        dir_okay=False,
        writable=True,
        readable=False,
        allow_dash=True,
    ),
    quiet: bool = typer.Option(
        False,
        "--quiet",
        "-q",
        show_default=False,
        help="Only print warnings and errors",
    ),
    verbose: bool = typer.Option(
        False, "--verbose", "-v", show_default=False, help="Print debug information"
    ),
) -> None:
    """
    \b
    Collects AWS environment information from the AWS APIs, and stores the
    result in a JSON file.

    \b
    There are four ways to specify AWS credentials and region:
    1. Directly on the command-line
    2. With a profile specified on the command-line
    3. With a configuration file specified on the command-line
    4. From the environment

    \b
    For details about specifying AWS credentials and region, see
    https://github.com/foreseeti/securicad-aws-collector/blob/master/README.md
    """
    try:
        init_logging(quiet, verbose)
        config_data = get_config_data(
            profile, access_key, secret_key, session_token, role, region, config
        )
        output_data = collect(
            config=config_data,
            include_inspector=inspector,
            include_guardduty=guardduty,
            threads=threads,
            limit_per_second=limit_per_second,
            total_limit=total_limit,
        )
        utils.write_json(output_data, output)
        if str(output) != "-":
            log.info(f"Output written to {output}")
    except AwsCollectorError as e:
        sys.exit(f"Error: {e}")
