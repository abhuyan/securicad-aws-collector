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

import base64
import concurrent.futures
import json
import logging
import sys
from datetime import datetime
from pathlib import Path
from threading import Lock
from typing import TYPE_CHECKING, Any, Callable, Optional

from boto3.session import Session
from botocore.client import BaseClient
from botocore.config import Config
from botocore.exceptions import ClientError, ProfileNotFound

from securicad.aws_collector.exceptions import (
    AwsCollectorInputError,
    AwsCollectorIOError,
)

if TYPE_CHECKING:
    from typing_extensions import Protocol

    class ClientCallable(Protocol):
        def __call__(self, service_name: str) -> BaseClient:
            ...

    class UnpaginatedCallable(Protocol):
        def __call__(
            self,
            service_name: str,
            operation_name: str,
            param: Optional[dict[str, Any]] = None,
        ) -> dict[str, Any]:
            ...

    class PaginateCallable(Protocol):
        def __call__(
            self,
            service_name: str,
            operation_name: str,
            key: Optional[str | list[str]] = None,
            param: Optional[dict[str, Any]] = None,
        ) -> list[Any]:
            ...

    class FakePaginateCallable(Protocol):
        def __call__(
            self,
            service_name: str,
            operation_name: str,
            request_key: str,
            response_key: str,
            n: int,
            items: list[Any],
            param: Optional[dict[str, Any]] = None,
        ) -> list[Any]:
            ...


CLIENT_CONFIG = Config(retries={"max_attempts": 10, "mode": "standard"})

log = logging.getLogger("securicad-aws-collector")


def get_session(account: dict[str, Any]) -> Session:
    try:
        if "access_key" in account and "secret_key" in account:
            return Session(
                aws_access_key_id=account["access_key"],
                aws_secret_access_key=account["secret_key"],
                aws_session_token=account.get("session_token"),
            )
        return Session(profile_name=account.get("profile"))
    except ProfileNotFound as e:
        raise AwsCollectorInputError(str(e)) from e


def get_regions(account: dict[str, Any]) -> Optional[list[str]]:
    if "regions" in account:
        return account["regions"]
    try:
        session = get_session(account)
        if session.region_name:
            return [session.region_name]
        log.warning(f"AWS Profile {session.profile_name} has no default region")
    except AwsCollectorInputError as e:
        log.warning(str(e))
    return None


def get_credentials(account: dict[str, Any]) -> Optional[dict[str, str]]:
    try:
        session = get_session(account)
    except AwsCollectorInputError as e:
        log.warning(str(e))
        return None
    session_credentials = session.get_credentials()
    if not session_credentials:
        log.warning("No AWS credentials found")
        return None
    credentials = {
        "aws_access_key_id": session_credentials.access_key,
        "aws_secret_access_key": session_credentials.secret_key,
        "aws_session_token": session_credentials.token,
    }

    if "role" in account:
        client = session.client("sts", endpoint_url=account.get("endpoint_url"))
        try:
            role = client.assume_role(
                RoleArn=account["role"], RoleSessionName="securicad"
            )
        except ClientError as e:
            code = e.response.get("Error", {}).get("Code")
            message = e.response.get("Error", {}).get("Message")
            if code in {
                "InvalidClientTokenId",
                "SignatureDoesNotMatch",
                "AccessDenied",
            }:
                log.warning(message)
                return None
            raise
        credentials["aws_access_key_id"] = role["Credentials"]["AccessKeyId"]
        credentials["aws_secret_access_key"] = role["Credentials"]["SecretAccessKey"]
        credentials["aws_session_token"] = role["Credentials"]["SessionToken"]
    return credentials


def is_valid_region(session: Session, region: str) -> bool:
    return region in set(session.get_available_regions("ec2"))


def get_client(
    session: Session, client_lock: Lock, client_cache: dict[str, BaseClient]
) -> ClientCallable:
    def client(service_name: str) -> BaseClient:
        with client_lock:
            if service_name not in client_cache:
                client_cache[service_name] = session.client(service_name, config=CLIENT_CONFIG)  # type: ignore
            return client_cache[service_name]

    return client


def get_unpaginated(
    session: Session, client_lock: Lock, client_cache: dict[str, BaseClient]
) -> UnpaginatedCallable:
    _client = get_client(session, client_lock, client_cache)

    def unpaginated(
        service_name: str, operation_name: str, param: Optional[dict[str, Any]] = None
    ) -> dict[str, Any]:
        if param is None:
            param = {}
        client = _client(service_name)
        operation = getattr(client, operation_name)
        result = operation(**param)
        if "ResponseMetadata" in result:
            del result["ResponseMetadata"]
        return result

    return unpaginated


def get_paginate(
    session: Session, client_lock: Lock, client_cache: dict[str, BaseClient]
) -> PaginateCallable:
    _client = get_client(session, client_lock, client_cache)

    def paginate(
        service_name: str,
        operation_name: str,
        key: Optional[str | list[str]] = None,
        param: Optional[dict[str, Any]] = None,
    ) -> list[Any]:
        if param is None:
            param = {}
        client = _client(service_name)
        paginator = client.get_paginator(operation_name)
        page_iterator = paginator.paginate(**param)
        result = []
        for page in page_iterator:
            if key:
                if isinstance(key, list):
                    _page = page
                    for k in key:
                        _page = _page.get(k, None)
                        if _page is None:
                            break
                    if _page:
                        result.extend(_page)
                elif isinstance(key, str):
                    result.extend(page[key])
            else:
                result.append(page)
        return result

    return paginate


def get_fake_paginate(
    session: Session, client_lock: Lock, client_cache: dict[str, BaseClient]
) -> FakePaginateCallable:
    _unpaginated = get_unpaginated(session, client_lock, client_cache)

    def fake_paginate(
        service_name: str,
        operation_name: str,
        request_key: str,
        response_key: str,
        n: int,
        items: list[Any],
        param: Optional[dict[str, Any]] = None,
    ) -> list[Any]:
        if param is None:
            param = {}
        head = None
        tail = items
        result = []
        while len(tail) > 0:
            head = tail[:n]
            tail = tail[n:]
            param[request_key] = head
            result.extend(
                _unpaginated(service_name, operation_name, param)[response_key]
            )
        return result

    return fake_paginate


def execute_tasks(
    tasks: list[Callable[[], tuple[list[str], Any]]], threads: Optional[int]
) -> Optional[dict[str, Any]]:
    output: dict[str, Any] = {}
    threads = len(tasks) if threads is None else threads
    with concurrent.futures.ThreadPoolExecutor(max_workers=threads) as executor:
        future_to_name = {executor.submit(task): task.__name__ for task in tasks}
        for future in concurrent.futures.as_completed(future_to_name):
            try:
                names, result = future.result()

                if names:
                    obj = output
                    for name in names[:-1]:
                        if name not in obj:
                            obj[name] = {}
                        obj = obj[name]
                    obj[names[-1]] = result
            except ClientError as e:
                name = future_to_name[future]
                code = e.response.get("Error", {}).get("Code")
                message = e.response.get("Error", {}).get("Message")
                if code in {"InvalidClientTokenId", "SignatureDoesNotMatch"}:
                    log.warning(message)
                    return None
                if code in {
                    "AccessDenied",
                    "UnauthorizedOperation",
                    "AccessDeniedException",
                }:
                    log.warning(f"{name}: {message}")
                    continue
                raise
    return output


class CustomJSONEncoder(json.JSONEncoder):
    def default(self, o):
        if isinstance(o, datetime):
            # TODO: Change to o.isoformat()
            return str(o)
        if isinstance(o, bytes):
            return base64.b64encode(o).decode()
        return super().default(o)


def parse_constant(string: str) -> None:
    raise ValueError(f'Invalid JSON constant "{string}"')


def read_json(path: Path) -> Any:
    try:
        if str(path) == "-":
            return json.load(sys.stdin, parse_constant=parse_constant)
        with path.open(mode="r", encoding="utf-8") as f:
            return json.load(f, parse_constant=parse_constant)
    except OSError as e:
        raise AwsCollectorIOError(str(e)) from e


def write_json(data: Any, path: Path) -> None:
    try:
        if str(path) == "-":
            json.dump(data, sys.stdout, allow_nan=False, indent=2)
            return
        with path.open(mode="w", encoding="utf-8") as f:
            json.dump(data, f, allow_nan=False, indent=2)
    except OSError as e:
        raise AwsCollectorIOError(str(e)) from e
