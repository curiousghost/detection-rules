# Copyright 2023 Google LLC
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
#
"""List the latest versions of all rules.

API reference:
https://cloud.google.com/chronicle/docs/reference/detection-engine-api#listrules
"""

import os
from typing import Any, Mapping, Sequence, Tuple

from google.auth.transport import requests


def list_rules(
    http_session: requests.AuthorizedSession,
    page_size: int | None = None,
    page_token: str | None = None,
    state: str | None = None,
) -> Tuple[Sequence[Mapping[str, Any]], str]:
  """List detection rules.

  Args:
      http_session: Authorized session for HTTP requests.
      page_size: Maximum number of rules to return. Must be non-negative, and is
        capped at a server-side limit of 1000. Optional - a server-side default
        of 100 is used if the size is 0 or a None value.
    page_token: Page token from a previous ListRules call used for pagination.
      Optional - the first page is retrieved if the token is the empty string or
      a None value.
    state: The state to filter rules by (ACTIVE, ARCHIVED or ALL). Optional - if
      unspecified, only rules with ACTIVE state are returned.

  Returns:
      List of rules and a page token for the next page of rules, if there are
      any.

  Raises:
      requests.exceptions.HTTPError: HTTP request resulted in an error
      (response.status_code >= 400).
  """
  url = f"{os.environ['CHRONICLE_API_BASE_URL']}/v2/detect/rules"
  params = {"page_size": page_size, "page_token": page_token, "state": state}

  response = http_session.request(method="GET", url=url, params=params)

  if response.status_code >= 400:
    print(response.text)
    response.raise_for_status()

  response_json = response.json()

  return response_json.get("rules"), response_json.get("nextPageToken")
