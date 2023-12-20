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
"""Create a new version of an existing rule.

API reference:
https://cloud.google.com/chronicle/docs/reference/detection-engine-api#createruleversion
"""

import os
from typing import Any, Mapping

from google.auth.transport import requests


def create_rule_version(
    http_session: requests.AuthorizedSession, rule_id: str, rule_content: str
) -> Mapping[str, Any]:
  """Creates a new rule version for a specific rule with the provided rule content.

  Args:
      http_session: Authorized session for HTTP requests.
      rule_id: Unique ID of the detection rule to create a new version for
        ("ru_<UUID>").
      rule_content: Content of the new detection rule.

  Returns:
      New version of the detection rule.

  Raises:
      requests.exceptions.HTTPError: HTTP request resulted in an error
      (response.status_code >= 400).
  """
  url = f"{os.environ['CHRONICLE_API_BASE_URL']}/v2/detect/rules/{rule_id}:createVersion"
  body = {"ruleText": rule_content}

  response = http_session.request(method="POST", url=url, json=body)

  if response.status_code >= 400:
    print(response.text)
  response.raise_for_status()

  return response.json()
