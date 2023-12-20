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
"""Verify that a rule is a valid YARA-L 2.0 rule without creating a new rule or evaluating it over data.

API reference:
https://cloud.google.com/chronicle/docs/reference/detection-engine-api#verifyrule
"""

import os
from typing import Any, Mapping

from google.auth.transport import requests


def verify_rule(
    http_session: requests.AuthorizedSession, rule_content: str
) -> Mapping[str, Any]:
  """Verifies that a rule is a valid YARA-L 2.0 rule without creating a new rule or evaluating it over data.

  Args:
      http_session: Authorized session for HTTP requests.
      rule_content: Content of the detection rule.

  Returns:
    A compilation error if there is one.

  Raises:
      requests.exceptions.HTTPError: HTTP request resulted in an error
      (response.status_code >= 400).
  """
  url = f"{os.environ['CHRONICLE_API_BASE_URL']}/v2/detect/rules:verifyRule"
  body = {"ruleText": rule_content}

  response = http_session.request(method="POST", url=url, json=body)

  if response.status_code >= 400:
    print(response.text)
  response.raise_for_status()

  return response.json()
