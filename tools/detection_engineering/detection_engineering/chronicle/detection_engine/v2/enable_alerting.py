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
"""Enable alerting for a detection rule.

API reference:
https://cloud.google.com/chronicle/docs/reference/detection-engine-api#enablealerting
"""

import os

from google.auth.transport import requests


def enable_alerting(
    http_session: requests.AuthorizedSession, rule_id: str
):
  """Enable alerting for a specific detection rule.

  Args:
      http_session: Authorized session for HTTP requests.
      rule_id: Unique ID of the detection rule to enable alerting for
        ("ru_<UUID>"). It does not accept version id format
        ("ru_<UUID>@v_<seconds>_<nanoseconds>").

  Raises:
      requests.exceptions.HTTPError: HTTP request resulted in an error
      (response.status_code >= 400).
  """
  url = f"{os.environ['CHRONICLE_API_BASE_URL']}/v2/detect/rules/{rule_id}:enableAlerting"

  response = http_session.request("POST", url)

  if response.status_code >= 400:
    print(response.text)
  response.raise_for_status()

