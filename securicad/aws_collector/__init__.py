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


def verify_python_version():
    import sys

    if sys.version_info < (3, 8):
        raise ValueError("You need python 3.8 or newer for this to work")


verify_python_version()

from .main import PARSER_VERSION as PARSER_VERSION
from .main import PARSER_VERSION_FIELD as PARSER_VERSION_FIELD
from .main import collect as collect
from .main import get_config_data as get_config_data

__version__ = "2.1.0rc3"
