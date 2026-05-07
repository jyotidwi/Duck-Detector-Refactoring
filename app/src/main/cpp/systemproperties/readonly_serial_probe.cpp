/*
 * Copyright 2026 Duck Apps Contributor
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#include "systemproperties/readonly_serial_probe.h"

#include <sys/system_properties.h>

#include <set>
#include <string>
#include <string_view>
#include <vector>

namespace systemproperties {
    namespace {

        constexpr std::string_view kReadOnlyPrefix = "ro.";
        constexpr std::string_view kAppCompatOverridePrefix = "ro.appcompat_override.";

        bool is_readonly_property(const std::string &property) {
            return property.starts_with(kReadOnlyPrefix) &&
                   !property.starts_with(kAppCompatOverridePrefix);
        }

    }  // namespace

    ReadOnlyPropertySerialSnapshot
    scan_readonly_property_serials(const std::vector<std::string> &properties) {
        ReadOnlyPropertySerialSnapshot snapshot;

        std::set<std::string> candidates;
        for (const std::string &property: properties) {
            if (is_readonly_property(property)) {
                candidates.insert(property);
            }
        }

        for (const std::string &property: candidates) {
            const prop_info *info = __system_property_find(property.c_str());
            if (info == nullptr) {
                continue;
            }

            snapshot.available = true;
            ++snapshot.checked_count;
        }

        // __system_property_serial() is an opaque change token in the public API.
        // Its storage currently also carries value length and bionic-private flags,
        // so low-bit patterns are not scored as tamper evidence.
        snapshot.finding_count = 0;
        return snapshot;
    }

}  // namespace systemproperties
