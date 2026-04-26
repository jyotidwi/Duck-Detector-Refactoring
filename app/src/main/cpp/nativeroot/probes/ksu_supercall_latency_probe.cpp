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

#include "nativeroot/probes/ksu_supercall_latency_probe.h"

#include <csignal>
#include <cstdio>
#include <cstring>
#include <string>

#include <fcntl.h>
#include <sys/syscall.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>

namespace duckdetector::nativeroot {
    namespace {

        constexpr int kIterations = 100;
        constexpr int kSupercallNr = 45;
        constexpr unsigned long kSupercallHello = 0x1000;

        double get_us(struct timespec start, struct timespec end) {
            return (end.tv_sec - start.tv_sec) * 1000000.0 + (end.tv_nsec - start.tv_nsec) / 1000.0;
        }

        double measure_latency(const char *buffer) {
            struct timespec start, end;
            double total_us = 0;

            // Warmup
            syscall(kSupercallNr, buffer, kSupercallHello);

            for (int i = 0; i < kIterations; i++) {
                clock_gettime(CLOCK_MONOTONIC, &start);
                syscall(kSupercallNr, buffer, kSupercallHello);
                clock_gettime(CLOCK_MONOTONIC, &end);
                total_us += get_us(start, end);
            }

            return total_us / kIterations;
        }

        struct LatencyResult {
            double full_latency;
            double empty_latency;
            bool success;
        };

        bool run_benchmark_in_child(LatencyResult &out_result, bool &blocked_by_seccomp) {
            int pipe_fds[2] = {-1, -1};
            if (pipe(pipe_fds) != 0) {
                return false;
            }

            fcntl(pipe_fds[0], F_SETFD, FD_CLOEXEC);
            fcntl(pipe_fds[1], F_SETFD, FD_CLOEXEC);

            const pid_t pid = fork();
            if (pid < 0) {
                close(pipe_fds[0]);
                close(pipe_fds[1]);
                return false;
            }

            if (pid == 0) {
                close(pipe_fds[0]);

                char buffer[128];
                memset(buffer, 'A', 127);
                buffer[127] = '\0';

                LatencyResult result{};
                result.full_latency = measure_latency(buffer);

                memset(buffer, 0, sizeof(buffer));
                result.empty_latency = measure_latency(buffer);
                result.success = true;

                const ssize_t ignored = write(pipe_fds[1], &result, sizeof(result));
                (void) ignored;
                close(pipe_fds[1]);
                _exit(0);
            }

            close(pipe_fds[1]);

            int status = 0;
            if (waitpid(pid, &status, 0) < 0) {
                close(pipe_fds[0]);
                return false;
            }

            const ssize_t bytes_read = read(pipe_fds[0], &out_result, sizeof(out_result));
            close(pipe_fds[0]);

            if (WIFSIGNALED(status) && WTERMSIG(status) == SIGSYS) {
                blocked_by_seccomp = true;
                return false;
            }

            return WIFEXITED(status) && WEXITSTATUS(status) == 0 &&
                   bytes_read == static_cast<ssize_t>(sizeof(out_result));
        }

    }  // namespace

    ProbeResult run_ksu_supercall_latency_probe() {
        ProbeResult result;
        bool blocked = false;
        LatencyResult latencies = {0.0, 0.0, false};

        if (!run_benchmark_in_child(latencies, blocked)) {
            if (blocked) {
                result.checked_count = 1;
                result.denied_count = 1;
            }
            return result;
        }

        result.checked_count = 1;
        if (!latencies.success) {
            return result;
        }

        if (latencies.full_latency > latencies.empty_latency * 1.5 &&
            (latencies.full_latency - latencies.empty_latency) > 0.5) {
            result.flags.kernel_su = true;
            result.flags.apatch = true;
            result.hit_count = 1;

            char detail[256];
            snprintf(
                    detail,
                    sizeof(detail),
                    "Full string latency: %.3f us, Empty string latency: %.3f us. The significant difference indicates an older KernelPatch hooking logic.",
                    latencies.full_latency,
                    latencies.empty_latency
            );

            result.findings.push_back(
                    Finding{
                            .group = "SYSCALL",
                            .label = "Supercall Latency Anomalous",
                            .value = "Detected",
                            .detail = detail,
                            .severity = Severity::kDanger,
                    }
            );
        }

        return result;
    }

}  // namespace duckdetector::nativeroot