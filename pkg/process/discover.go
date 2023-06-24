// Copyright The OpenTelemetry Authors
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package process

import (
	"io"
	"io/ioutil"
	"os"
	"path"
	"strconv"
	"strings"
	"time"

	"github.com/google/gops/goprocess"
	"go.opentelemetry.io/auto/pkg/errors"
	"go.opentelemetry.io/auto/pkg/log"
)

// Analyzer is used to find actively running processes.
type Analyzer struct {
	done          chan bool
	pidTickerChan <-chan time.Time
}

// NewAnalyzer returns a new [ProcessAnalyzer].
func NewAnalyzer() *Analyzer {
	return &Analyzer{
		done:          make(chan bool, 1),
		pidTickerChan: time.NewTicker(2 * time.Second).C,
	}
}

// DiscoverProcessID searches for the target as an actively running process,
// returning its PID if found.
func (a *Analyzer) DiscoverProcess(target *TargetArgs) chan goprocess.P {
	ch := make(chan goprocess.P)
	dupes := make(map[int]struct{})
	ignoreProcesses := make(map[string]struct{})
	ignoreProcesses["dockerd"] = struct{}{}
	ignoreProcesses["containerd"] = struct{}{}
	ignoreProcesses["gopls"] = struct{}{}
	ignoreProcesses["docker-proxy"] = struct{}{}
	ignoreProcesses["otel-go-instrumentation"] = struct{}{}
	ignoreProcesses["gops"] = struct{}{}
	ignoreProcesses["containerd-shim-runc-v2"] = struct{}{}

	go func() {
		defer func() {
			close(ch)
		}()

		for {
			select {
			case <-a.done:
				log.Logger.V(0).Info("stopping process id discovery due to kill signal")
				return
			case <-a.pidTickerChan:
				if target != nil {
					pid, err := a.findProcessID(target)
					if err == nil {
						log.Logger.V(0).Info("found process", "pid", pid)
						pr, ok, err := goprocess.Find(pid)
						if err != nil {
							log.Logger.V(0).Error(err, "error finding process", "pid", pid)
						}
						if ok {
							ch <- pr
						}
						return
					}
					if err == errors.ErrProcessNotFound {
						log.Logger.V(0).Info("process not found yet, trying again soon", "exe_path", target.ExePath)
					} else {
						log.Logger.Error(err, "error while searching for process", "exe_path", target.ExePath)
					}

				} else {
					pm := goprocess.FindAll()
					for _, p := range pm {
						if _, ok := dupes[p.PID]; ok {
							continue
						}
						if _, ok := ignoreProcesses[p.Exec]; ok {
							log.Logger.V(0).Info("ignoring process", "process", p)
							dupes[p.PID] = struct{}{}
							continue
						}

						log.Logger.V(0).Info("found new process", "process", p)
						ch <- p
						dupes[p.PID] = struct{}{}

					}
				}

			}
		}
	}()
	return ch
}

func (a *Analyzer) findProcessID(target *TargetArgs) (int, error) {
	proc, err := os.Open("/proc")
	if err != nil {
		return 0, err
	}

	for {
		dirs, err := proc.Readdir(15)
		if err == io.EOF {
			break
		}
		if err != nil {
			return 0, err
		}

		for _, di := range dirs {
			if !di.IsDir() {
				continue
			}

			dname := di.Name()
			if dname[0] < '0' || dname[0] > '9' {
				continue
			}

			pid, err := strconv.Atoi(dname)
			if err != nil {
				return 0, err
			}

			exeName, err := os.Readlink(path.Join("/proc", dname, "exe"))
			if err != nil {
				// Read link may fail if target process runs not as root
				cmdLine, err := ioutil.ReadFile(path.Join("/proc", dname, "cmdline"))
				if err != nil {
					return 0, err
				}

				if strings.Contains(string(cmdLine), target.ExePath) {
					return pid, nil
				}
			} else if exeName == target.ExePath {
				return pid, nil
			}
		}
	}

	return 0, errors.ErrProcessNotFound
}

// Close closes the analyzer.
func (a *Analyzer) Close() {
	a.done <- true
}
