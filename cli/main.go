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

package main

import (
	"fmt"
	"os"
	"os/signal"
	"syscall"

	"go.opentelemetry.io/auto/pkg/errors"
	"go.opentelemetry.io/auto/pkg/instrumentors"
	"go.opentelemetry.io/auto/pkg/log"
	"go.opentelemetry.io/auto/pkg/opentelemetry"
	"go.opentelemetry.io/auto/pkg/process"
)

func main() {
	err := log.Init()
	if err != nil {
		fmt.Printf("could not init logger: %s\n", err)
		os.Exit(1)
	}

	log.Logger.V(0).Info("starting Go OpenTelemetry Agent ...")

	processAnalyzer := process.NewAnalyzer()

	stopper := make(chan os.Signal, 1)
	signal.Notify(stopper, os.Interrupt, syscall.SIGTERM)

	target := process.ParseTargetArgs()
	if target == nil {
		log.Logger.Info("No target args will instrument for all go processes")
	}
	pch := processAnalyzer.DiscoverProcess(target)

	for p := range pch {

		var otelController *opentelemetry.Controller
		if target != nil {
			otelController, err = opentelemetry.NewController(target.ServiceName)
			if err != nil {
				log.Logger.Error(err, "unable to create OpenTelemetry controller")
				return
			}
		} else {
			otelController, err = opentelemetry.NewController(p.Exec)
			if err != nil {
				log.Logger.Error(err, "unable to create OpenTelemetry controller")
				return
			}
		}
		instManager, err := instrumentors.NewManager(otelController)
		if err != nil {
			log.Logger.Error(err, "error creating instrumetors manager")
			return
		}
		targetDetails, err := processAnalyzer.Analyze(p.PID, instManager.GetRelevantFuncs())
		if err != nil {
			log.Logger.Error(err, "error while analyzing target process")
			return
		}
		log.Logger.V(0).Info("target process analysis completed", "pid", targetDetails.PID,
			"go_version", targetDetails.GoVersion, "dependencies", targetDetails.Libraries,
			"total_functions_found", len(targetDetails.Functions))

		instManager.FilterUnusedInstrumentors(targetDetails)

		log.Logger.V(0).Info("invoking instrumentors")
		err = instManager.Run(targetDetails)
		if err != nil && err != errors.ErrInterrupted {
			log.Logger.Error(err, "error while running instrumentors")
		}
	}
	<-stopper
	log.Logger.V(0).Info("Got SIGTERM, cleaning up..")
	processAnalyzer.Close()
}
