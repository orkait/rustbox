---
title: Architecture Overview
description: How rustbox composes Linux primitives into a sandbox
---

rustbox is a Linux-native process sandbox. No containers, no VMs, no abstraction layers between your code and the kernel primitives that actually enforce isolation.

## The core idea

Every sandbox is a bet: "I can run your code without it affecting anything else on this machine." Most systems make that bet with thick abstraction layers (Docker, gVisor, Firecracker). rustbox makes it with direct kernel primitives, composed in a fixed order that's enforced at compile time.

The result is a 2.8MB binary that provides 8 layers of isolation, evidence-backed verdicts, and deterministic resource enforcement.

## Module map

<img src="/module-map.svg" alt="Module map" style="max-width: 360px; display: block; margin: 1rem auto;" />

Each layer only talks to the layer directly below it. `verdict/` never touches the kernel. `kernel/` never makes policy decisions. This isn't just good architecture - it's the reason the unsafe audit passes: `verdict/` has zero unsafe blocks because it never needs to touch a syscall.
