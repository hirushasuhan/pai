# ADR-012 — Inference runtime strategy: backend adapters first, own runtime manager later

**Status:** Proposed, future work. Not scheduled. Owner request 2026-10-23. Nothing in this ADR changes the current design, where the model is served by an external loopback server (today Ollama) behind the `Reasoner` interface (ADR-001, ADR-010).

## Context
The owner asked whether PAI could run models without Ollama, with a runtime that supports NVIDIA GPUs, AMD GPUs and an AMD NPU (the development laptop has an RTX 4050 6 GB, an AMD integrated GPU and an NPU). Today the NPU is not used: Ollama serves the model on CPU and GPU, and the project has no NPU detection yet (`ARCHITECTURE.md` describes accelerator routing as a design goal only).

## Decision (proposed)
1. **Do not write inference kernels.** Writing and maintaining CUDA, ROCm/HIP, Vulkan or NPU kernels is a very large, vendor-specific effort and is out of scope. PAI builds on existing engines and owns only the layer above them.
2. **Backend adapters behind `Reasoner`.** Each engine is one adapter with a model card (licence, SHA-256, RAM/VRAM and latency measured on the target machine). Candidate engines, to be re-verified when this ADR is taken up: llama.cpp (`llama-server`; CUDA, Vulkan, HIP or CPU builds), ONNX Runtime with the AMD Ryzen AI toolchain for the NPU, and Ollama as it is today.
3. **PAI runtime manager (`pai runtime`).** Detects hardware (including an NPU probe from VS4), chooses a backend with the router, fetches and hash-verifies model files, starts the engine as a child process bound to loopback only, and stops it and releases memory after use. This is the "own Ollama-like" part.
4. **Optional later: in-process inference in Rust.** Could improve purge control (threat T13) but needs a change to the `unsafe` boundary of ADR-009. Requires its own review.
5. **NPU backend only on evidence.** An NPU backend joins the router only if measurements on the owner's machine show a benefit (latency, RAM, power) for a task class compared with the RTX 4050 path.

## Stages
| Stage | Content | Entry condition |
|---|---|---|
| 0 | Keep Ollama (current) | now |
| 1 | llama.cpp `llama-server` adapter, measured against Ollama | 1.0.0 closed |
| 2 | `pai runtime` manager: detect, select, fetch, verify, supervise | Stage 1 results accepted |
| 3 | Optional in-process Rust inference | separate ADR and review of the `unsafe` boundary |
| 4 | Optional NPU backend | NPU probe merged, measurements show a benefit |

## Risks and requirements
- Supply chain (R12): engine binaries and model files must be pinned by hash and included in the signed release process (ADR-005).
- Licences of engines and models are read from official sources at adoption time and recorded.
- Per-vendor driver differences enlarge the test matrix. The owner's laptop can exercise three backends (NVIDIA, AMD GPU, NPU); other machines need `pai calibrate` (ADR-010).
- Every adapter needs hostile-input tests, a threat-register entry, claims-lint and CI before it is accepted.

## Consequences
No work starts before the 1.0.0 exit gate, and no change touches `research/` or `core/` during the shadow-evaluation window.
