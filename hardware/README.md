# hardware/ — Hardware Telemetry & Probe Charter (Phase 2 / Future Expansion)

Charter (ADR-004): Planned low-level GPU/NPU probing (NVML/CUDA/DXGI) and specialized hardware telemetry instrumentation.

**Current Production Status**:
In the current release (v1.5.1-beta.1), real-time hardware telemetry, RAM/VRAM pressure monitoring, and tier policy enforcement are actively implemented in Python (`research/hardware_telemetry.py`, `research/memory_optimizer.py`) via Win32 `kernel32` APIs and in the Rust core (`core/src/win32.rs`). Standalone C++ background daemons and raw socket clients were evaluated and dropped to maintain memory safety and reduce host attack surface.
