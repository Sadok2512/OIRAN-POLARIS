# S4.2 Web integration report

Probe Manager now consumes authenticated `GET /api/v1/storage/safety` and displays measured utilization, available bytes, decision state, reserved budget, bounded rotation and capture-service capability. The API measures the workspace filesystem on every request; the UI refreshes every 30 seconds while future active capture jobs require a one-second backend guard loop.

Capture controls remain disabled and explicitly state `NOT_CONFIGURED`. This prevents the UI from implying that POLARIS lifecycle control is available. Existing multi-session Session Explorer, Call Flow Viewer and Correlation Studio behavior is unchanged.
