"""Application layer: use cases orchestrated by the CLI/TUI entry points.

Holds the services (use cases), the application DTOs that cross adapter
boundaries, and the Dishka composition container. Depends on the
domain core; never on the adapters.
"""