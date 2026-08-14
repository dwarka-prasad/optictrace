# optictrace-fastapi

OpticTrace middleware for FastAPI (pure ASGI — works with Starlette or any
ASGI framework). Evaluates your `optic.yaml` **in-process** and ships governed
records to the OpticTrace agent.

```python
from fastapi import FastAPI
from optictrace_fastapi import OpticTraceMiddleware

app = FastAPI()
app.add_middleware(
    OpticTraceMiddleware,
    config_path="optic.yaml",
    agent_url="http://localhost:9095",  # omit to log JSON lines to stdout
)
```

Telemetry ships from a background thread, fire-and-forget — agent downtime
never affects your app. See the
[main repository](https://github.com/dwarka-prasad/optictrace) for the full
`optic.yaml` reference.
