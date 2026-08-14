# optictrace/sdks/gin

OpticTrace middleware for Gin, backed by the same Go engine as the agent.

```go
import (
    "github.com/gin-gonic/gin"
    "github.com/dwarka-prasad/optictrace"
    optictracegin "github.com/dwarka-prasad/optictrace/sdks/gin"
)

func main() {
    agent, err := optictrace.New("optic.yaml")
    if err != nil { panic(err) }
    defer agent.Close()
    agent.ServeAdmin("")            // /metrics + dashboard + APIs on :9095

    r := gin.New()
    r.Use(optictracegin.Middleware(agent))
    // ... routes
    r.Run(":8080")
}
```

See the [main repository](https://github.com/dwarka-prasad/optictrace) for the
full `optic.yaml` reference.
