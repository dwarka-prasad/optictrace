// Package optictracegin adapts the OpticTrace agent to Gin.
//
//	agent, _ := optictrace.New("optic.yaml")
//	defer agent.Close()
//	agent.ServeAdmin("")            // metrics + dashboard on :9095
//
//	r := gin.New()
//	r.Use(optictracegin.Middleware(agent))
package optictracegin

import (
	"bufio"
	"net"
	"net/http"

	"github.com/dwarka-prasad/optictrace"
	"github.com/gin-gonic/gin"
)

// Middleware runs every Gin request through the OpticTrace interceptor:
// rule evaluation, restriction/redaction, metrics, and payload storage.
func Middleware(agent *optictrace.Agent) gin.HandlerFunc {
	return func(c *gin.Context) {
		// Bridge Gin's context into a plain http.Handler chain so both
		// deployment modes share the exact same interception code path.
		wrapped := agent.Middleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			c.Writer = &ginWriterAdapter{ResponseWriter: w, gw: c.Writer}
			c.Request = r
			c.Next()
		}))
		wrapped.ServeHTTP(c.Writer, c.Request)
	}
}

// ginWriterAdapter satisfies gin.ResponseWriter while routing writes through
// OpticTrace's recording writer.
type ginWriterAdapter struct {
	http.ResponseWriter
	gw     gin.ResponseWriter
	status int
	size   int
}

func (g *ginWriterAdapter) WriteHeader(code int) {
	g.status = code
	g.ResponseWriter.WriteHeader(code)
}

func (g *ginWriterAdapter) Write(b []byte) (int, error) {
	if g.status == 0 {
		g.status = http.StatusOK
	}
	n, err := g.ResponseWriter.Write(b)
	g.size += n
	return n, err
}

func (g *ginWriterAdapter) WriteString(s string) (int, error) { return g.Write([]byte(s)) }
func (g *ginWriterAdapter) Status() int {
	if g.status == 0 {
		return http.StatusOK
	}
	return g.status
}
func (g *ginWriterAdapter) Size() int     { return g.size }
func (g *ginWriterAdapter) Written() bool { return g.status != 0 || g.size > 0 }
func (g *ginWriterAdapter) WriteHeaderNow() {
	if g.status == 0 {
		g.status = http.StatusOK
	}
	g.ResponseWriter.WriteHeader(g.status)
}

// Delegate gin-specific capabilities to the original writer.
func (g *ginWriterAdapter) CloseNotify() <-chan bool { return g.gw.CloseNotify() }
func (g *ginWriterAdapter) Flush() {
	if f, ok := g.ResponseWriter.(http.Flusher); ok {
		f.Flush()
	}
}
func (g *ginWriterAdapter) Pusher() http.Pusher { return g.gw.Pusher() }
func (g *ginWriterAdapter) Hijack() (net.Conn, *bufio.ReadWriter, error) {
	// Hijacked connections (websockets) bypass capture by nature.
	return g.gw.Hijack()
}
