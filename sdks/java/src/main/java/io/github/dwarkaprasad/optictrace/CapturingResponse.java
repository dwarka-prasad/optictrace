package io.github.dwarkaprasad.optictrace;

import jakarta.servlet.ServletOutputStream;
import jakarta.servlet.WriteListener;
import jakarta.servlet.http.HttpServletResponse;
import jakarta.servlet.http.HttpServletResponseWrapper;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.PrintWriter;
import java.util.LinkedHashMap;
import java.util.Locale;
import java.util.Map;

/**
 * Tees the response body on its way to the client.
 *
 * <p>Bytes are passed through immediately rather than buffered and replayed,
 * so a streaming response still reaches the client as it is produced and the
 * application's own flush semantics are unchanged. Live traffic is never
 * modified: what the client receives is exactly what the application wrote.
 */
final class CapturingResponse extends HttpServletResponseWrapper {

    private final boolean capture;
    private final int limit;
    private final ByteArrayOutputStream buffer = new ByteArrayOutputStream();
    private long bytes;
    private boolean truncated;
    private ServletOutputStream stream;
    private PrintWriter writer;

    CapturingResponse(HttpServletResponse response, boolean capture, int limit) {
        super(response);
        this.capture = capture;
        this.limit = limit;
    }

    byte[] captured() {
        return buffer.toByteArray();
    }

    long byteCount() {
        return bytes;
    }

    boolean truncated() {
        return truncated;
    }

    Map<String, String> headers() {
        Map<String, String> out = new LinkedHashMap<>();
        for (String name : getHeaderNames()) out.put(name.toLowerCase(Locale.ROOT), getHeader(name));
        return out;
    }

    void flushCapture() throws IOException {
        if (writer != null) writer.flush();
    }

    @Override
    public ServletOutputStream getOutputStream() throws IOException {
        if (stream != null) return stream;
        ServletOutputStream delegate = super.getOutputStream();
        stream = new ServletOutputStream() {
            @Override
            public void write(int b) throws IOException {
                delegate.write(b);
                record(new byte[]{(byte) b}, 0, 1);
            }

            @Override
            public void write(byte[] b, int off, int len) throws IOException {
                delegate.write(b, off, len);
                record(b, off, len);
            }

            @Override
            public boolean isReady() {
                return delegate.isReady();
            }

            @Override
            public void setWriteListener(WriteListener listener) {
                delegate.setWriteListener(listener);
            }
        };
        return stream;
    }

    @Override
    public PrintWriter getWriter() throws IOException {
        if (writer != null) return writer;
        String enc = getCharacterEncoding() == null ? "UTF-8" : getCharacterEncoding();
        writer = new PrintWriter(new java.io.OutputStreamWriter(getOutputStream(), enc), false);
        return writer;
    }

    private void record(byte[] b, int off, int len) {
        bytes += len;
        if (!capture) return;
        int room = limit - buffer.size();
        if (room > 0) buffer.write(b, off, Math.min(room, len));
        if (len > room) truncated = true;
    }
}
