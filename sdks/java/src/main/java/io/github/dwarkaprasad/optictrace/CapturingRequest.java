package io.github.dwarkaprasad.optictrace;

import jakarta.servlet.ReadListener;
import jakarta.servlet.ServletInputStream;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletRequestWrapper;

import java.io.ByteArrayOutputStream;
import java.io.IOException;

/**
 * Tees the request body as the application reads it.
 *
 * <p>Deliberately a tee rather than a read-ahead: the application still sees
 * the original stream, in the original order, so nothing about how it parses
 * its input changes. Capture stops at the limit but byte counting does not —
 * the size of a payload is useful even when its contents are not stored.
 */
final class CapturingRequest extends HttpServletRequestWrapper {

    private final boolean capture;
    private final int limit;
    private final ByteArrayOutputStream buffer = new ByteArrayOutputStream();
    private long bytes;
    private boolean truncated;
    private ServletInputStream stream;

    CapturingRequest(HttpServletRequest request, boolean capture, int limit) {
        super(request);
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

    @Override
    public ServletInputStream getInputStream() throws IOException {
        if (stream != null) return stream;
        ServletInputStream delegate = super.getInputStream();
        stream = new ServletInputStream() {
            @Override
            public int read() throws IOException {
                int b = delegate.read();
                if (b >= 0) record(new byte[]{(byte) b}, 0, 1);
                return b;
            }

            @Override
            public int read(byte[] b, int off, int len) throws IOException {
                int n = delegate.read(b, off, len);
                if (n > 0) record(b, off, n);
                return n;
            }

            @Override
            public boolean isFinished() {
                return delegate.isFinished();
            }

            @Override
            public boolean isReady() {
                return delegate.isReady();
            }

            @Override
            public void setReadListener(ReadListener listener) {
                delegate.setReadListener(listener);
            }
        };
        return stream;
    }

    @Override
    public java.io.BufferedReader getReader() throws IOException {
        return new java.io.BufferedReader(new java.io.InputStreamReader(getInputStream(), getCharacterEncodingOrUtf8()));
    }

    private String getCharacterEncodingOrUtf8() {
        String enc = getCharacterEncoding();
        return enc == null ? "UTF-8" : enc;
    }

    private void record(byte[] b, int off, int len) {
        bytes += len;
        if (!capture) return;
        int room = limit - buffer.size();
        if (room > 0) buffer.write(b, off, Math.min(room, len));
        if (len > room) truncated = true;
    }
}
