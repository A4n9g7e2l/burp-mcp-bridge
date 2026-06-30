package com.burpmcpbridge.mcp;

import java.io.InputStream;
import java.io.IOException;
import java.util.concurrent.BlockingQueue;
import java.util.concurrent.LinkedBlockingQueue;
import java.util.concurrent.TimeUnit;

public class SSESession {

    private final String sessionId;
    private final BlockingQueue<byte[]> queue = new LinkedBlockingQueue<>();
    private volatile boolean closed = false;
    private final SSEInputStream inputStream;

    public SSESession(String sessionId) {
        this.sessionId = sessionId;
        this.inputStream = new SSEInputStream();
    }

    public String getSessionId() {
        return sessionId;
    }

    public InputStream getInputStream() {
        return inputStream;
    }

    public void sendEvent(String eventType, String data) {
        if (closed) return;
        String event = "event: " + eventType + "\ndata: " + data + "\n\n";
        queue.offer(event.getBytes(java.nio.charset.StandardCharsets.UTF_8));
    }

    public void close() {
        closed = true;
        queue.offer(new byte[0]);
    }

    public boolean isClosed() {
        return closed;
    }

    private class SSEInputStream extends InputStream {
        private byte[] currentBuffer = null;
        private int currentPos = 0;

        @Override
        public int read() throws IOException {
            if (closed && currentBuffer == null) {
                return -1;
            }
            while (true) {
                if (currentBuffer != null && currentPos < currentBuffer.length) {
                    return currentBuffer[currentPos++] & 0xFF;
                }
                if (currentBuffer != null && currentPos >= currentBuffer.length) {
                    currentBuffer = null;
                    currentPos = 0;
                    if (closed) {
                        return -1;
                    }
                }
                try {
                    currentBuffer = queue.poll(60, TimeUnit.SECONDS);
                    if (currentBuffer == null) {
                        continue;
                    }
                    if (currentBuffer.length == 0) {
                        return -1;
                    }
                    currentPos = 0;
                } catch (InterruptedException e) {
                    Thread.currentThread().interrupt();
                    return -1;
                }
            }
        }

        @Override
        public int read(byte[] b, int off, int len) throws IOException {
            if (closed && currentBuffer == null) {
                return -1;
            }
            while (true) {
                if (currentBuffer != null && currentPos < currentBuffer.length) {
                    int available = Math.min(len, currentBuffer.length - currentPos);
                    System.arraycopy(currentBuffer, currentPos, b, off, available);
                    currentPos += available;
                    return available;
                }
                if (currentBuffer != null && currentPos >= currentBuffer.length) {
                    currentBuffer = null;
                    currentPos = 0;
                    if (closed) {
                        return -1;
                    }
                }
                try {
                    currentBuffer = queue.poll(60, TimeUnit.SECONDS);
                    if (currentBuffer == null) {
                        continue;
                    }
                    if (currentBuffer.length == 0) {
                        return -1;
                    }
                    currentPos = 0;
                } catch (InterruptedException e) {
                    Thread.currentThread().interrupt();
                    return -1;
                }
            }
        }

        @Override
        public int available() throws IOException {
            if (currentBuffer != null && currentPos < currentBuffer.length) {
                return currentBuffer.length - currentPos;
            }
            return queue.size() > 0 ? 1 : 0;
        }

        @Override
        public void close() throws IOException {
            closed = true;
            queue.offer(new byte[0]);
        }
    }
}