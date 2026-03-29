package com.cisc468share.net;

import java.util.concurrent.ArrayBlockingQueue;
import java.util.concurrent.BlockingQueue;
import java.util.concurrent.atomic.AtomicBoolean;

/**
 * Decouples consent prompts from background TCP threads.
 *
 * The TCP router runs in a background thread and cannot safely call
 * Scanner.nextLine() while the CLI is also blocked on Scanner.nextLine()
 * in the main thread — the first keypress goes to whichever caller
 * happens to win the race.
 *
 * Fix: the background thread queues a request here and blocks on
 * the response queue. The main CLI loop polls hasPending(), prints
 * the prompt itself, reads the response, and calls respond().
 */
public class ConsentManager {

    public static class ConsentRequest {
        public final String peerName;
        public final String filename;
        public final long   filesize;

        ConsentRequest(String peerName, String filename, long filesize) {
            this.peerName = peerName;
            this.filename = filename;
            this.filesize = filesize;
        }
    }

    private final BlockingQueue<ConsentRequest> pending  = new ArrayBlockingQueue<>(1);
    private final BlockingQueue<Boolean>        response = new ArrayBlockingQueue<>(1);
    private final AtomicBoolean                 waiting  = new AtomicBoolean(false);

    /**
     * Called from a background thread.
     * Submits the request and blocks until the main thread responds.
     */
    public boolean request(String peerName, String filename, long filesize)
            throws InterruptedException {
        pending.put(new ConsentRequest(peerName, filename, filesize));
        waiting.set(true);
        return response.take();   // blocks until CLI loop calls respond()
    }

    /** True when a consent request is queued and waiting for a response. */
    public boolean hasPending() {
        return waiting.get();
    }

    /** Called from the main thread to retrieve the queued request. */
    public ConsentRequest popPending() throws InterruptedException {
        waiting.set(false);
        return pending.take();
    }

    /** Called from the main thread after the user answers. */
    public void respond(boolean accepted) throws InterruptedException {
        response.put(accepted);
    }
}
