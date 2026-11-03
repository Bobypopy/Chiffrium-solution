package com.chiffrium.api;

import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.util.ArrayDeque;
import java.util.Deque;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;

/**
 * Limitation des échecs d'authentification par adresse IP (fenêtre glissante), en complément du
 * verrouillage par compte : freine le "password spraying" sur de nombreux identifiants.
 */
final class LoginThrottle {

    static final int MAX_FAILURES = 20;
    static final Duration WINDOW = Duration.ofMinutes(5);

    private final Clock clock;
    private final Map<String, Deque<Instant>> failures = new ConcurrentHashMap<>();

    LoginThrottle(Clock clock) {
        this.clock = clock;
    }

    boolean isBlocked(String ip) {
        Deque<Instant> attempts = failures.get(ip);
        if (attempts == null) {
            return false;
        }
        synchronized (attempts) {
            prune(attempts);
            return attempts.size() >= MAX_FAILURES;
        }
    }

    void recordFailure(String ip) {
        Deque<Instant> attempts = failures.computeIfAbsent(ip, k -> new ArrayDeque<>());
        synchronized (attempts) {
            prune(attempts);
            attempts.addLast(clock.instant());
        }
    }

    void reset(String ip) {
        failures.remove(ip);
    }

    private void prune(Deque<Instant> attempts) {
        Instant limit = clock.instant().minus(WINDOW);
        while (!attempts.isEmpty() && attempts.peekFirst().isBefore(limit)) {
            attempts.removeFirst();
        }
    }
}
