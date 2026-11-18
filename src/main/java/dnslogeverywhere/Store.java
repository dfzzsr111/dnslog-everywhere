package dnslogeverywhere;

import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.atomic.AtomicInteger;

/**
 * 内存中的注入表 + 命中结果表。注入线程与轮询线程、Swing 线程共享。
 */
public final class Store {

    /** key = 12 位标识 */
    private final Map<String, Hit> pending = new ConcurrentHashMap<>();
    /** 已命中，按命中顺序 */
    private final List<Hit> hits = new ArrayList<>();

    public final AtomicInteger injected = new AtomicInteger();
    public final AtomicInteger matched = new AtomicInteger();

    public void register(Hit hit) {
        if (pending.size() > 20000) {          // 简单防爆内存
            pending.clear();
        }
        pending.put(hit.id, hit);
        injected.incrementAndGet();
    }

    /** 轮询返回一条记录时调用；返回是否命中已知注入。 */
    public synchronized Hit onDns(String subdomain, String ip, String dnsTime, String type) {
        if (subdomain == null) return null;
        int dot = subdomain.indexOf('.');
        String key = dot > 0 ? subdomain.substring(0, dot) : subdomain;
        Hit h = pending.get(key);
        if (h == null || h.matched()) return null;
        h.ip = ip == null ? "?" : ip;
        h.dnsTime = dnsTime;
        h.type = type;
        hits.add(h);
        matched.incrementAndGet();
        return h;
    }

    public synchronized List<Hit> hits() {
        return new ArrayList<>(hits);
    }

    public synchronized void remove(Hit h) {
        hits.remove(h);
    }

    public synchronized void clear() {
        pending.clear();
        hits.clear();
        injected.set(0);
        matched.set(0);
    }

    public int pendingSize() {
        return pending.size();
    }
}
