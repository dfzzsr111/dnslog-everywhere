package dnslogeverywhere;

/**
 * 一次“注入 -> 回连”的记录。注入时先建对象，回连命中后补齐 dnsTime / ip。
 */
public final class Hit {

    public final String id;          // 12 位标识（10 位随机 hex + 2 位序号）
    public final long injectTime;    // System.currentTimeMillis()
    public final String method;
    public final String url;
    public final String header;      // 触发点，如 X-Forwarded-For
    public final String domain;      // 完整回连域名

    public volatile String dnsTime;  // DNSlog 服务端记录的时间
    public volatile String ip;       // 来源 IP
    public volatile String type;     // A / AAAA / HTTP ...

    public Hit(String id, String method, String url, String header, String domain) {
        this.id = id;
        this.injectTime = System.currentTimeMillis();
        this.method = method;
        this.url = url;
        this.header = header;
        this.domain = domain;
    }

    public boolean matched() {
        return ip != null;
    }
}
