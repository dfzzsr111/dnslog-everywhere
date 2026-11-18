package dnslogeverywhere;

import burp.api.montoya.http.handler.HttpHandler;
import burp.api.montoya.http.handler.HttpRequestToBeSent;
import burp.api.montoya.http.handler.HttpResponseReceived;
import burp.api.montoya.http.handler.RequestToBeSentAction;
import burp.api.montoya.http.handler.ResponseReceivedAction;
import burp.api.montoya.http.message.params.HttpParameter;
import burp.api.montoya.http.message.params.ParsedHttpParameter;
import burp.api.montoya.http.message.requests.HttpRequest;

import java.security.SecureRandom;
import java.util.List;
import java.util.concurrent.atomic.AtomicLong;

/**
 * 核心注入逻辑：对每个出站请求，给配置里的每个 Header 塞一个带唯一标识的 DNSlog 子域，
 * 并登记到 Store，等待轮询命中。
 * 同时记录“收到了多少请求 / 上一次为什么没注入”，方便排查“注入请求一直是 0”。
 */
public final class InjectionHandler implements HttpHandler {

    private static final String STATIC_EXT =
            ".js|.css|.png|.jpg|.jpeg|.gif|.svg|.ico|.woff|.woff2|.ttf|.eot|.map|.webp|.mp4|.mp3|.avi|.pdf|.zip";

    private final Config cfg;
    private final Store store;
    private final SecureRandom rnd = new SecureRandom();
    private final AtomicLong seen = new AtomicLong();
    private volatile String lastSkip = "还没有收到任何请求";

    public InjectionHandler(Config cfg, Store store) {
        this.cfg = cfg;
        this.store = store;
    }

    /** 经过本 handler 的请求总数（不管有没有注入）。 */
    public long seen() {
        return seen.get();
    }

    /** 上一次被跳过的原因；成功注入时为 null。 */
    public String lastSkip() {
        return lastSkip;
    }

    @Override
    public RequestToBeSentAction handleHttpRequestToBeSent(HttpRequestToBeSent requestToBeSent) {
        seen.incrementAndGet();
        try {
            if (!cfg.enabled) return skip(requestToBeSent, "已暂停注入");

            if (isBlank(cfg.token)) return skip(requestToBeSent, "未填写 Token");
            if (isBlank(cfg.subdomain)) return skip(requestToBeSent, "未填写子域后缀");

            String url;
            String method;
            try {
                url = requestToBeSent.url();
                method = requestToBeSent.method();
            } catch (RuntimeException malformed) {
                return skip(requestToBeSent, "请求格式异常，取不到 URL");
            }
            if (url == null || url.isEmpty()) return skip(requestToBeSent, "URL 为空");

            // 别把我们的轮询请求也注入了
            String base = cfg.baseUrl();
            if (!base.isEmpty() && url.startsWith(base)) {
                return skip(requestToBeSent, "跳过 DNSlog 服务器自身的请求");
            }

            if (cfg.scopeOnly) {
                boolean inScope;
                try {
                    inScope = requestToBeSent.isInScope();
                } catch (RuntimeException ex) {
                    inScope = true;
                }
                if (!inScope) return skip(requestToBeSent, "URL 不在 Scope 内（可取消勾选「仅 Scope 内」）");
            }

            if (cfg.skipStatic && isStatic(url)) {
                return skip(requestToBeSent, "静态资源，已跳过");
            }

            List<String> headers = cfg.headerNames();
            if (headers.isEmpty()) return skip(requestToBeSent, "注入头一栏为空");

            String id = newId();
            HttpRequest updated = requestToBeSent;
            int idx = 0;
            for (String header : headers) {
                idx++;
                String key = id + String.format("%02d", idx);
                String domain = key + "." + cfg.subdomain;
                updated = updated.withHeader(header, valueFor(header, domain));
                store.register(new Hit(key, method, url, header, domain));
            }

            // 可选：把参数值也换成回连域名（噪声大，默认关）。同类参数最多 5 个。
            if (cfg.injectParams) {
                int injectedParams = 0;
                for (ParsedHttpParameter p : requestToBeSent.parameters()) {
                    if (injectedParams >= 5) break;
                    String name = p.name();
                    if (name == null || name.isEmpty()) continue;
                    idx++;
                    injectedParams++;
                    String key = id + String.format("%02d", Math.min(idx, 99));
                    String domain = key + "." + cfg.subdomain;
                    try {
                        updated = updated.withUpdatedParameters(
                                HttpParameter.parameter(name, domain, p.type()));
                        store.register(new Hit(key, method, url, "参数:" + name, domain));
                    } catch (RuntimeException ignored) {
                        // 某些参数类型不支持替换，跳过
                    }
                }
            }
            lastSkip = null;
            return RequestToBeSentAction.continueWith(updated);
        } catch (Throwable t) {
            // 任何异常都不能影响正常请求
            lastSkip = "处理异常：" + t.getClass().getSimpleName();
            return RequestToBeSentAction.continueWith(requestToBeSent);
        }
    }

    @Override
    public ResponseReceivedAction handleHttpResponseReceived(HttpResponseReceived responseReceived) {
        return ResponseReceivedAction.continueWith(responseReceived);
    }

    private RequestToBeSentAction skip(HttpRequestToBeSent r, String why) {
        lastSkip = why;
        return RequestToBeSentAction.continueWith(r);
    }

    private static boolean isBlank(String s) {
        return s == null || s.trim().isEmpty();
    }

    /** 10 位随机 hex，配合 2 位序号共 12 位。 */
    private String newId() {
        byte[] b = new byte[5];
        rnd.nextBytes(b);
        StringBuilder sb = new StringBuilder(10);
        for (byte x : b) sb.append(String.format("%02x", x));
        return sb.toString();
    }

    /** URL 语义的头带 scheme，否则纯域名更容易被日志/解析器记录下来。 */
    private static String valueFor(String header, String domain) {
        String h = header.trim();
        if (h.equalsIgnoreCase("Referer") || h.equalsIgnoreCase("Origin")) {
            return "http://" + domain + "/";
        }
        if (h.equalsIgnoreCase("User-Agent")) {
            return "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 DNSlogEverywhere/" + domain;
        }
        return domain;
    }

    private static boolean isStatic(String url) {
        int q = url.indexOf('?');
        String path = (q >= 0 ? url.substring(0, q) : url).toLowerCase();
        for (String ext : STATIC_EXT.split("\\|")) {
            if (path.endsWith(ext)) return true;
        }
        return false;
    }
}
