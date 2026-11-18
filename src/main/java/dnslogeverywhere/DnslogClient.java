package dnslogeverywhere;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.HttpURLConnection;
import java.net.URL;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;

/**
 * DNSlog-GO 的极简客户端：只依赖 JDK 的 HttpURLConnection，走 Java 原生网络栈，
 * 不经过 Burp 的代理，因此不会被自己的 HttpHandler 二次注入，也不会污染 Proxy history。
 * JSON 用自带的 MiniJson 解析，字段名做了兼容，缺字段不会崩。
 */
public final class DnslogClient {

    public static final class Entry {
        public final String subdomain;
        public final String ip;
        public final String time;
        public final String type;

        Entry(String subdomain, String ip, String time, String type) {
            this.subdomain = subdomain;
            this.ip = ip;
            this.time = time;
            this.type = type;
        }
    }

    private final Config cfg;

    public DnslogClient(Config cfg) {
        this.cfg = cfg;
    }

    /** 校验 token 并返回绑定的子域；失败抛异常。 */
    public String verifyToken() throws IOException {
        String body = "{\"token\":\"" + jsonEscape(cfg.token) + "\"}";
        String resp = post(cfg.baseUrl() + "/api/verifyToken", body);
        Map<String, Object> root = asMap(parseJson(resp));
        if (root == null) throw new IOException("返回不是 JSON 对象: " + brief(resp));
        Map<String, Object> data = asMap(get(root, "data"));
        if (data == null) throw new IOException("返回缺少 data: " + brief(resp));
        String sub = str(data, "subdomain", "domain", "name");
        if (sub == null || sub.isBlank()) throw new IOException("返回缺少 subdomain: " + brief(resp));
        return sub.trim();
    }

    /** 拉取 DNS 记录列表。 */
    public List<Entry> fetchData() throws IOException {
        String resp = get(cfg.baseUrl() + "/api/getDnsData");
        List<Entry> out = new ArrayList<>();
        Map<String, Object> root = asMap(parseJson(resp));
        if (root == null) return out;

        Object data = get(root, "data");
        List<Object> list = asList(data);
        if (list == null) {
            // 兼容 {"data":{"list":[...]}} 之类的包装
            Map<String, Object> wrap = asMap(data);
            if (wrap != null) list = asList(get(wrap, "list", "rows", "items", "records"));
        }
        if (list == null) return out;

        int skipped = 0;
        for (Object item : list) {
            Map<String, Object> m = asMap(item);
            if (m == null) { skipped++; continue; }
            String sub = str(m, "subdomain", "domain", "name", "qname");
            if (sub == null || sub.isBlank()) { skipped++; continue; }
            out.add(new Entry(sub.trim(),
                    str(m, "ipaddress", "ip", "address", "remote_addr", "client_ip"),
                    str(m, "time", "created_at", "date", "timestamp"),
                    str(m, "type", "record_type")));
        }
        if (out.isEmpty() && skipped > 0) {
            throw new IOException("返回了 " + skipped + " 条记录但认不出字段，原始返回: " + brief(resp));
        }
        return out;
    }

    /** 清空服务端记录（可选调用）。 */
    public void clean() throws IOException {
        get(cfg.baseUrl() + "/api/clean");
    }

    // ------------------------------------------------------------------ HTTP

    private String get(String url) throws IOException {
        HttpURLConnection c = open(url, "GET");
        c.setRequestProperty("token", cfg.token);
        return read(c);
    }

    private String post(String url, String body) throws IOException {
        HttpURLConnection c = open(url, "POST");
        c.setRequestProperty("token", cfg.token);
        c.setRequestProperty("Content-Type", "application/json");
        c.setDoOutput(true);
        byte[] b = body.getBytes(StandardCharsets.UTF_8);
        c.setRequestProperty("Content-Length", String.valueOf(b.length));
        try (OutputStream os = c.getOutputStream()) {
            os.write(b);
        }
        return read(c);
    }

    private HttpURLConnection open(String url, String method) throws IOException {
        HttpURLConnection c = (HttpURLConnection) new URL(url).openConnection();
        c.setRequestMethod(method);
        c.setConnectTimeout(8000);
        c.setReadTimeout(8000);
        c.setInstanceFollowRedirects(true);
        c.setRequestProperty("Accept", "application/json");
        c.setRequestProperty("User-Agent", "DNSlogEverywhere/1.0");
        String auth = cfg.basicAuthValue();
        if (auth != null) c.setRequestProperty("Authorization", auth);
        return c;
    }

    private String read(HttpURLConnection c) throws IOException {
        int code = c.getResponseCode();
        InputStream in = code >= 400 ? c.getErrorStream() : c.getInputStream();
        String text = in == null ? "" : slurp(in);
        if (code == 401) {
            throw new IOException("HTTP 401: token 无效，或服务器启用了 Basic Auth"
                    + (cfg.hasAuth() ? "（已带上账号密码，请确认是否正确）" : "（请在配置里填写账号/密码）")
                    + "。" + brief(text));
        }
        if (code >= 400) {
            throw new IOException("HTTP " + code + ": " + brief(text));
        }
        return text;
    }

    private static String slurp(InputStream in) throws IOException {
        ByteArrayOutputStream bos = new ByteArrayOutputStream();
        byte[] buf = new byte[8192];
        int n;
        while ((n = in.read(buf)) > 0) bos.write(buf, 0, n);
        try {
            in.close();
        } catch (IOException ignored) {
        }
        return bos.toString(StandardCharsets.UTF_8);
    }

    // ------------------------------------------------------------- JSON 工具

    private static Object parseJson(String resp) throws IOException {
        if (resp == null || resp.isBlank()) throw new IOException("返回内容为空");
        String t = resp.trim();
        if (!t.startsWith("{") && !t.startsWith("[")) {
            throw new IOException("返回不是 JSON（可能是登录页或错误页）: " + brief(resp));
        }
        try {
            return MiniJson.parse(t);
        } catch (RuntimeException ex) {
            throw new IOException("JSON 解析失败(" + ex.getMessage() + "): " + brief(resp));
        }
    }

    @SuppressWarnings("unchecked")
    private static Map<String, Object> asMap(Object o) {
        return o instanceof Map ? (Map<String, Object>) o : null;
    }

    @SuppressWarnings("unchecked")
    private static List<Object> asList(Object o) {
        return o instanceof List ? (List<Object>) o : null;
    }

    /** 按给定顺序取第一个存在的键，大小写不敏感。 */
    private static Object get(Map<String, Object> m, String... keys) {
        if (m == null) return null;
        for (String k : keys) {
            if (m.containsKey(k)) return m.get(k);
        }
        for (String k : keys) {
            for (Map.Entry<String, Object> e : m.entrySet()) {
                if (e.getKey() != null && e.getKey().equalsIgnoreCase(k)) return e.getValue();
            }
        }
        return null;
    }

    private static String str(Map<String, Object> m, String... keys) {
        Object v = get(m, keys);
        if (v == null) return null;
        if (v instanceof String) return (String) v;
        if (v instanceof Double) {
            double d = (Double) v;
            if (d == Math.rint(d) && !Double.isInfinite(d)) return String.valueOf((long) d);
            return String.valueOf(d);
        }
        return String.valueOf(v);
    }

    private static String brief(String s) {
        if (s == null) return "";
        s = s.replaceAll("\\s+", " ").trim();
        return s.length() > 160 ? s.substring(0, 160) + "..." : s;
    }

    private static String jsonEscape(String s) {
        StringBuilder sb = new StringBuilder();
        for (char ch : s.toCharArray()) {
            switch (ch) {
                case '"': sb.append("\\\""); break;
                case '\\': sb.append("\\\\"); break;
                case '\n': sb.append("\\n"); break;
                case '\r': sb.append("\\r"); break;
                case '\t': sb.append("\\t"); break;
                default:
                    if (ch < 0x20) sb.append(String.format("\\u%04x", (int) ch));
                    else sb.append(ch);
            }
        }
        return sb.toString();
    }
}
