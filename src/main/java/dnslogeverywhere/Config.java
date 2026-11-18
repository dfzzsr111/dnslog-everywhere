package dnslogeverywhere;

import burp.api.montoya.persistence.Preferences;

import java.util.ArrayList;
import java.util.List;

/**
 * 插件配置，持久化在 Burp 的 Java 偏好存储里（重启不丢）。
 */
public final class Config {

    private static final String K_SERVER = "dnslog.serverUrl";
    private static final String K_TOKEN = "dnslog.token";
    private static final String K_SUBDOMAIN = "dnslog.subdomain";
    private static final String K_HEADERS = "dnslog.headers";
    private static final String K_PARAMS = "dnslog.injectParams";
    private static final String K_INTERVAL = "dnslog.pollSeconds";
    private static final String K_SCOPE = "dnslog.scopeOnly";
    private static final String K_STATIC = "dnslog.skipStatic";
    private static final String K_USER = "dnslog.username";
    private static final String K_PASS = "dnslog.password";

    public static final String DEFAULT_HEADERS =
            "X-Forwarded-For,X-Real-IP,X-Client-IP,X-Forwarded-Host,Referer,Origin,User-Agent";

    public volatile String serverUrl = "";
    public volatile String token = "";
    public volatile String subdomain = "";
    public volatile String headers = DEFAULT_HEADERS;
    public volatile boolean injectParams = false;
    public volatile int pollSeconds = 8;
    public volatile boolean scopeOnly = true;
    public volatile boolean skipStatic = true;

    /** 可选：DNSlog-GO 前置了 Basic Auth 时填写（明文存在 Burp 配置里）。 */
    public volatile String username = "";
    public volatile String password = "";

    /** 总开关：暂停注入时不影响已记录的命中。 */
    public volatile boolean enabled = true;

    private final Preferences prefs;

    public Config(Preferences prefs) {
        this.prefs = prefs;
        load();
    }

    private void load() {
        String v;
        if ((v = prefs.getString(K_SERVER)) != null && !v.isBlank()) serverUrl = v.trim();
        if ((v = prefs.getString(K_TOKEN)) != null && !v.isBlank()) token = v.trim();
        if ((v = prefs.getString(K_SUBDOMAIN)) != null && !v.isBlank()) subdomain = v.trim();
        if ((v = prefs.getString(K_HEADERS)) != null && !v.isBlank()) headers = v.trim();
        Boolean b;
        if ((b = prefs.getBoolean(K_PARAMS)) != null) injectParams = b;
        Integer i;
        if ((i = prefs.getInteger(K_INTERVAL)) != null && i >= 3) pollSeconds = i;
        if ((b = prefs.getBoolean(K_SCOPE)) != null) scopeOnly = b;
        if ((b = prefs.getBoolean(K_STATIC)) != null) skipStatic = b;
        if ((v = prefs.getString(K_USER)) != null && !v.isBlank()) username = v.trim();
        if ((v = prefs.getString(K_PASS)) != null && !v.isEmpty()) password = v;
    }

    public void save() {
        extractUserInfo();
        prefs.setString(K_SERVER, serverUrl);
        prefs.setString(K_TOKEN, token);
        prefs.setString(K_SUBDOMAIN, subdomain);
        prefs.setString(K_HEADERS, headers);
        prefs.setBoolean(K_PARAMS, injectParams);
        prefs.setInteger(K_INTERVAL, pollSeconds);
        prefs.setBoolean(K_SCOPE, scopeOnly);
        prefs.setBoolean(K_STATIC, skipStatic);
        prefs.setString(K_USER, username);
        prefs.setString(K_PASS, password);
    }

    /** 是否配置了 Basic Auth 账号。 */
    public boolean hasAuth() {
        return username != null && !username.isBlank();
    }

    /** Base64(user:pass)，未配置账号时返回 null。 */
    public String basicAuthValue() {
        if (!hasAuth()) return null;
        String raw = username + ":" + (password == null ? "" : password);
        return "Basic " + java.util.Base64.getEncoder()
                .encodeToString(raw.getBytes(java.nio.charset.StandardCharsets.UTF_8));
    }

    /**
     * 允许把凭据直接写在地址里（http://user:pass@host:8000），保存时拆出来，
     * 避免用户名密码以明文形式留在 URL 里。
     */
    private void extractUserInfo() {
        String s = serverUrl == null ? "" : serverUrl.trim();
        int scheme = s.indexOf("://");
        if (scheme < 0) return;
        int authStart = scheme + 3;
        int at = s.indexOf('@', authStart);
        if (at < 0) return;
        int slash = s.indexOf('/', authStart);
        if (slash >= 0 && slash < at) return;
        String userInfo = s.substring(authStart, at);
        int colon = userInfo.indexOf(':');
        if (colon < 0) {
            username = userInfo;
            password = "";
        } else {
            username = userInfo.substring(0, colon);
            password = userInfo.substring(colon + 1);
        }
        serverUrl = s.substring(0, authStart) + s.substring(at + 1);
    }

    public List<String> headerNames() {
        List<String> out = new ArrayList<>();
        for (String s : headers.split(",")) {
            String h = s.trim();
            if (!h.isEmpty() && !out.contains(h)) out.add(h);
        }
        return out;
    }

    public String baseUrl() {
        String s = serverUrl == null ? "" : serverUrl.trim();
        while (s.endsWith("/")) s = s.substring(0, s.length() - 1);
        return s;
    }

    public void updateFrom(Config other) {
        this.serverUrl = other.serverUrl;
        this.token = other.token;
        this.subdomain = other.subdomain;
        this.headers = other.headers;
        this.injectParams = other.injectParams;
        this.pollSeconds = other.pollSeconds;
        this.scopeOnly = other.scopeOnly;
        this.skipStatic = other.skipStatic;
        this.username = other.username;
        this.password = other.password;
        save();
    }
}
