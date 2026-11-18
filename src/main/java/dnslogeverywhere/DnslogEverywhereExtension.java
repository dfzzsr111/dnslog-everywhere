package dnslogeverywhere;

import burp.api.montoya.BurpExtension;
import burp.api.montoya.MontoyaApi;

/**
 * 入口类。Burp 加载 jar 时会扫描实现 BurpExtension 的类并调用 initialize。
 */
public final class DnslogEverywhereExtension implements BurpExtension {

    /** 每次改代码都动它，用来确认 Burp 里跑的是不是最新 jar。 */
    public static final String VERSION = "1.4";

    @Override
    public void initialize(MontoyaApi api) {
        api.extension().setName("DNSlog Everywhere");

        Config cfg = new Config(api.persistence().preferences());
        Store store = new Store();
        DnslogClient client = new DnslogClient(cfg);
        InjectionHandler handler = new InjectionHandler(cfg, store);

        DnslogTab tab = new DnslogTab(api, cfg, store, client, handler);
        api.userInterface().registerSuiteTab("DNSlog", tab);
        api.userInterface().applyThemeToComponent(tab);

        api.http().registerHttpHandler(handler);

        api.logging().logToOutput("DNSlog Everywhere v" + VERSION + " loaded. file=" + safeFilename(api)
                + " server=" + cfg.baseUrl()
                + " subdomain=" + (cfg.subdomain.isEmpty() ? "(unset)" : cfg.subdomain));
    }

    private static String safeFilename(MontoyaApi api) {
        try {
            String f = api.extension().filename();
            return f == null || f.isEmpty() ? "(unknown)" : f;
        } catch (RuntimeException ex) {
            return "(unknown)";
        }
    }
}
