package dnslogeverywhere;

import burp.api.montoya.MontoyaApi;

import javax.swing.*;
import javax.swing.table.AbstractTableModel;
import java.awt.*;
import java.awt.datatransfer.StringSelection;
import java.awt.event.MouseAdapter;
import java.awt.event.MouseEvent;
import java.text.SimpleDateFormat;
import java.util.ArrayList;
import java.util.Date;
import java.util.List;
import java.util.concurrent.Executors;
import java.util.concurrent.ScheduledExecutorService;
import java.util.concurrent.TimeUnit;

/**
 * Burp 顶部独立 Tab：上面配置，中间命中表格，下面状态栏。
 */
public final class DnslogTab extends JPanel {

    private final MontoyaApi api;
    private final Config cfg;
    private final Store store;
    private final DnslogClient client;
    private final InjectionHandler handler;

    private final JTextField serverField = new JTextField(28);
    private final JTextField tokenField = new JTextField(28);
    private final JTextField subField = new JTextField(28);
    private final JTextField userField = new JTextField(28);
    private final JPasswordField passField = new JPasswordField(28);
    private final JTextField headersField = new JTextField(60);
    private final JCheckBox paramsBox = new JCheckBox("注入 URL/POST 参数（噪声大，默认关）");
    private final JCheckBox scopeBox = new JCheckBox("仅 Scope 内");
    private final JCheckBox staticBox = new JCheckBox("跳过静态资源");
    private final JSpinner intervalSpinner = new JSpinner(new SpinnerNumberModel(8, 3, 120, 1));
    private final JLabel statusLabel = new JLabel(" ");
    private final JButton toggleBtn = new JButton("暂停注入");

    private final HitTableModel model = new HitTableModel();
    private final JTable table = new JTable(model);

    private final ScheduledExecutorService exec = Executors.newSingleThreadScheduledExecutor(r -> {
        Thread t = new Thread(r, "dnslog-everywhere-poll");
        t.setDaemon(true);
        return t;
    });

    private volatile long lastPollAt;
    private volatile String lastError = "";
    private volatile boolean polling;

    public DnslogTab(MontoyaApi api, Config cfg, Store store, DnslogClient client, InjectionHandler handler) {
        super(new BorderLayout(6, 6));
        this.api = api;
        this.cfg = cfg;
        this.store = store;
        this.client = client;
        this.handler = handler;

        add(buildConfigPanel(), BorderLayout.NORTH);
        add(buildTablePanel(), BorderLayout.CENTER);
        add(buildStatusBar(), BorderLayout.SOUTH);

        loadFields();
        bindLiveUpdates();
        toggleBtn.addActionListener(e -> toggleInjection());
        exec.scheduleWithFixedDelay(this::tick, 4, 3, TimeUnit.SECONDS);
    }

    // ---------------------------------------------------------------- UI

    private JComponent buildConfigPanel() {
        JPanel p = new JPanel(new GridBagLayout());
        p.setBorder(BorderFactory.createTitledBorder("DNSlog-GO 配置"));
        GridBagConstraints c = new GridBagConstraints();
        c.insets = new Insets(3, 4, 3, 4);
        c.anchor = GridBagConstraints.WEST;
        c.fill = GridBagConstraints.HORIZONTAL;

        int row = 0;
        addRow(p, c, row++, "服务器地址", serverField, "http:// 或 https:// 均可，末尾不要带 /");
        addRow(p, c, row++, "Token", tokenField, "DNSlog-GO 后台生成的 token");
        addRow(p, c, row++, "子域后缀", subField, "例如 abc.example.com，标识会拼在它前面");
        addRow(p, c, row++, "账号(可选)", userField, "服务器加了 Basic Auth 才填");
        addRow(p, c, row++, "密码(可选)", passField, "填了账号就必须填密码");
        addRow(p, c, row++, "注入头", headersField, "英文逗号分隔");

        JPanel opts = new JPanel(new FlowLayout(FlowLayout.LEFT, 10, 0));
        opts.add(new JLabel("轮询间隔(秒)"));
        opts.add(intervalSpinner);
        opts.add(scopeBox);
        opts.add(staticBox);
        opts.add(paramsBox);
        c.gridx = 1;
        c.gridy = row;
        c.gridwidth = 2;
        p.add(opts, c);

        JPanel buttons = new JPanel(new FlowLayout(FlowLayout.LEFT, 8, 4));
        JButton save = new JButton("保存配置");
        JButton test = new JButton("测试连接");
        JButton clear = new JButton("清空记录");
        save.addActionListener(e -> saveConfig());
        test.addActionListener(e -> testConnection());
        clear.addActionListener(e -> {
            store.clear();
            model.refresh();
            updateStatus("已清空");
        });
        buttons.add(save);
        buttons.add(test);
        buttons.add(toggleBtn);
        buttons.add(clear);

        c.gridx = 0;
        c.gridy = ++row;
        c.gridwidth = 3;
        p.add(buttons, c);
        return p;
    }

    private void addRow(JPanel p, GridBagConstraints c, int row, String label, JTextField field, String tip) {
        c.gridy = row;
        c.gridx = 0;
        c.weightx = 0;
        c.gridwidth = 1;
        p.add(new JLabel(label), c);
        c.gridx = 1;
        c.weightx = 1;
        field.setToolTipText(tip);
        p.add(field, c);
        c.gridx = 2;
        c.weightx = 0;
        p.add(new JLabel(tip), c);
    }

    private JComponent buildTablePanel() {
        table.setAutoCreateRowSorter(true);
        table.setFillsViewportHeight(true);
        table.setRowHeight(22);
        table.getColumnModel().getColumn(0).setPreferredWidth(90);
        table.getColumnModel().getColumn(1).setPreferredWidth(60);
        table.getColumnModel().getColumn(2).setPreferredWidth(420);
        table.getColumnModel().getColumn(3).setPreferredWidth(120);
        table.getColumnModel().getColumn(4).setPreferredWidth(220);
        table.getColumnModel().getColumn(5).setPreferredWidth(110);

        JPopupMenu popup = new JPopupMenu();
        JMenuItem copyDomain = new JMenuItem("复制回连域名");
        JMenuItem copyUrl = new JMenuItem("复制请求 URL");
        JMenuItem remove = new JMenuItem("删除该行");
        popup.add(copyDomain);
        popup.add(copyUrl);
        popup.addSeparator();
        popup.add(remove);

        copyDomain.addActionListener(e -> copySelected(4));
        copyUrl.addActionListener(e -> copySelected(2));
        remove.addActionListener(e -> {
            int r = table.getSelectedRow();
            if (r < 0) return;
            Hit h = model.get(table.convertRowIndexToModel(r));
            if (h != null) {
                store.remove(h);
                model.refresh();
                updateStatus("已删除一条记录");
            }
        });

        table.addMouseListener(new MouseAdapter() {
            @Override
            public void mousePressed(MouseEvent e) { maybePopup(e); }

            @Override
            public void mouseReleased(MouseEvent e) { maybePopup(e); }

            private void maybePopup(MouseEvent e) {
                if (!e.isPopupTrigger()) return;
                int r = table.rowAtPoint(e.getPoint());
                if (r >= 0) table.setRowSelectionInterval(r, r);
                popup.show(table, e.getX(), e.getY());
            }
        });

        JPanel p = new JPanel(new BorderLayout());
        p.setBorder(BorderFactory.createTitledBorder("回连命中（右键可复制/删除）"));
        p.add(new JScrollPane(table), BorderLayout.CENTER);
        return p;
    }

    private JComponent buildStatusBar() {
        JPanel p = new JPanel(new BorderLayout());
        p.setBorder(BorderFactory.createEmptyBorder(2, 6, 4, 6));
        p.add(statusLabel, BorderLayout.WEST);
        return p;
    }

    // ------------------------------------------------------------- actions

    private void loadFields() {
        serverField.setText(cfg.serverUrl);
        tokenField.setText(cfg.token);
        subField.setText(cfg.subdomain);
        userField.setText(cfg.username);
        passField.setText(cfg.password);
        headersField.setText(cfg.headers);
        intervalSpinner.setValue(cfg.pollSeconds);
        scopeBox.setSelected(cfg.scopeOnly);
        staticBox.setSelected(cfg.skipStatic);
        paramsBox.setSelected(cfg.injectParams);
        toggleBtn.setText(cfg.enabled ? "暂停注入" : "开始注入");
        updateStatus("就绪  v" + DnslogEverywhereExtension.VERSION);
    }

    private void saveConfig() {
        sync();
        cfg.save();
        updateStatus("配置已保存并生效");
    }

    /** 边改边生效：不用点“保存配置”，注入也立刻用最新值（保存只是把值写进 Burp 偏好）。 */
    private void bindLiveUpdates() {
        javax.swing.event.DocumentListener dl = new javax.swing.event.DocumentListener() {
            @Override public void insertUpdate(javax.swing.event.DocumentEvent e) { sync(); }
            @Override public void removeUpdate(javax.swing.event.DocumentEvent e) { sync(); }
            @Override public void changedUpdate(javax.swing.event.DocumentEvent e) { sync(); }
        };
        serverField.getDocument().addDocumentListener(dl);
        tokenField.getDocument().addDocumentListener(dl);
        subField.getDocument().addDocumentListener(dl);
        userField.getDocument().addDocumentListener(dl);
        passField.getDocument().addDocumentListener(dl);
        headersField.getDocument().addDocumentListener(dl);
        intervalSpinner.addChangeListener(e -> sync());
        scopeBox.addItemListener(e -> sync());
        staticBox.addItemListener(e -> sync());
        paramsBox.addItemListener(e -> sync());
    }

    /** 把界面上的值同步进 Config（线程安全：字段都是 volatile）。 */
    private void sync() {
        cfg.serverUrl = serverField.getText().trim();
        cfg.token = tokenField.getText().trim();
        cfg.subdomain = subField.getText().trim();
        cfg.username = userField.getText().trim();
        cfg.password = new String(passField.getPassword());
        cfg.headers = headersField.getText().trim();
        Object v = intervalSpinner.getValue();
        if (v instanceof Integer) cfg.pollSeconds = (Integer) v;
        cfg.scopeOnly = scopeBox.isSelected();
        cfg.skipStatic = staticBox.isSelected();
        cfg.injectParams = paramsBox.isSelected();
    }

    private void toggleInjection() {
        cfg.enabled = !cfg.enabled;
        toggleBtn.setText(cfg.enabled ? "暂停注入" : "开始注入");
        updateStatus(cfg.enabled ? "注入已开启" : "注入已暂停");
    }

    private void testConnection() {
        saveConfig();
        if (cfg.token.isBlank()) {
            JOptionPane.showMessageDialog(this, "请先填 Token", "DNSlog Everywhere", JOptionPane.WARNING_MESSAGE);
            return;
        }
        updateStatus("正在测试连接…");
        Thread t = new Thread(() -> {
            try {
                String sub = client.verifyToken();
                SwingUtilities.invokeLater(() -> {
                    if (subField.getText().isBlank()) {
                        subField.setText(sub);
                        cfg.subdomain = sub;
                        cfg.save();
                    }
                    updateStatus("连接成功，绑定子域：" + sub);
                });
            } catch (Exception ex) {
                SwingUtilities.invokeLater(() -> {
                    updateStatus("连接失败：" + ex.getMessage());
                    JOptionPane.showMessageDialog(DnslogTab.this,
                            "连接失败：\n" + ex.getMessage(), "DNSlog Everywhere", JOptionPane.ERROR_MESSAGE);
                });
            }
        }, "dnslog-test");
        t.setDaemon(true);
        t.start();
    }

    // ------------------------------------------------------------- polling

    private void tick() {
        if (polling) return;
        long interval = Math.max(3, cfg.pollSeconds) * 1000L;
        if (System.currentTimeMillis() - lastPollAt < interval) return;
        lastPollAt = System.currentTimeMillis();
        if (cfg.token.isBlank() || cfg.baseUrl().isEmpty()) {
            updateStatus("等待配置 Token / 服务器地址");
            return;
        }
        polling = true;
        try {
            List<DnslogClient.Entry> entries = client.fetchData();
            boolean any = false;
            for (DnslogClient.Entry e : entries) {
                if (store.onDns(e.subdomain, e.ip, e.time, e.type) != null) any = true;
            }
            lastError = "";
            if (any) SwingUtilities.invokeLater(model::refresh);
            SwingUtilities.invokeLater(() -> updateStatus("轮询正常"));
        } catch (Exception ex) {
            lastError = ex.getMessage() == null ? ex.getClass().getSimpleName() : ex.getMessage();
            SwingUtilities.invokeLater(() -> updateStatus("轮询失败：" + lastError));
        } finally {
            polling = false;
        }
    }

    private void updateStatus(String msg) {
        String skip = handler == null ? null : handler.lastSkip();
        String tail = skip == null ? "  |  正在注入" : "  |  当前跳过：" + skip;
        statusLabel.setText(String.format(
                "%s  |  收到请求 %d  |  注入 %d  |  待回连 %d  |  命中 %d  |  轮询 %s%s",
                msg,
                handler == null ? 0L : handler.seen(),
                store.injected.get(),
                store.pendingSize(),
                store.matched.get(),
                lastPollAt == 0 ? "-" : new SimpleDateFormat("HH:mm:ss").format(new Date(lastPollAt)),
                tail));
    }

    private void copySelected(int col) {
        int r = table.getSelectedRow();
        if (r < 0) return;
        Object v = table.getValueAt(r, col);
        if (v == null) return;
        Toolkit.getDefaultToolkit().getSystemClipboard()
                .setContents(new StringSelection(v.toString()), null);
        updateStatus("已复制");
    }

    // --------------------------------------------------------------- model

    private final class HitTableModel extends AbstractTableModel {

        private final String[] cols = {"时间", "方法", "URL", "触发头", "回连域名", "来源 IP"};
        private final SimpleDateFormat fmt = new SimpleDateFormat("MM-dd HH:mm:ss");
        private List<Hit> rows = new ArrayList<>();

        void refresh() {
            rows = store.hits();
            fireTableDataChanged();
        }

        Hit get(int r) {
            return r >= 0 && r < rows.size() ? rows.get(r) : null;
        }

        @Override public int getRowCount() { return rows.size(); }

        @Override public int getColumnCount() { return cols.length; }

        @Override public String getColumnName(int c) { return cols[c]; }

        @Override public Object getValueAt(int r, int c) {
            Hit h = rows.get(r);
            switch (c) {
                case 0: return fmt.format(new Date(h.injectTime));
                case 1: return h.method;
                case 2: return h.url;
                case 3: return h.header;
                case 4: return h.domain;
                case 5: return h.ip + (h.type == null ? "" : " (" + h.type + ")");
                default: return "";
            }
        }
    }
}
