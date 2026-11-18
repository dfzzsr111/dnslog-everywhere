package dnslogeverywhere;

import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

/**
 * 极简 JSON 解析器，只依赖 JDK。
 * 不用 Burp 的 JsonNode：那个实现遇到缺失字段会直接 NPE，而且离开 Burp 运行时就没法测试。
 * 解析结果：Map / List / String / Double|Long / Boolean / null。
 */
final class MiniJson {

    private final String s;
    private int i;
    private int depth;

    private MiniJson(String s) {
        this.s = s;
    }

    static Object parse(String text) {
        if (text == null) throw new IllegalArgumentException("内容为空");
        MiniJson p = new MiniJson(text);
        p.skipWs();
        Object v = p.readValue();
        p.skipWs();
        if (p.i < p.s.length()) throw new IllegalArgumentException("第 " + p.i + " 个字符后有多余内容");
        return v;
    }

    // ------------------------------------------------------------- 基础读取

    private Object readValue() {
        if (++depth > 64) throw new IllegalArgumentException("JSON 嵌套过深");
        try {
            skipWs();
            if (i >= s.length()) throw new IllegalArgumentException("JSON 意外结束");
            char c = s.charAt(i);
            switch (c) {
                case '{': return readObject();
                case '[': return readArray();
                case '"': return readString();
                case 't': expect("true"); return Boolean.TRUE;
                case 'f': expect("false"); return Boolean.FALSE;
                case 'n': expect("null"); return null;
                default: return readNumber();
            }
        } finally {
            depth--;
        }
    }

    private Map<String, Object> readObject() {
        Map<String, Object> m = new LinkedHashMap<>();
        i++; // {
        skipWs();
        if (peek() == '}') { i++; return m; }
        while (true) {
            skipWs();
            if (peek() != '"') throw new IllegalArgumentException("对象的键必须是字符串 @" + i);
            String k = readString();
            skipWs();
            if (peek() != ':') throw new IllegalArgumentException("缺少冒号 @" + i);
            i++;
            m.put(k, readValue());
            skipWs();
            char c = peek();
            if (c == ',') { i++; continue; }
            if (c == '}') { i++; return m; }
            throw new IllegalArgumentException("对象未闭合 @" + i);
        }
    }

    private List<Object> readArray() {
        List<Object> l = new ArrayList<>();
        i++; // [
        skipWs();
        if (peek() == ']') { i++; return l; }
        while (true) {
            l.add(readValue());
            skipWs();
            char c = peek();
            if (c == ',') { i++; continue; }
            if (c == ']') { i++; return l; }
            throw new IllegalArgumentException("数组未闭合 @" + i);
        }
    }

    private String readString() {
        i++; // "
        StringBuilder sb = new StringBuilder();
        while (true) {
            if (i >= s.length()) throw new IllegalArgumentException("字符串未闭合");
            char c = s.charAt(i++);
            if (c == '"') return sb.toString();
            if (c != '\\') { sb.append(c); continue; }
            if (i >= s.length()) throw new IllegalArgumentException("转义不完整");
            char e = s.charAt(i++);
            switch (e) {
                case '"': sb.append('"'); break;
                case '\\': sb.append('\\'); break;
                case '/': sb.append('/'); break;
                case 'b': sb.append('\b'); break;
                case 'f': sb.append('\f'); break;
                case 'n': sb.append('\n'); break;
                case 'r': sb.append('\r'); break;
                case 't': sb.append('\t'); break;
                case 'u':
                    if (i + 4 > s.length()) throw new IllegalArgumentException("\\u 转义不完整");
                    sb.append((char) Integer.parseInt(s.substring(i, i + 4), 16));
                    i += 4;
                    break;
                default: throw new IllegalArgumentException("非法转义 \\" + e);
            }
        }
    }

    private Object readNumber() {
        int start = i;
        while (i < s.length() && "+-0123456789.eE".indexOf(s.charAt(i)) >= 0) i++;
        if (start == i) throw new IllegalArgumentException("非法字符 '" + s.charAt(start) + "' @" + start);
        String num = s.substring(start, i);
        if (num.indexOf('.') < 0 && num.indexOf('e') < 0 && num.indexOf('E') < 0) {
            try {
                return Long.parseLong(num);
            } catch (NumberFormatException ignored) {
                // 落到 Double
            }
        }
        return Double.parseDouble(num);
    }

    private void expect(String word) {
        if (!s.startsWith(word, i)) throw new IllegalArgumentException("期望 " + word + " @" + i);
        i += word.length();
    }

    private char peek() {
        if (i >= s.length()) throw new IllegalArgumentException("JSON 意外结束");
        return s.charAt(i);
    }

    private void skipWs() {
        while (i < s.length()) {
            char c = s.charAt(i);
            if (c == ' ' || c == '\t' || c == '\n' || c == '\r' || c == '\uFEFF') i++;
            else break;
        }
    }
}
