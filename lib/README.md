# lib/

把用于编译的 Burp / Montoya API jar 放到这个目录，`build.ps1` / `build.sh`
会自动使用它（也可以改用 `-BurpJar` 参数或 `BURP_JAR` 环境变量）。

这个目录里的 `*.jar` 已被 `.gitignore` 忽略，**不要**把 Burp 的 jar 提交到仓库。
