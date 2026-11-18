# DNSlog Everywhere 回环自测服务器
#
# 作用：在本机监听一个端口，接收 Burp 转发过来的请求，
#       1) 打印请求行与请求头，确认注入确实生效；
#       2) 把请求头里出现的 *.<DnsSuffix> 域名真实解析一次，
#          让 DNSlog 服务端立刻收到查询，从而在扩展表格里命中。
#
# 用法：
#   powershell -ExecutionPolicy Bypass -File tools\loopback-test.ps1 -DnsSuffix dnslog.example.com
#   然后把浏览器代理指向 Burp，访问 http://127.0.0.1:8888/anything
#
# 注意：本文件必须保存为 UTF-8 with BOM，否则 Windows PowerShell 5.1
#       会按 ANSI 读取中文注释，导致语法错误。

param(
    [int]$Port = 8888,
    [string]$DnsSuffix = "dnslog.example.com"
)

$ErrorActionPreference = 'Stop'
$listener = New-Object System.Net.Sockets.TcpListener -ArgumentList @([System.Net.IPAddress]::Loopback, $Port)
$listener.Start()
Write-Host "== 回环测试服务器已启动: http://127.0.0.1:$Port/ ==" -ForegroundColor Green
Write-Host "   监听后缀: *.$DnsSuffix"
Write-Host "   在 Burp 里请求 http://127.0.0.1:$Port/，看下面的输出；Ctrl+C 结束。`n"

$domainRe = [regex]::new("([a-z0-9]{8,})\." + [regex]::Escape($DnsSuffix), 'IgnoreCase')

while ($true) {
    $client = $listener.AcceptTcpClient()
    try {
        $client.ReceiveTimeout = 5000
        $stream = $client.GetStream()
        $buf = New-Object byte[] 8192
        $sb = New-Object System.Text.StringBuilder
        $deadline = (Get-Date).AddSeconds(5)

        # 读到请求头结束（\r\n\r\n）
        while ((Get-Date) -lt $deadline) {
            if (-not $stream.DataAvailable) { Start-Sleep -Milliseconds 20; continue }
            $n = $stream.Read($buf, 0, $buf.Length)
            if ($n -le 0) { break }
            [void]$sb.Append([System.Text.Encoding]::UTF8.GetString($buf, 0, $n))
            if ($sb.ToString().Contains("`r`n`r`n")) { break }
        }

        $raw = $sb.ToString()
        $lines = $raw -split "`r`n"
        $first = if ($lines.Count -gt 0) { $lines[0] } else { "(空请求)" }
        $stamp = (Get-Date).ToString("HH:mm:ss")

        Write-Host "[$stamp] $first" -ForegroundColor Cyan

        $found = @()
        $headers = @()
        foreach ($line in $lines) {
            if ($line -match '^([A-Za-z0-9\-]+):\s*(.*)$') {
                $headers += $line
                $value = $Matches[2]
                foreach ($m in $domainRe.Matches($value)) {
                    $found += $m.Groups[0].Value
                }
            }
        }

        $found = $found | Select-Object -Unique
        if ($found.Count -eq 0) {
            Write-Host "    没在请求头里发现 *.$DnsSuffix（注入没生效？检查插件是否暂停/Scope 过滤/静态后缀跳过）" -ForegroundColor Yellow
        }
        else {
            foreach ($d in $found) {
                Write-Host "    注入域名: $d" -ForegroundColor Green
                try {
                    $r = Resolve-DnsName -Name $d -Type A -ErrorAction Stop -QuickTimeout
                    $ips = ($r | Where-Object { $_.IPAddress } | ForEach-Object { $_.IPAddress }) -join ','
                    Write-Host "      解析结果: $ips  (DNSlog 服务端应已收到这条查询)" -ForegroundColor DarkGreen
                }
                catch {
                    Write-Host "      解析失败: $($_.Exception.Message)" -ForegroundColor DarkYellow
                }
            }
        }

        # 回显请求头，方便直接确认注入内容
        $body = "收到请求: $first`n`n" + ($headers -join "`n") + "`n"
        $bodyBytes = [System.Text.Encoding]::UTF8.GetBytes($body)
        $head = "HTTP/1.1 200 OK`r`nContent-Type: text/plain; charset=utf-8`r`nContent-Length: $($bodyBytes.Length)`r`nConnection: close`r`n`r`n"
        $headBytes = [System.Text.Encoding]::ASCII.GetBytes($head)
        $stream.Write($headBytes, 0, $headBytes.Length)
        $stream.Write($bodyBytes, 0, $bodyBytes.Length)
        $stream.Flush()
    }
    catch {
        Write-Host "    处理出错: $($_.Exception.Message)" -ForegroundColor Red
    }
    finally {
        $client.Close()
    }
}
