// Build: dotnet new console -n PcapngHist && replace Program.cs with this file
// Run:   dotnet run -- <path-to.pcapng> [options]
//        See usage for all available options.
//
// Requires NuGet package:
//   dotnet add package Haukcode.PcapngUtils

using Haukcode.PcapngUtils;
using Haukcode.PcapngUtils.Common;
using System;
using System.Collections.Generic;
using System.Globalization;
using System.IO;
using System.Linq;
using System.Text;
using System.Text.Json;
using System.Text.Json.Serialization;
using System.Threading;

internal static class Program
{
    private enum Mode { Bytes, Packets }

    private static int Main(string[] args)
    {
        try
        {
            if (args.Length == 0)
            {
                PrintUsage();
                return 2;
            }

            var path = args[0];
            if (!File.Exists(path))
            {
                Console.Error.WriteLine($"File not found: {path}");
                return 2;
            }
            
            string htmlPath = null;
            var otherArgs = new List<string>();
            var tcpBlacklist = new HashSet<ushort>();
            var udpBlacklist = new HashSet<ushort>();
            var ipBlacklist = new HashSet<string>();

            foreach (var arg in args.Skip(1))
            {
                if (arg.StartsWith("--html=", StringComparison.OrdinalIgnoreCase))
                {
                    htmlPath = arg.Substring("--html=".Length).Trim();
                }
                else if (arg.StartsWith("--blacklist-tcp-ports=", StringComparison.OrdinalIgnoreCase))
                {
                    ParsePortList(arg.Substring("--blacklist-tcp-ports=".Length), tcpBlacklist);
                }
                else if (arg.StartsWith("--blacklist-udp-ports=", StringComparison.OrdinalIgnoreCase))
                {
                    ParsePortList(arg.Substring("--blacklist-udp-ports=".Length), udpBlacklist);
                }
                else if (arg.StartsWith("--blacklist-ips=", StringComparison.OrdinalIgnoreCase))
                {
                    ParseIpList(arg.Substring("--blacklist-ips=".Length), ipBlacklist);
                }
                else
                {
                    otherArgs.Add(arg);
                }
            }

            var mode = ParseMode(otherArgs);

            var hist = new Histogram(mode, tcpBlacklist, udpBlacklist, ipBlacklist);
            using var cts = new CancellationTokenSource();
            Console.CancelKeyPress += (s, e) => { e.Cancel = true; cts.Cancel(); };

            Console.WriteLine($"Analyzing '{path}' in '{mode.ToString().ToLowerInvariant()}' mode. Press Ctrl+C to stop.");

            using var reader = IReaderFactory.GetReader(path);
            reader.OnReadPacketEvent += (s, p) => hist.ProcessPacket(p);
            reader.ReadPackets(cts.Token);

            Console.WriteLine("\nAnalysis complete.");
            hist.Print(Console.Out);

            if (!string.IsNullOrWhiteSpace(htmlPath))
            {
                hist.WriteHtmlReport(htmlPath);
                Console.WriteLine($"\nSuccessfully generated HTML report at: {Path.GetFullPath(htmlPath)}");
            }

            return 0;
        }
        catch (OperationCanceledException)
        {
            Console.Error.WriteLine("\nCanceled.");
            return 130; // SIGINT-like
        }
        catch (Exception ex)
        {
            Console.Error.WriteLine("Error: " + ex.Message);
            return 1;
        }
    }

    private static void ParsePortList(string portString, HashSet<ushort> set)
    {
        var ports = portString.Split(new[] { ',' }, StringSplitOptions.RemoveEmptyEntries);
        foreach (var portStr in ports)
        {
            if (ushort.TryParse(portStr.Trim(), out ushort port))
            {
                set.Add(port);
            }
        }
    }

    private static void ParseIpList(string ipString, HashSet<string> set)
    {
        var ips = ipString.Split(new[] { ',' }, StringSplitOptions.RemoveEmptyEntries);
        foreach (var ip in ips)
        {
            set.Add(ip.Trim());
        }
    }

    private static Mode ParseMode(IEnumerable<string> args)
    {
        foreach (var a in args)
        {
            if (a.StartsWith("--mode=", StringComparison.OrdinalIgnoreCase))
            {
                var v = a.Substring("--mode=".Length).Trim();
                if (v.Equals("bytes", StringComparison.OrdinalIgnoreCase)) return Mode.Bytes;
                if (v.Equals("packets", StringComparison.OrdinalIgnoreCase)) return Mode.Packets;
                Console.Error.WriteLine($"Unknown mode '{v}', defaulting to 'bytes'.");
                return Mode.Bytes;
            }
        }
        return Mode.Bytes;
    }

    private static void PrintUsage()
    {
        Console.WriteLine(@"PCAPNG Flow & IP Histogram
Usage:
  PcapngHist <path-to.pcapng> [options]

Description:
  Computes histograms and generates an interactive HTML report.

Options:
  --mode=<bytes|packets>          - Set analysis mode. Default: bytes.
  --html=<report.html>            - Path to generate the HTML report.
  --blacklist-tcp-ports=<p1,p2>   - Comma-separated TCP ports to ignore.
  --blacklist-udp-ports=<p1,p2>   - Comma-separated UDP ports to ignore.
  --blacklist-ips=<ip1,ip2>       - Comma-separated source IPs to ignore.

Examples:
  dotnet run -- sample.pcapng --html=report.html
  dotnet run -- sample.pcapng --blacklist-tcp-ports=443 --blacklist-ips=8.8.8.8
");
    }

    private sealed class Histogram
    {
        private readonly Mode _mode;
        private readonly HashSet<ushort> _tcpBlacklist;
        private readonly HashSet<ushort> _udpBlacklist;
        private readonly HashSet<string> _ipBlacklist;

        private struct TimeValue
        {
            [JsonPropertyName("t")] public long T { get; set; } // Timestamp
            [JsonPropertyName("v")] public long V { get; set; } // Value
        }

        private readonly Dictionary<string, List<TimeValue>> _bySrcPort = new();
        private readonly Dictionary<string, List<TimeValue>> _byDstPort = new();
        private readonly Dictionary<string, List<TimeValue>> _bySrcIp = new();
        private readonly Dictionary<string, List<TimeValue>> _byFlow = new();
        private readonly Dictionary<string, List<TimeValue>> _bySrcIpAndPort = new();
        private readonly Dictionary<string, List<TimeValue>> _bySrcIpAndFlow = new();

        public Histogram(Mode mode, HashSet<ushort> tcpBlacklist, HashSet<ushort> udpBlacklist, HashSet<string> ipBlacklist)
        {
            _mode = mode;
            _tcpBlacklist = tcpBlacklist;
            _udpBlacklist = udpBlacklist;
            _ipBlacklist = ipBlacklist;
        }

        public void ProcessPacket(IPacket p)
        {
            var data = p.Data;
            if (data == null || data.Length < 14) return;
            
            long timestamp = (long)p.Seconds * 1000 + p.Microseconds / 1000;
            ushort etherType = ReadU16BE(data, 12);

            if (etherType == 0x0800) ProcessIPv4(data, 14, timestamp);
            else if (etherType == 0x86DD) ProcessIPv6(data, 14, timestamp);
        }

        private void ProcessIPv4(byte[] buf, int ipOffset, long timestamp)
        {
            if (buf.Length < ipOffset + 20) return;
            if (((buf[ipOffset] >> 4) & 0xF) != 4) return;
            int ihl = (buf[ipOffset] & 0xF) * 4;
            if (ihl < 20 || buf.Length < ipOffset + ihl) return;
            ushort totalLen = ReadU16BE(buf, ipOffset + 2);
            if (totalLen < ihl) return;
            byte proto = buf[ipOffset + 9];
            string srcIp = $"{buf[ipOffset + 12]}.{buf[ipOffset + 13]}.{buf[ipOffset + 14]}.{buf[ipOffset + 15]}";
            int l4Offset = ipOffset + ihl;
            int l4Len = totalLen - ihl;
            if (l4Len <= 0) return;

            if ((proto == 6 || proto == 17) && buf.Length >= l4Offset + 4)
            {
                ushort srcPort = ReadU16BE(buf, l4Offset);
                ushort dstPort = ReadU16BE(buf, l4Offset + 2);
                
                if (_ipBlacklist.Contains(srcIp)) return;
                if (proto == 6 && (_tcpBlacklist.Contains(srcPort) || _tcpBlacklist.Contains(dstPort))) return;
                if (proto == 17 && (_udpBlacklist.Contains(srcPort) || _udpBlacklist.Contains(dstPort))) return;

                long value = _mode == Mode.Bytes ? l4Len : 1;
                string protocol = proto == 6 ? "TCP" : "UDP";
                
                Accumulate(_bySrcPort, $"{protocol}/{srcPort}", timestamp, value);
                Accumulate(_byDstPort, $"{protocol}/{dstPort}", timestamp, value);
                Accumulate(_bySrcIp, srcIp, timestamp, value);
                Accumulate(_byFlow, $"{protocol}/{srcPort} -> {dstPort}", timestamp, value);
                Accumulate(_bySrcIpAndPort, $"{srcIp}:{srcPort} ({protocol})", timestamp, value);
                Accumulate(_bySrcIpAndFlow, $"{srcIp} -> {srcPort} -> {dstPort} ({protocol})", timestamp, value);
            }
        }

        private void ProcessIPv6(byte[] buf, int ipOffset, long timestamp)
        {
            if (buf.Length < ipOffset + 40) return;
            if (((buf[ipOffset] >> 4) & 0xF) != 6) return;
            ushort payloadLen = ReadU16BE(buf, ipOffset + 4);
            byte nextHeader = buf[ipOffset + 6];
            string srcIp = ReadIPv6ToString(buf, ipOffset + 8);
            int l4Offset = ipOffset + 40;
            int l4Len = payloadLen;
            if (l4Len <= 0) return;

            if ((nextHeader == 6 || nextHeader == 17) && buf.Length >= l4Offset + 4)
            {
                ushort srcPort = ReadU16BE(buf, l4Offset);
                ushort dstPort = ReadU16BE(buf, l4Offset + 2);

                if (_ipBlacklist.Contains(srcIp)) return;
                if (nextHeader == 6 && (_tcpBlacklist.Contains(srcPort) || _tcpBlacklist.Contains(dstPort))) return;
                if (nextHeader == 17 && (_udpBlacklist.Contains(srcPort) || _udpBlacklist.Contains(dstPort))) return;

                long value = _mode == Mode.Bytes ? l4Len : 1;
                string protocol = nextHeader == 6 ? "TCP" : "UDP";

                Accumulate(_bySrcPort, $"{protocol}/{srcPort}", timestamp, value);
                Accumulate(_byDstPort, $"{protocol}/{dstPort}", timestamp, value);
                Accumulate(_bySrcIp, srcIp, timestamp, value);
                Accumulate(_byFlow, $"{protocol}/{srcPort} -> {dstPort}", timestamp, value);
                Accumulate(_bySrcIpAndPort, $"{srcIp}:{srcPort} ({protocol})", timestamp, value);
                Accumulate(_bySrcIpAndFlow, $"{srcIp} -> {srcPort} -> {dstPort} ({protocol})", timestamp, value);
            }
        }

        private void Accumulate(Dictionary<string, List<TimeValue>> dict, string key, long timestamp, long value)
        {
            if (!dict.TryGetValue(key, out var timeSeries))
            {
                timeSeries = new List<TimeValue>();
                dict[key] = timeSeries;
            }
            timeSeries.Add(new TimeValue { T = timestamp, V = value });
        }

        public void Print(TextWriter tw)
        {
            if (!_byFlow.Any())
            {
                tw.WriteLine("No TCP/UDP packets found to analyze.");
                return;
            }
            var totals = _byFlow.ToDictionary(kv => kv.Key, kv => kv.Value.Sum(v => v.V));
            var grandTotal = totals.Values.Sum();
            
            tw.WriteLine($"\n--- Console Results (Grouped by Flow, Mode: {_mode.ToString().ToLowerInvariant()}) ---");
            foreach (var group in totals.OrderByDescending(kv => kv.Value).ThenBy(kv => kv.Key))
            {
                tw.WriteLine($"\nFlow {group.Key} : {FormatValue(group.Value)} ({Percent(group.Value, grandTotal)} of total)");
            }
        }
        
        public void WriteHtmlReport(string path)
        {
            if (!_byFlow.Any())
            {
                File.WriteAllText(path, "<html><body><h1>No data to display.</h1><p>The capture file contained no packets or all packets were filtered by the blacklist.</p></body></html>");
                return;
            }

            var reportData = new
            {
                srcPort = _bySrcPort,
                dstPort = _byDstPort,
                srcIp = _bySrcIp,
                flow = _byFlow,
                srcIpAndPort = _bySrcIpAndPort,
                srcIpAndFlow = _bySrcIpAndFlow
            };
            
            string jsonData = JsonSerializer.Serialize(new { unit = _mode.ToString().ToLowerInvariant(), data = reportData });
            string htmlContent = GetHtmlTemplate(jsonData);
            File.WriteAllText(path, htmlContent);
        }

        private static string GetHtmlTemplate(string jsonData)
        {
            return $@"<!DOCTYPE html>
<html lang=""en"">
<head>
    <meta charset=""UTF-8"">
    <title>Pcapng Analysis Report</title>
    <script src=""https://cdn.jsdelivr.net/npm/chart.js""></script>
    <script src=""https://cdn.jsdelivr.net/npm/chartjs-adapter-date-fns/dist/chartjs-adapter-date-fns.bundle.min.js""></script>
    <script src=""https://cdn.jsdelivr.net/npm/chartjs-plugin-zoom@2.0.1/dist/chartjs-plugin-zoom.min.js""></script>
    <style>
        body {{ font-family: -apple-system, BlinkMacSystemFont, ""Segoe UI"", Roboto, Helvetica, Arial, sans-serif; margin: 0; background-color: #f8f9fa; color: #212529; }}
        .container {{ max-width: 1200px; margin: 2rem auto; padding: 2rem; background: #fff; border-radius: 8px; box-shadow: 0 4px 6px rgba(0,0,0,0.1); }}
        h1, h2 {{ text-align: center; color: #343a40; }}
        .controls {{ display: flex; justify-content: center; gap: 1.5rem; margin: 1.5rem 0; flex-wrap: wrap; }}
        .controls label {{ display: flex; align-items: center; gap: 0.5rem; cursor: pointer; }}
        .table-container {{ max-height: 600px; overflow-y: auto; border: 1px solid #dee2e6; border-radius: 8px; margin-top: 2rem; }}
        table {{ width: 100%; border-collapse: collapse; }}
        th, td {{ padding: 12px 15px; text-align: left; border-bottom: 1px solid #dee2e6; }}
        th {{ background-color: #f8f9fa; font-weight: 600; position: sticky; top: 0; }}
        tbody tr {{ cursor: pointer; }}
        tbody tr:hover {{ background-color: #e9ecef; }}
        tbody tr.active {{ background-color: #d1e7fd; font-weight: 500; }}
        td:nth-child(2), td:nth-child(3) {{ text-align: right; font-family: monospace, monospace; }}
        #detailContainer {{ margin-top: 3rem; padding-top: 1.5rem; border-top: 1px solid #dee2e6; }}
        #detailChartContainer {{ max-width: 900px; margin: 1rem auto; }}
        .detail-header {{ display: flex; justify-content: center; align-items: center; gap: 1rem; }}
        .reset-zoom-btn {{ padding: 0.25rem 0.75rem; font-size: 0.8rem; border-radius: 4px; border: 1px solid #0d6efd; background-color: #fff; color: #0d6efd; cursor: pointer; }}
        .reset-zoom-btn:hover {{ background-color: #e9ecef; }}
    </style>
</head>
<body>
<div class=""container"">
    <h1>Traffic Analysis</h1>
    <div class=""controls"">
        <label><input type=""radio"" name=""grouping"" value=""srcPort"" onchange=""updateView()""> Source Port</label>
        <label><input type=""radio"" name=""grouping"" value=""dstPort"" onchange=""updateView()""> Destination Port</label>
        <label><input type=""radio"" name=""grouping"" value=""srcIp"" onchange=""updateView()""> Source IP</label>
        <label><input type=""radio"" name=""grouping"" value=""flow"" onchange=""updateView()"" checked> Flow</label>
        <label><input type=""radio"" name=""grouping"" value=""srcIpAndPort"" onchange=""updateView()""> Source IP & Port</label>
        <label><input type=""radio"" name=""grouping"" value=""srcIpAndFlow"" onchange=""updateView()""> Source IP & Flow</label>
    </div>
    <h2 id=""tableTitle""></h2>
    <div class=""table-container""><table id=""mainTable""><thead></thead><tbody></tbody></table></div>
    <div id=""detailContainer"" style=""display:none;"">
        <div class=""detail-header"">
            <h2 id=""detailTitle""></h2>
            <button class=""reset-zoom-btn"" onclick=""resetDetailChartZoom()"">Reset Zoom</button>
        </div>
        <div id=""detailChartContainer""><canvas id=""detailChart""></canvas></div>
    </div>
</div>
<script>
    const report = {jsonData};
    const unit = report.unit;
    const datasets = report.data;
    let detailChartInstance = null;
    let currentGroupedData = [];

    const groupTitles = {{
        srcPort: 'Source Port',
        dstPort: 'Destination Port',
        srcIp: 'Source IP',
        flow: 'Flow (Source → Destination)',
        srcIpAndPort: 'Source IP & Port',
        srcIpAndFlow: 'Source IP & Flow'
    }};

    function updateView() {{
        const mode = document.querySelector('input[name=""grouping""]:checked').value;
        const dataForMode = datasets[mode];

        currentGroupedData = Object.keys(dataForMode).map(key => {{
            const timeSeries = dataForMode[key];
            const total = timeSeries.reduce((sum, item) => sum + item.v, 0);
            return {{ key, total, timeSeries }};
        }}).sort((a, b) => b.total - a.total);

        renderTable(mode);
        document.getElementById('detailContainer').style.display = 'none';
        if (detailChartInstance) {{ detailChartInstance.destroy(); }}
    }}

    function renderTable(mode) {{
        const table = document.getElementById('mainTable');
        const thead = table.querySelector('thead');
        const tbody = table.querySelector('tbody');
        
        document.getElementById('tableTitle').innerText = `Traffic by ${{groupTitles[mode]}}`;
        thead.innerHTML = `<tr><th>${{groupTitles[mode]}}</th><th>Total (${{unit}})</th><th>% of Grand Total</th></tr>`;
        tbody.innerHTML = '';

        const grandTotal = currentGroupedData.reduce((sum, d) => sum + d.total, 0);

        currentGroupedData.forEach((group, index) => {{
            const tr = document.createElement('tr');
            const percentOfTotal = grandTotal > 0 ? (group.total / grandTotal * 100).toFixed(2) : 0;
            tr.innerHTML = `<td>${{group.key}}</td><td>${{group.total.toLocaleString()}}</td><td>${{percentOfTotal}}%</td>`;
            tr.onclick = () => {{
                document.querySelectorAll('#mainTable tbody tr').forEach(row => row.classList.remove('active'));
                tr.classList.add('active');
                showDetail(group.key, group.timeSeries, mode);
            }};
            tbody.appendChild(tr);
        }});
    }}

    function showDetail(key, timeSeries, mode) {{
        document.getElementById('detailContainer').style.display = 'block';
        document.getElementById('detailTitle').innerText = `Traffic Over Time for ${{groupTitles[mode]}}: ${{key}}`;
        
        const detailCtx = document.getElementById('detailChart').getContext('2d');
        if (detailChartInstance) {{ detailChartInstance.destroy(); }}

        detailChartInstance = new Chart(detailCtx, {{
            type: 'line',
            data: {{
                datasets: [{{
                    label: `Traffic (${{unit}})`,
                    data: timeSeries.map(d => ({{x: d.t, y: d.v}})),
                    borderColor: 'rgb(75, 192, 192)',
                    tension: 0.1,
                    pointRadius: 0
                }}]
            }},
            options: {{
                responsive: true,
                scales: {{
                    x: {{ type: 'time', time: {{ unit: 'second' }} }},
                    y: {{ beginAtZero: true, ticks: {{ callback: value => value.toLocaleString() }} }}
                }},
                plugins: {{
                    legend: {{ display: false }},
                    zoom: {{
                        pan: {{
                            enabled: true,
                            mode: 'x'
                        }},
                        zoom: {{
                            wheel: {{ enabled: true }},
                            pinch: {{ enabled: true }},
                            mode: 'x'
                        }}
                    }}
                }}
            }}
        }});
        document.getElementById('detailContainer').scrollIntoView({{ behavior: 'smooth', block: 'start' }});
    }}
    
    function resetDetailChartZoom() {{
        if(detailChartInstance) {{
            detailChartInstance.resetZoom();
        }}
    }}

    document.addEventListener('DOMContentLoaded', updateView);
</script>
</body>
</html>";
        }

        private static string FormatValue(long v) => v.ToString("N0", CultureInfo.InvariantCulture);
        private static string Percent(long part, long total) => total <= 0 ? "0.00%" : ((double)part / total).ToString("0.00%", CultureInfo.InvariantCulture);
        private static ushort ReadU16BE(byte[] b, int off) => off + 1 >= b.Length ? (ushort)0 : (ushort)((b[off] << 8) | b[off + 1]);
        private static string ReadIPv6ToString(byte[] b, int off)
        {
            if (off + 15 >= b.Length) return "::";
            Span<ushort> blocks = stackalloc ushort[8];
            for (int i = 0; i < 8; i++)
                blocks[i] = (ushort)((b[off + 2 * i] << 8) | b[off + 2 * i + 1]);
            return string.Join(":", blocks.ToArray().Select(x => x.ToString("x", CultureInfo.InvariantCulture)));
        }
    }
}

