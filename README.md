# LeakLens - 敏感信息扫描工具

## 项目介绍

LeakLens是一个高度可配置的Web爬虫工具，用于从目标网站爬取链接并通过正则表达式扫描敏感数据。

## 主要功能

- **Web爬虫**：通过DOM层次结构和正则表达式提取链接
- **域名白名单和黑名单**：支持域名过滤
- **多目标支持**：从文件中输入目标URL
- **本地文件扫描**：支持扫描本地文件和目录
- **可扩展的自定义配置**：头部、代理、超时、cookie、爬取深度、跟随重定向等
- **内置正则表达式**：用于搜索敏感信息
- **YAML格式的灵活配置**
- **WebUI界面**：提供直观的用户界面
- **API端点发现**：自动检测API端点
- **认证状态检测**：检测网站的认证状态
- **IDOR越权测试**：检测IDOR漏洞
- **JWT认证绕过检测**：检测JWT漏洞
- **报告生成**：生成详细的扫描报告
- **深度分析**：使用AI模型进行深度分析

## 系统要求

- 平台：在MacOS、Ubuntu和Windows上测试通过
- Python版本 >= 3.9

## 安装

```bash
pip install leaklens
```

## 更新

```bash
pip install --upgrade leaklens
```

## 基本使用

### 单个目标扫描

```bash
leaklens -u https://example.com
```

### 多个目标扫描

```bash
leaklens -f urls.txt
# urls.txt内容
http://example.com/1
http://example.com/2
http://example.com/3
```

## WebUI界面

启动WebUI服务器：

```bash
python app.py
```

然后访问 http://127.0.0.1:5000 即可使用Web界面。

## 高级功能

### 验证链接状态

使用 `--validate` 选项检查发现链接的状态，这有助于减少结果中的无效链接。

```bash
leaklens -u https://example.com --validate --max-page=10
```

### 深度爬取

默认最大深度设置为1，这意味着只爬取起始URL。要更改此设置，可以通过 `--max-depth <number>` 指定。或者以更简单的方式，使用 `-m 2` 以深度模式运行爬虫，这相当于 `--max-depth 2`。

```bash
leaklens -u https://example.com -m 2
```

### 将结果写入CSV文件

```bash
leaklens -u https://example.com -o result.csv
```

### 域名白名单/黑名单

支持通配符(*)，白名单：

```bash
leaklens -u https://example.com -d *example*
```

黑名单：

```bash
leaklens -u https://example.com -D *.gov
```

### 隐藏正则表达式结果

使用 `-H` 选项隐藏正则表达式匹配结果。只会显示找到的链接。

```bash
leaklens -u https://example.com -H
```

### 从本地文件提取密钥

```bash
leaklens -l <目录或文件>
```

## 自定义配置

内置配置如下。您可以通过 `-i settings.yml` 指定自定义配置。

```yaml
verbose: false
debug: false
loglevel: critical
logpath: log
handler_type: re

proxy: "" # http://127.0.0.1:7890
max_depth: 1 # 0表示无限制
max_page_num: 1000 # 0表示无限制
timeout: 5
follow_redirects: true
workers_num: 1000
headers:
  Accept: "*/*"
  Cookie: ""
  User-Agent: Mozilla/5.0 (Windows NT 10.0; WOW64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/80.0.3987.87 Safari/537.36 SE 2.X MetaSr 1.0
```

## 报告生成

扫描完成后，可以在WebUI中点击"生成报告"按钮生成详细的扫描报告，或者点击"深度分析"按钮使用AI模型进行深度分析。

## 许可证

MIT License
