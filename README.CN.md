# SBOM 比较工具

## 简介

这是一个用于比较两个 CycloneDX SBOM（软件物料清单）文件的 Python 脚本。它能够检测组件的新增、移除、版本变更和许可证变更，并生成详细的比较报告。

## 功能

- 比较两个 SBOM 文件，识别新增、移除、版本变更和许可证变更的组件。
- 支持调试输出，便于排查问题。
- 可选地忽略版本变更，只关注组件的新增和移除。
- 可选地重点关注许可证变更。
- 生成格式化的比较报告，支持保存到文件。

## 使用方法

### 命令行参数

```bash
python3 sbom_comparison.py --old <旧SBOM文件> --new <新SBOM文件> [其他选项]
```

| 参数 | 描述 |
|------|------|
| `--old` | 旧的 SBOM 文件路径 |
| `--new` | 新的 SBOM 文件路径 |
| `--output` | 输出文件路径（可选） |
| `--debug` | 启用调试输出 |
| `--deep-debug` | 启用深度调试（生成组件列表文件） |
| `--ignore-version` | 忽略版本变更，只报告组件的新增和移除 |
| `--license-focus` | 重点关注许可证变更 |

### 示例

```bash
python3 sbom_comparison.py --old old_sbom.json --new new_sbom.json --output comparison_report.txt
```

这将比较 `old_sbom.json` 和 `new_sbom.json`，并将结果保存到 `comparison_report.txt` 文件中。

## 输出格式

比较报告包含以下部分：

- **变更摘要**：显示总组件数的变化、新增组件数、移除组件数、版本变更数和许可证变更数。
- **版本变更**：列出版本发生变更的组件及其新旧版本。
- **新增组件**：列出在新 SBOM 中新增的组件。
- **移除组件**：列出在旧 SBOM 中存在但在新 SBOM 中移除的组件。
- **许可证变更**：列出许可证发生变更的组件及其新旧许可证。

## 注意事项

- 确保输入的 SBOM 文件是有效的 CycloneDX JSON 格式。
- 如果使用深度调试功能，会在当前目录下生成 `old_components.txt` 和 `new_components.txt` 文件，包含组件的详细信息。
