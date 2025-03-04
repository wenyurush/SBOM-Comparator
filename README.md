# SBOM Comparison Tool

## Introduction

This is a Python script for comparing two CycloneDX SBOM (Software Bill of Materials) files. It can detect added, removed, version-changed, and license-changed components, and generate a detailed comparison report.

## Features

- Compare two SBOM files to identify added, removed, version-changed, and license-changed components.
- Support debug output for troubleshooting.
- Optionally ignore version changes and focus only on component additions and removals.
- Optionally focus on license changes.
- Generate a formatted comparison report that can be saved to a file.

## Usage

### Command-line Arguments

```bash
python3 sbom_comparison.py --old <old SBOM file> --new <new SBOM file> [other options]
```

| Argument | Description |
|----------|-------------|
| `--old` | Path to the old SBOM file |
| `--new` | Path to the new SBOM file |
| `--output` | Path to the output file (optional) |
| `--debug` | Enable debug output |
| `--deep-debug` | Enable deep debug (generate component list files) |
| `--ignore-version` | Ignore version changes and only report added and removed components |
| `--license-focus` | Focus on license changes |

### Example

```bash
python3 sbom_comparison.py --old old_sbom.json --new new_sbom.json --output comparison_report.txt
```

This will compare `old_sbom.json` and `new_sbom.json` and save the result to `comparison_report.txt`.

## Output Format

The comparison report includes the following sections:

- **Summary of Changes**: Displays the changes in the total number of components, the number of added components, removed components, version changes, and license changes.
- **Version Changes**: Lists components with version changes and their old and new versions.
- **Added Components**: Lists components that are newly added in the new SBOM.
- **Removed Components**: Lists components that exist in the old SBOM but are removed in the new SBOM.
- **License Changes**: Lists components with license changes and their old and new licenses.

## Notes

- Ensure that the input SBOM files are in valid CycloneDX JSON format.
- If the deep debug feature is used, `old_components.txt` and `new_components.txt` files will be generated in the current directory, containing detailed information about the components.
