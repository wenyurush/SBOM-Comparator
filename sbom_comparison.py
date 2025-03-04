#!/usr/bin/env python3
import json
import argparse
import datetime
import os.path
from dataclasses import dataclass
from typing import Dict, List, Set, Optional, Tuple
import re
import sys

@dataclass
class Component:
    name: str
    group: Optional[str]
    version: str
    purl: Optional[str]
    license: Optional[str]
    
    @property
    def base_purl(self) -> Optional[str]:
        """返回不包含版本号的PURL"""
        if not self.purl:
            return None
        # 使用正则表达式去除版本部分
        return re.sub(r'@[^?#]+', '', self.purl)
    
    @property
    def identifier(self) -> str:
        """返回组件的唯一标识符（不含版本）"""
        if self.purl:
            base = self.base_purl
            return base if base else self.purl.split('@')[0]
        if self.group:
            return f"{self.group}:{self.name}"
        return self.name

    @property
    def full_identifier(self) -> str:
        """返回包含版本的完整标识符"""
        if self.purl:
            return self.purl
        if self.group:
            return f"{self.group}:{self.name}:{self.version}"
        return f"{self.name}:{self.version}"

def load_cyclonedx(file_path: str) -> Dict:
    """加载 CycloneDX JSON 文件"""
    with open(file_path, 'r') as file:
        return json.load(file)

def extract_components(sbom: Dict) -> Dict[str, Component]:
    """从 SBOM 中提取组件信息"""
    components = {}
    
    for comp in sbom.get('components', []):
        name = comp.get('name', '')
        group = comp.get('group')
        version = comp.get('version', '')
        purl = comp.get('purl')
        
        # 处理许可证信息
        license_info = None
        if 'licenses' in comp and comp['licenses']:
            if 'license' in comp['licenses'][0]:
                license_info = comp['licenses'][0]['license'].get('id') or comp['licenses'][0]['license'].get('name')
            elif 'expression' in comp['licenses'][0]:
                license_info = comp['licenses'][0]['expression']
        
        component = Component(
            name=name,
            group=group,
            version=version,
            purl=purl,
            license=license_info
        )
        
        components[component.full_identifier] = component
    
    return components

def group_components_by_base_id(components: Dict[str, Component]) -> Dict[str, List[Component]]:
    """将组件按基本标识符分组"""
    grouped = {}
    
    for comp in components.values():
        base_id = comp.identifier
        if base_id not in grouped:
            grouped[base_id] = []
        grouped[base_id].append(comp)
    
    return grouped

def compare_sboms(old_components: Dict[str, Component], new_components: Dict[str, Component], debug=False):
    """改进的SBOM比较逻辑，更准确地区分新增、删除和版本变更"""
    # 按基本标识符分组
    old_grouped = group_components_by_base_id(old_components)
    new_grouped = group_components_by_base_id(new_components)
    
    # 所有基本标识符的并集
    all_base_ids = set(old_grouped.keys()).union(set(new_grouped.keys()))
    
    if debug:
        print(f"DEBUG: 基本ID总数: {len(all_base_ids)}")
        print(f"DEBUG: 旧SBOM基本ID数: {len(old_grouped)}")
        print(f"DEBUG: 新SBOM基本ID数: {len(new_grouped)}")
    
    # 初始化结果容器
    truly_added = []  # 真正新增的组件（基本ID在新SBOM中但不在旧SBOM中）
    truly_removed = []  # 真正移除的组件（基本ID在旧SBOM中但不在新SBOM中）
    version_changed = {}  # 版本变更的组件
    license_changed = {}  # 许可证变更的组件
    
    # 遍历所有基本ID
    for base_id in all_base_ids:
        old_comps = old_grouped.get(base_id, [])
        new_comps = new_grouped.get(base_id, [])
        
        # 组件在新SBOM中但不在旧SBOM中 -> 真正新增
        if not old_comps and new_comps:
            for comp in new_comps:
                truly_added.append(comp)
            continue
            
        # 组件在旧SBOM中但不在新SBOM中 -> 真正移除
        if old_comps and not new_comps:
            for comp in old_comps:
                truly_removed.append(comp)
            continue
        
        # 组件在两者中都存在，检查版本和许可证变更
        # 简化：只比较每个组的第一个组件
        if old_comps and new_comps:
            old_comp = old_comps[0]
            new_comp = new_comps[0]
            
            # 版本变更
            if old_comp.version != new_comp.version:
                version_changed[base_id] = (old_comp, new_comp)
                if debug:
                    print(f"DEBUG: 版本变更: {base_id} {old_comp.version} -> {new_comp.version}")
            
            # 许可证变更
            if old_comp.license != new_comp.license:
                license_changed[base_id] = (old_comp, new_comp)
                if debug:
                    print(f"DEBUG: 许可证变更: {base_id} {old_comp.license or '无'} -> {new_comp.license or '无'}")
    
    return {
        'added': truly_added,
        'removed': truly_removed,
        'version_changed': version_changed,
        'license_changed': license_changed
    }

def format_output(comparison_result: Dict, old_components: Dict[str, Component], new_components: Dict[str, Component], old_file: str, new_file: str):
    """格式化比较结果输出"""
    now = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    output = []
    
    # 添加比较信息
    output.append(f"# SBOM 比较报告")
    output.append(f"- 生成时间: {now}")
    output.append(f"- 旧版本 SBOM: {os.path.basename(old_file)}")
    output.append(f"- 新版本 SBOM: {os.path.basename(new_file)}")
    output.append("")
    
    # 统计摘要（放在前面，便于快速了解变更概况）
    output.append("## 变更摘要")
    output.append(f"- 总组件数: {len(old_components)} -> {len(new_components)} (变化: {len(new_components) - len(old_components)})")
    output.append(f"- 新增组件: {len(comparison_result['added'])}")
    output.append(f"- 移除组件: {len(comparison_result['removed'])}")
    output.append(f"- 版本变更: {len(comparison_result['version_changed'])}")
    output.append(f"- 许可证变更: {len(comparison_result['license_changed'])}")
    output.append("")
    
    # 版本变更（通常更关注版本变更，因此放在前面）
    if comparison_result['version_changed']:
        output.append("## 版本变更")
        for base_id, (old_comp, new_comp) in comparison_result['version_changed'].items():
            output.append(f"- **{base_id}**: {old_comp.version} -> {new_comp.version} ({old_comp.full_identifier} -> {new_comp.full_identifier})")
        output.append("")
    
    # 新增组件
    if comparison_result['added']:
        output.append("## 新增组件")
        for comp in comparison_result['added']:
            output.append(f"- **{comp.full_identifier}** (版本: {comp.version}, 许可证: {comp.license or '未指定'})")
        output.append("")
    
    # 移除组件
    if comparison_result['removed']:
        output.append("## 移除组件")
        for comp in comparison_result['removed']:
            output.append(f"- **{comp.full_identifier}** (版本: {comp.version}, 许可证: {comp.license or '未指定'})")
        output.append("")
    
    # 许可证变更
    if comparison_result['license_changed']:
        output.append("## 许可证变更")
        for base_id, (old_comp, new_comp) in comparison_result['license_changed'].items():
            output.append(f"- **{new_comp.full_identifier}**: {old_comp.license or '未指定'} -> {new_comp.license or '未指定'}")
    
    return "\n".join(output)

def create_component_list_file(components, filename):
    """创建组件列表文件，用于调试"""
    with open(filename, 'w') as f:
        for comp_id, comp in components.items():
            f.write(f"{comp_id}\t{comp.identifier}\t{comp.version}\t{comp.license or '无许可证'}\n")
    print(f"已将组件列表写入文件 {filename}")

def main():
    parser = argparse.ArgumentParser(description='比较两个 CycloneDX SBOM 文件')
    parser.add_argument('--old', required=True, help='旧的 SBOM 文件路径')
    parser.add_argument('--new', required=True, help='新的 SBOM 文件路径')
    parser.add_argument('--output', '-o', help='输出文件路径（可选）')
    parser.add_argument('--debug', action='store_true', help='启用调试输出')
    parser.add_argument('--deep-debug', action='store_true', help='启用深度调试')
    parser.add_argument('--ignore-version', action='store_true', help='忽略版本变更，只报告组件的新增和删除')
    parser.add_argument('--license-focus', action='store_true', help='重点关注许可证变更')
    args = parser.parse_args()
    
    # 加载 SBOM 文件
    try:
        old_sbom = load_cyclonedx(args.old)
        new_sbom = load_cyclonedx(args.new)
    except Exception as e:
        print(f"错误: 无法加载SBOM文件: {e}")
        return
    
    # 提取组件信息
    old_components = extract_components(old_sbom)
    new_components = extract_components(new_sbom)
    
    if args.debug:
        print(f"DEBUG: 旧SBOM组件数: {len(old_components)}")
        print(f"DEBUG: 新SBOM组件数: {len(new_components)}")
    
    if args.deep_debug:
        # 将组件列表写入文件进行深度调试
        create_component_list_file(old_components, "old_components.txt")
        create_component_list_file(new_components, "new_components.txt")
    
    # 比较 SBOM
    comparison_result = compare_sboms(old_components, new_components, args.debug)
    
    if args.debug:
        print(f"DEBUG: 真正新增组件: {len(comparison_result['added'])}")
        print(f"DEBUG: 真正移除组件: {len(comparison_result['removed'])}")
        print(f"DEBUG: 版本变更: {len(comparison_result['version_changed'])}")
        print(f"DEBUG: 许可证变更: {len(comparison_result['license_changed'])}")
    
    # 格式化输出
    output = format_output(comparison_result, old_components, new_components, args.old, args.new)
    
    # 保存或打印结果
    if args.output:
        with open(args.output, 'w') as file:
            file.write(output)
        print(f"比较结果已保存到 {args.output}")
    else:
        print(output)

if __name__ == "__main__":
    main()
