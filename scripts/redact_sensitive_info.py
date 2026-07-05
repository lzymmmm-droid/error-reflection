#!/usr/bin/env python3
"""
敏感信息自动脱敏脚本
用于在将复盘报告公开发布前，扫描并替换常见敏感字段
"""

import re
import sys
from pathlib import Path

# 脱敏规则：正则表达式 -> 替换模板
REDACTION_RULES = [
    # Windows 用户路径
    (r'C:\\Users\\[^\\]+\\', r'C:\\Users\\<USER>\\'),
    (r'C:\\Users\\<USER>\\', r'<HOME>\\'),

    # Linux/macOS 用户路径
    (r'/home/[^/]+/', r'<HOME>/'),
    (r'/Users/[^/]+/', r'<HOME>/'),

    # 通用环境变量路径
    (r'\$HOME', r'<HOME>'),
    (r'%USERPROFILE%', r'<HOME>'),

    # API Key / Token
    (r'(api[_-]?key|token|secret|password|auth)\s*[=:]\s*[\'\"]?([A-Za-z0-9_\-]{16,})[\'\"]?',
     r'\1=<REDACTED>'),

    # 邮箱
    (r'[\w\.-]+@[\w\.-]+\.\w+', r'<EMAIL>'),

    # 手机号（中国大陆）
    (r'1[3-9]\d{9}', r'<PHONE>'),

    # IPv4 地址（保留格式，但替换内容）
    (r'\b(\d{1,3}\.){3}\d{1,3}\b', r'<IP>'),

    # 内部域名
    (r'[\w-]+\.internal', r'<INTERNAL_DOMAIN>'),
    (r'[\w-]+\.local', r'<LOCAL_DOMAIN>'),

    # 身份证号
    (r'\d{17}[\dXx]', r'<ID_CARD>'),

    # 项目代号/内部命名（可扩展）
    # (r'项目名称：[\u4e00-\u9fa5]+', r'项目名称：<PROJECT>'),
]

# 必须脱敏的文件扩展名
SENSITIVE_EXTENSIONS = {'.md', '.html', '.json', '.yaml', '.yml', '.txt', '.py', '.js', '.ts'}

# 禁止脱敏的文件名（如模板中的占位符本身）
SAFE_PATTERNS = [
    r'<[^>]+>',  # 已经是占位符格式的不再处理
    r'YOUR_API_KEY',
    r'example\.com',
]


def redact_text(text: str) -> tuple[str, list[str]]:
    """对文本进行脱敏处理，返回 (脱敏后文本, 替换记录)"""
    replacements = []

    for pattern, replacement in REDACTION_RULES:
        matches = re.findall(pattern, text, re.IGNORECASE)
        if matches:
            replacements.append(f"  - {pattern[:50]}... -> {replacement[:50]}...")
        text = re.sub(pattern, replacement, text, flags=re.IGNORECASE)

    return text, replacements


def should_process_file(filepath: Path) -> bool:
    """判断文件是否需要处理"""
    if filepath.suffix.lower() not in SENSITIVE_EXTENSIONS:
        return False

    # 跳过 node_modules、.git 等目录
    parts = filepath.parts
    if any(p in parts for p in ['node_modules', '.git', '__pycache__', '.workbuddy']):
        return False

    return True


def redact_file(filepath: Path, dry_run: bool = False) -> bool:
    """对单个文件进行脱敏"""
    try:
        content = filepath.read_text(encoding='utf-8')
    except Exception as e:
        print(f"  ⚠️  无法读取 {filepath}: {e}")
        return False

    redacted_content, replacements = redact_text(content)

    if not replacements:
        return False

    if dry_run:
        print(f"  📋 {filepath}")
        for r in replacements:
            print(r)
    else:
        filepath.write_text(redacted_content, encoding='utf-8')
        print(f"  ✅ 已脱敏: {filepath}")
        for r in replacements:
            print(r)

    return True


def main():
    import argparse

    parser = argparse.ArgumentParser(description='自动脱敏脚本')
    parser.add_argument('path', type=str, help='要扫描的文件或目录路径')
    parser.add_argument('--dry-run', action='store_true', help='仅显示会修改的内容，不实际写入')
    parser.add_argument('--recursive', '-r', action='store_true', help='递归处理目录')
    args = parser.parse_args()

    target = Path(args.path)
    if not target.exists():
        print(f"❌ 路径不存在: {target}")
        sys.exit(1)

    print(f"🔍 扫描路径: {target}")
    print(f"模式: {'预览（不写入）' if args.dry_run else '实际脱敏'}")
    print()

    if target.is_file():
        if should_process_file(target):
            redact_file(target, dry_run=args.dry_run)
        else:
            print(f"⏭️  跳过: {target}（文件类型不需要处理）")
    else:
        pattern = '**/*' if args.recursive else '*'
        files = list(target.glob(pattern))
        files = [f for f in files if f.is_file() and should_process_file(f)]

        if not files:
            print("⚠️  未找到需要处理的文件")
            sys.exit(0)

        print(f"找到 {len(files)} 个文件需要检查\n")

        modified_count = 0
        for filepath in files:
            if redact_file(filepath, dry_run=args.dry_run):
                modified_count += 1

        print(f"\n{'预览' if args.dry_run else '脱敏'}完成: 共 {len(files)} 个文件，{'需要处理' if args.dry_run else '已修改'} {modified_count} 个")

        if args.dry_run and modified_count > 0:
            print("\n💡 去掉 --dry-run 参数即可实际执行脱敏")


if __name__ == '__main__':
    main()
