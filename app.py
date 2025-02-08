#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Aruba Configuration Analysis Tool
Author: Lucas.Mei
"""

from flask import Flask, render_template, request, jsonify, send_from_directory, Response
import re
import os
import time
from datetime import datetime
import logging
import json
import requests
import subprocess
import glob
from pathlib import Path
from werkzeug.utils import secure_filename
import select  # 添加这个导入
import psutil

# 设置环境变量
os.environ['OPENAI_BASE_URL'] = 'http://10.0.69.88:3000/v1'
os.environ['OPENAI_API_KEY'] = 'sk-5BNIoIraUDdFxu9m3b394e9394284eAfB0C437E2E59eD2Fa'
os.environ['DEEPLX_ENDPOINT'] = 'http://10.0.69.88:1188/translate'

app = Flask(__name__)
# 设置最大文件大小为1MB
app.config['MAX_CONTENT_LENGTH'] = 50 * 1024 * 1024

# 创建日志目录
log_dir = os.path.join(os.path.dirname(__file__), 'log')
if not os.path.exists(log_dir):
    os.makedirs(log_dir)

# 配置日志
logging.basicConfig(
    level=logging.DEBUG,
    format='%(asctime)s - %(levelname)s - [%(filename)s:%(lineno)d] - %(message)s',
    handlers=[
        logging.FileHandler(os.path.join(log_dir, 'app.log'), encoding='utf-8'),
        logging.StreamHandler()
    ]
)
logger = logging.getLogger(__name__)

# 记录环境变量
logger.info("Environment Variables:")
logger.info(f"OPENAI_BASE_URL: {os.environ.get('OPENAI_BASE_URL', 'Not Set')}")
logger.info(f"OPENAI_API_KEY: {'*' * len(os.environ.get('OPENAI_API_KEY', ''))} (Length: {len(os.environ.get('OPENAI_API_KEY', ''))})")
logger.info(f"DEEPLX_ENDPOINT: {os.environ.get('DEEPLX_ENDPOINT', 'Not Set')}")

# 确保data目录存在
data_dir = os.path.join(os.path.dirname(__file__), 'data')
if not os.path.exists(data_dir):
    os.makedirs(data_dir)

# 定义需要处理的配置段落类型
VALID_SECTION_TYPES = {
    'netdestination',
    'ip access-list session',
    'user-role',
    'interface gigabitethernet',
    'interface port-channel',
    'interface vlan',
    'aaa rfc-3576-server',
    'aaa authentication mac',
    'aaa authentication dot1x',
    'aaa authentication-server radius',
    'aaa server-group',
    'aaa profile',
    'aaa authentication captive-portal',
    'lc-cluster group-profile',
    'ap regulatory-domain-profile',
    'ap wired-ap-profile',
    'ap multizone-profile',
    'ap system-profile',
    'ap wired-port-profile',
    'ids general-profile',
    'ids profile',
    'rf dot11-60GHz-radio-profile',
    'rf arm-profile',
    'rf ht-radio-profile',
    'rf spectrum-profile',
    'rf am-scan-profile',
    'rf dot11a-radio-profile',
    'rf dot11g-radio-profile',
    'rf dot11-6GHz-radio-profile',
    'wlan rrm-ie-profile',
    'wlan dot11r-profile',
    'wlan ht-ssid-profile',
    'wlan he-ssid-profile',
    'wlan edca-parameters-profile station',
    'wlan edca-parameters-profile ap',
    'wlan mu-edca-parameters-profile',
    'wlan dot11k-profile',
    'wlan ssid-profile',
    'wlan virtual-ap',
    'mgmt-server profile',
    'wlan traffic-management-profile',
    'ap-group',
    'airgroupprofile service',
    'airgroupprofile',
    'iot radio-profile',
    'dump-collection-profile',
    'ap-name'
}

def parse_section(line):
    """
    解析配置段落的第一行，提取类型和名称
    
    Args:
        line (str): 配置段落的第一行
    
    Returns:
        tuple: (section_type, section_name) 如果是有效的段落类型，否则返回 (None, None)
    """
    line = line.strip()
    
    # 检查是否是有效的段落类型
    for valid_type in VALID_SECTION_TYPES:
        if line.startswith(valid_type):
            # 移除段落类型，获取剩余部分作为名称
            name_part = line[len(valid_type):].strip()
            
            # 处理带引号的名称
            if '"' in name_part:
                name = name_part.split('"')[1]
            else:
                name = name_part
                
            return valid_type, name
            
    return None, None

def parse_config_sections(content):
    """
    解析配置文件内容，将其分解为独立的配置段落
    
    Args:
        content (str): 配置文件内容
    
    Returns:
        list: 包含所有有效配置段落的列表，每个段落包含类型、名称和命令
    """
    sections = []
    current_section = None
    current_commands = []
    
    for line in content.splitlines():
        stripped_line = line.strip()
        
        # 跳过空行
        if not stripped_line:
            continue
            
        # 检查是否是新段落的开始（无缩进的行）
        if not line.startswith(' ') and not line.startswith('\t'):
            # 保存前一个段落（如果存在）
            if current_section and current_section[0]:  # 只保存有效的段落类型
                sections.append({
                    'type': current_section[0],
                    'name': current_section[1],
                    'commands': current_commands
                })
                current_commands = []
            
            # 解析新段落
            section_type, section_name = parse_section(line)
            current_section = (section_type, section_name)
                
        # 检查是否是段落结束（遇到 ! 符号）
        elif stripped_line == '!':
            if current_section and current_section[0]:  # 只保存有效的段落类型
                sections.append({
                    'type': current_section[0],
                    'name': current_section[1],
                    'commands': current_commands
                })
                current_section = None
                current_commands = []
        else:
            # 将命令行添加到当前段落
            if current_section and current_section[0]:  # 只为有效段落类型收集命令
                current_commands.append(stripped_line)
    
    # 处理最后一个段落
    if current_section and current_section[0]:  # 只保存有效的段落类型
        sections.append({
            'type': current_section[0],
            'name': current_section[1],
            'commands': current_commands
        })
    
    return sections

def save_config_sections(sections):
    """
    保存配置段落到文件系统，按类型分类存储
    
    Args:
        sections (list): 配置段落列表
    
    Returns:
        dict: 保存结果统计
    """
    timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
    base_dir = os.path.join(data_dir, timestamp)
    
    # 统计信息
    stats = {
        'total': len(sections),
        'saved': 0,
        'types': {}
    }
    
    # 创建JSON文件来存储所有段落
    sections_file = os.path.join(base_dir, 'sections.json')
    os.makedirs(base_dir, exist_ok=True)
    
    try:
        # 将所有段落保存到一个JSON文件中
        with open(sections_file, 'w', encoding='utf-8') as f:
            json.dump({
                'timestamp': timestamp,
                'sections': sections
            }, f, indent=2, ensure_ascii=False)
        
        # 更新统计信息
        stats['saved'] = len(sections)
        for section in sections:
            section_type = section['type']
            stats['types'][section_type] = stats['types'].get(section_type, 0) + 1
        
        logger.info(f'Saved {len(sections)} sections to {sections_file}')
        
    except Exception as e:
        logger.error(f'Error saving sections: {str(e)}')
    
    return stats

def parse_config(config_text):
    """
    解析Aruba配置文件，重构AP组配置的关联关系
    
    Args:
        config_text (str): 配置文件内容
    
    Returns:
        dict: 解析后的配置结构
    """
    try:
        # 先解析所有配置段落
        sections = parse_config_sections(config_text)
        logger.debug(f"Parsed {len(sections)} sections")
        
        # 将配置段落转换为字典形式，便于查找
        section_dict = {}
        for section in sections:
            if section['type'] not in section_dict:
                section_dict[section['type']] = {}
            section_dict[section['type']][section['name']] = section['commands']
        
        # 记录找到的配置类型
        logger.debug(f"Found configuration types: {list(section_dict.keys())}")
        
        # 存储最终的配置结构
        config_structure = {}
        
        # 处理每个ap-group配置
        if 'ap-group' in section_dict:
            for ap_group_name, group_commands in section_dict['ap-group'].items():
                logger.debug(f"Processing ap-group: {ap_group_name}")
                
                # 初始化AP组配置结构
                config_structure[ap_group_name] = {
                    'commands': [],  # 存储未关联的命令
                    'profiles': {},  # 存储各类配置文件
                    'profile_order': []  # 存储配置的顺序
                }
                
                # 处理 ap-group 下的命令
                for cmd in group_commands:
                    if cmd.startswith('virtual-ap'):
                        try:
                            vap_name = get_quoted_name(cmd)
                            logger.debug(f"Processing virtual-ap: {vap_name} in ap-group: {ap_group_name}")
                            
                            if vap_name:
                                # 获取virtual-ap的命令
                                vap_commands = section_dict.get('wlan virtual-ap', {}).get(vap_name, [])
                                logger.debug(f"Found {len(vap_commands)} commands for VAP {vap_name}")
                                
                                # 初始化配置
                                vap_config = {
                                    'name': vap_name,
                                    'commands': [],
                                    'command_associations': {}  # 用于存储命令位置和关联配置的映射
                                }
                                
                                # 处理virtual-ap的命令
                                for i, vcmd in enumerate(vap_commands):
                                    try:
                                        logger.debug(f"Processing VAP command: {vcmd}")
                                        # 保存所有原始命令
                                        vap_config['commands'].append(vcmd)
                                        
                                        if vcmd.startswith('ssid-profile'):
                                            ssid_name = get_quoted_name(vcmd)
                                            if ssid_name:
                                                ssid_commands = section_dict.get('wlan ssid-profile', {}).get(ssid_name, [])
                                                vap_config['command_associations'][i] = {
                                                    'type': 'ssid_profile',
                                                    'name': ssid_name,
                                                    'commands': ssid_commands
                                                }
                                        elif vcmd.startswith('dot11k-profile'):
                                            profile_name = get_quoted_name(vcmd)
                                            if profile_name:
                                                dot11k_commands = section_dict.get('wlan dot11k-profile', {}).get(profile_name, [])
                                                vap_config['command_associations'][i] = {
                                                    'type': 'dot11k_profile',
                                                    'name': profile_name,
                                                    'commands': dot11k_commands
                                                }
                                        elif vcmd.startswith('aaa-profile'):
                                            aaa_name = get_quoted_name(vcmd)
                                            if aaa_name:
                                                aaa_commands = section_dict.get('aaa profile', {}).get(aaa_name, [])
                                                aaa_config = {
                                                    'name': aaa_name,
                                                    'commands': [],
                                                    'associations': {}
                                                }
                                                
                                                # 保存所有原始命令
                                                for j, acmd in enumerate(aaa_commands):
                                                    aaa_config['commands'].append(acmd)
                                                    
                                                    if 'authentication-dot1x' in acmd:
                                                        auth_name = get_quoted_name(acmd)
                                                        if auth_name:
                                                            auth_commands = section_dict.get('aaa authentication dot1x', {}).get(auth_name, [])
                                                            aaa_config['associations'][j] = {
                                                                'type': 'authentication_dot1x',
                                                                'name': auth_name,
                                                                'commands': auth_commands
                                                            }
                                                    elif 'dot1x-default-role' in acmd:
                                                        role_name = get_quoted_name(acmd)
                                                        if role_name:
                                                            role_commands = section_dict.get('user-role', {}).get(role_name, [])
                                                            aaa_config['associations'][j] = {
                                                                'type': 'dot1x_default_role',
                                                                'name': role_name,
                                                                'commands': role_commands
                                                            }
                                                    elif 'dot1x-server-group' in acmd:
                                                        group_name = get_quoted_name(acmd)
                                                        if group_name:
                                                            group_commands = section_dict.get('aaa server-group', {}).get(group_name, [])
                                                            aaa_config['associations'][j] = {
                                                                'type': 'dot1x_server_group',
                                                                'name': group_name,
                                                                'commands': group_commands
                                                            }
                                                    elif 'authentication-mac' in acmd:
                                                        mac_name = get_quoted_name(acmd)
                                                        if mac_name:
                                                            mac_commands = section_dict.get('aaa authentication mac', {}).get(mac_name, [])
                                                            aaa_config['associations'][j] = {
                                                                'type': 'authentication_mac',
                                                                'name': mac_name,
                                                                'commands': mac_commands
                                                            }
                                                    elif 'mac-default-role' in acmd:
                                                        role_name = get_quoted_name(acmd)
                                                        if role_name:
                                                            role_commands = section_dict.get('user-role', {}).get(role_name, [])
                                                            aaa_config['associations'][j] = {
                                                                'type': 'mac_default_role',
                                                                'name': role_name,
                                                                'commands': role_commands
                                                            }
                                                    elif 'mac-server-group' in acmd:
                                                        group_name = get_quoted_name(acmd)
                                                        if group_name:
                                                            group_commands = section_dict.get('aaa server-group', {}).get(group_name, [])
                                                            aaa_config['associations'][j] = {
                                                                'type': 'mac_server_group',
                                                                'name': group_name,
                                                                'commands': group_commands
                                                            }
                                                    elif 'radius-accounting' in acmd:
                                                        acct_name = get_quoted_name(acmd)
                                                        if acct_name:
                                                            acct_commands = section_dict.get('aaa server-group', {}).get(acct_name, [])
                                                            aaa_config['associations'][j] = {
                                                                'type': 'radius_accounting',
                                                                'name': acct_name,
                                                                'commands': acct_commands
                                                            }
                                                    elif 'initial-role' in acmd:
                                                        role_name = get_quoted_name(acmd)
                                                        if role_name:
                                                            role_commands = section_dict.get('user-role', {}).get(role_name, [])
                                                            aaa_config['associations'][j] = {
                                                                'type': 'initial_role',
                                                                'name': role_name,
                                                                'commands': role_commands
                                                            }
                                                
                                                vap_config['command_associations'][i] = {
                                                    'type': 'aaa_profile',
                                                    'config': aaa_config
                                                }
                                    except Exception as e:
                                        logger.error(f"Error processing VAP command: {str(e)}", exc_info=True)
                                        continue
                                
                                if 'virtual-ap' not in config_structure[ap_group_name]['profiles']:
                                    config_structure[ap_group_name]['profiles']['virtual-ap'] = {}
                                config_structure[ap_group_name]['profiles']['virtual-ap'][vap_name] = vap_config
                                config_structure[ap_group_name]['profile_order'].append({
                                    'type': 'virtual-ap',
                                    'name': vap_name
                                })
                        except Exception as e:
                            logger.error(f"Error processing virtual-ap configuration: {str(e)}", exc_info=True)
                            logger.error(f"Failed command: {cmd}")
                            logger.error(f"Current ap-group: {ap_group_name}")
                            continue
                    
                    # 处理dot11a-radio-profile配置
                    elif cmd.startswith('dot11a-radio-profile'):
                        parts = cmd.split('"')
                        if len(parts) >= 2:
                            profile_name = parts[1]
                            if 'dot11a-radio-profile' not in config_structure[ap_group_name]['profiles']:
                                config_structure[ap_group_name]['profiles']['dot11a-radio-profile'] = {}
                            
                            # 获取dot11a-radio-profile的命令
                            profile_commands = section_dict.get('rf dot11a-radio-profile', {}).get(profile_name, [])
                            
                            # 初始化配置
                            profile_config = {
                                'name': profile_name,
                                'commands': [],
                                'command_associations': {}
                            }
                            
                            # 处理命令和关联
                            for i, radio_cmd in enumerate(profile_commands):
                                # 保存所有原始命令
                                profile_config['commands'].append(radio_cmd)
                                
                                # 处理arm-profile关联
                                if radio_cmd.startswith('arm-profile'):
                                    arm_name = get_quoted_name(radio_cmd)
                                    if arm_name:
                                        arm_commands = section_dict.get('rf arm-profile', {}).get(arm_name, [])
                                        profile_config['command_associations'][i] = {
                                            'type': 'arm_profile',
                                            'name': arm_name,
                                            'commands': arm_commands
                                        }
                            
                            config_structure[ap_group_name]['profiles']['dot11a-radio-profile'][profile_name] = profile_config
                            config_structure[ap_group_name]['profile_order'].append({
                                'type': 'dot11a-radio-profile',
                                'name': profile_name
                            })
                    
                    # 处理dot11g-radio-profile配置
                    elif cmd.startswith('dot11g-radio-profile'):
                        parts = cmd.split('"')
                        if len(parts) >= 2:
                            profile_name = parts[1]
                            if 'dot11g-radio-profile' not in config_structure[ap_group_name]['profiles']:
                                config_structure[ap_group_name]['profiles']['dot11g-radio-profile'] = {}
                            
                            # 获取dot11g-radio-profile的命令
                            profile_commands = section_dict.get('rf dot11g-radio-profile', {}).get(profile_name, [])
                            
                            # 初始化配置
                            profile_config = {
                                'name': profile_name,
                                'commands': [],
                                'command_associations': {}
                            }
                            
                            # 处理命令和关联
                            for i, radio_cmd in enumerate(profile_commands):
                                # 保存所有原始命令
                                profile_config['commands'].append(radio_cmd)
                                
                                # 处理arm-profile关联
                                if radio_cmd.startswith('arm-profile'):
                                    arm_name = get_quoted_name(radio_cmd)
                                    if arm_name:
                                        arm_commands = section_dict.get('rf arm-profile', {}).get(arm_name, [])
                                        profile_config['command_associations'][i] = {
                                            'type': 'arm_profile',
                                            'name': arm_name,
                                            'commands': arm_commands
                                        }
                            
                            config_structure[ap_group_name]['profiles']['dot11g-radio-profile'][profile_name] = profile_config
                            config_structure[ap_group_name]['profile_order'].append({
                                'type': 'dot11g-radio-profile',
                                'name': profile_name
                            })
                    
                    # 处理ap-system-profile配置
                    elif cmd.startswith('ap-system-profile'):
                        parts = cmd.split('"')
                        if len(parts) >= 2:
                            profile_name = parts[1]
                            if 'ap-system-profile' not in config_structure[ap_group_name]['profiles']:
                                config_structure[ap_group_name]['profiles']['ap-system-profile'] = {}
                            config_structure[ap_group_name]['profiles']['ap-system-profile'][profile_name] = {
                                'commands': section_dict.get('ap system-profile', {}).get(profile_name, [])
                            }
                            config_structure[ap_group_name]['profile_order'].append({
                                'type': 'ap-system-profile',
                                'name': profile_name
                            })
                    
                    # 处理regulatory-domain-profile配置
                    elif cmd.startswith('regulatory-domain-profile'):
                        parts = cmd.split('"')
                        if len(parts) >= 2:
                            profile_name = parts[1]
                            if 'regulatory-domain-profile' not in config_structure[ap_group_name]['profiles']:
                                config_structure[ap_group_name]['profiles']['regulatory-domain-profile'] = {}
                            config_structure[ap_group_name]['profiles']['regulatory-domain-profile'][profile_name] = {
                                'commands': section_dict.get('ap regulatory-domain-profile', {}).get(profile_name, [])
                            }
                            config_structure[ap_group_name]['profile_order'].append({
                                'type': 'regulatory-domain-profile',
                                'name': profile_name
                            })
                    
                    # 处理dot11-6GHz-radio-profile配置
                    elif cmd.startswith('dot11-6GHz-radio-profile'):
                        parts = cmd.split('"')
                        if len(parts) >= 2:
                            profile_name = parts[1]
                            if 'dot11-6GHz-radio-profile' not in config_structure[ap_group_name]['profiles']:
                                config_structure[ap_group_name]['profiles']['dot11-6GHz-radio-profile'] = {}
                            config_structure[ap_group_name]['profiles']['dot11-6GHz-radio-profile'][profile_name] = {
                                'commands': section_dict.get('rf dot11-6GHz-radio-profile', {}).get(profile_name, [])
                            }
                            config_structure[ap_group_name]['profile_order'].append({
                                'type': 'dot11-6GHz-radio-profile',
                                'name': profile_name
                            })
                    
                    # 处理iot radio-profile配置
                    elif cmd.startswith('iot radio-profile'):
                        parts = cmd.split('"')
                        if len(parts) >= 2:
                            profile_name = parts[1]
                            if 'iot radio-profile' not in config_structure[ap_group_name]['profiles']:
                                config_structure[ap_group_name]['profiles']['iot radio-profile'] = {}
                            config_structure[ap_group_name]['profiles']['iot radio-profile'][profile_name] = {
                                'commands': section_dict.get('iot radio-profile', {}).get(profile_name, [])
                            }
                            config_structure[ap_group_name]['profile_order'].append({
                                'type': 'iot radio-profile',
                                'name': profile_name
                            })
                    
                    # 保存其他未关联的命令
                    else:
                        config_structure[ap_group_name]['commands'].append(cmd)
        
        return config_structure
    except Exception as e:
        logger.error(f"Error parsing configuration: {str(e)}", exc_info=True)
        return {}

def get_counter():
    """获取处理次数"""
    counter_file = os.path.join('templates', 'counters')
    try:
        with open(counter_file, 'r') as f:
            counter = int(f.read().strip() or '0')
            logger.info(f'Counter read: {counter}')
            return counter
    except (FileNotFoundError, ValueError) as e:
        logger.warning(f'Error reading counter: {str(e)}')
        return 0

def increment_counter():
    """增加处理次数并保存"""
    counter_file = os.path.join('templates', 'counters')
    try:
        counter = get_counter() + 1
        with open(counter_file, 'w') as f:
            f.write(str(counter))
        logger.info(f'Counter incremented to: {counter}')
        return counter
    except Exception as e:
        logger.error(f'Error incrementing counter: {str(e)}')
        return 0

def save_content(content):
    """保存内容到data目录，使用时间戳作为文件名"""
    timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
    filename = f"{timestamp}.log"
    filepath = os.path.join(data_dir, filename)
    
    try:
        # 确保data目录存在
        os.makedirs(data_dir, exist_ok=True)
        
        # 写入文件
        with open(filepath, 'w', encoding='utf-8') as f:
            f.write(content)
        logger.info(f'Content saved to file: {filepath}')
        return filename
    except Exception as e:
        logger.error(f'Error saving content to file: {str(e)}')
        return None

def analyze_config(content):
    """分析配置并生成AI提示"""
    analysis_results = []
    
    # 检查ap-name配置
    def check_ap_name_config(text):
        ap_names = []
        for line in text.splitlines():
            # 检查是否是非缩进的ap-name配置
            if line.startswith('ap-name '):
                # 提取ap-name后面的名称（去掉'ap-name '和前后空格）
                ap_name = line[8:].strip()
                if ap_name:
                    ap_names.append(ap_name)
        return ap_names
    
    # 检查ap-name配置并生成提示
    ap_names = check_ap_name_config(content)
    if ap_names:
        ap_list = ', '.join(ap_names)
        analysis_results.append({
            'type': 'warning',
            'message': f'AP-name based configurations exit for following AP: {ap_list}'
        })
    
    # 规范化字符串比较：移除多余空白字符，统一换行
    def normalize_config(config):
        # 分割行，去除每行首尾空白，移除空行
        lines = [line.strip() for line in config.splitlines() if line.strip()]
        # 重新合成字符串
        return '\n'.join(lines)
    
    # 定义默认的validuser ACL配置
    default_validuser_acl = """ip access-list session validuser
    network 127.0.0.0 255.0.0.0 any any deny
    network 169.254.0.0 255.255.0.0 any any deny
    network 224.0.0.0 240.0.0.0 any any deny
    host 255.255.255.255 any any deny
    network 240.0.0.0 240.0.0.0 any any deny
    any any any permit
    ipv6 host fe80:: any any deny
    ipv6 network fc00::/7 any any permit
    ipv6 network fe80::/64 any any permit
    ipv6 alias ipv6-reserved-range any any deny
    ipv6 any any any permit"""
    
    # 定义默认的validusereth ACL配置
    default_validusereth_acl = """ip access-list eth validuserethacl
    permit any"""
    
    # 检查validuser ACL配置
    validuser_start = content.find('ip access-list session validuser')
    if validuser_start >= 0:
        validuser_end = content.find('!', validuser_start)
        if validuser_end >= 0:
            actual_acl = content[validuser_start:validuser_end].strip()
            if normalize_config(actual_acl) != normalize_config(default_validuser_acl):
                analysis_results.append({
                    'type': 'warning',
                    'message': 'Default validuser acl may be changed, Please check.'
                })
    
    # 检查validusereth ACL配置
    validusereth_start = content.find('ip access-list eth validuserethacl')
    if validusereth_start >= 0:
        validusereth_end = content.find('!', validusereth_start)
        if validusereth_end >= 0:
            actual_eth_acl = content[validusereth_start:validusereth_end].strip()
            if normalize_config(actual_eth_acl) != normalize_config(default_validusereth_acl):
                analysis_results.append({
                    'type': 'warning',
                    'message': 'Default validusereth acl may be changed, Please check.'
                })
    
    # 检查arp配置
    def check_arp_config(text):
        # 在firewall段落中查找arp配置
        firewall_start = text.find('firewall')
        if firewall_start >= 0:
            firewall_end = text.find('!', firewall_start)
            if firewall_end >= 0:
                firewall_section = text[firewall_start:firewall_end]
                # 使用正则表达式检查是否存在arp配置
                import re
                arp_pattern = r'attack-rate\s+arp\s+\d+\s+drop'
                if not re.search(arp_pattern, firewall_section):
                    return True
        return False
    
    # 检查arp配置
    if check_arp_config(content):
        analysis_results.append({
            'type': 'warning',
            'message': 'Suggest to control arp with command under firewall "attack-rate arp 50 drop"'
        })
    
    # 检查allow-tri-session配置
    def check_tri_session_config(text):
        # 在firewall段落中查找配置
        firewall_start = text.find('firewall')
        if firewall_start >= 0:
            firewall_end = text.find('!', firewall_start)
            if firewall_end >= 0:
                firewall_section = text[firewall_start:firewall_end]
                # 检查是否存在allow-tri-session配置
                if 'allow-tri-session' not in firewall_section:
                    return True
        return False
    
    # 检查allow-tri-session配置
    if check_tri_session_config(content):
        analysis_results.append({
            'type': 'warning',
            'message': 'Suggest to use allow-tri-session under firewall for portal authentication'
        })
    
    # 检查debug日志配置
    def check_debug_logging(text):
        # 使用正则表达式检查是否存在debug日志配置
        import re
        debug_pattern = r'logging\s+.*\s*debugging\s+'
        if re.search(debug_pattern, text):
            return True
        return False
    
    # 检查debug日志配置
    if check_debug_logging(content):
        analysis_results.append({
            'type': 'warning',
            'message': 'Debug level logging exists, please check.'
        })
    
    # 检查VLAN配置
    def check_vlan_config(text):
        import re
        # 提取所有vlan配置中的vlan-id
        # 使用更严格的模式匹配：行首有空格，然后是"vlan"，然后是空格，然后是1-4096的数，然后是行尾或空
        vlan_pattern = r'^\s*vlan\s+(\d+)(?:\s|$)'
        vlan_ids = []
        
        # 逐行检查，确保严格匹配
        for line in text.splitlines():
            match = re.match(vlan_pattern, line)
            if match:
                vlan_id = int(match.group(1))
                # 验证vlan-id范围
                if 1 <= vlan_id <= 4096:
                    vlan_ids.append(str(vlan_id))
        
        # 检查个vlan-id的interface配置
        missing_bcmc = []
        for vlan_id in vlan_ids:
            # 查找interface vlan配置
            interface_pattern = f'interface vlan {vlan_id}'
            interface_start = text.find(interface_pattern)
            
            if interface_start < 0:
                missing_bcmc.append(vlan_id)
                continue
                
            # 查找该interface的配置块结束位置
            interface_end = text.find('!', interface_start)
            if interface_end < 0:
                interface_end = len(text)
            
            # 检查配置块中是否有bcmc-optimization
            interface_config = text[interface_start:interface_end]
            if 'bcmc-optimization' not in interface_config:
                missing_bcmc.append(vlan_id)
        
        return sorted(missing_bcmc)  # 返回排序后的列表
    
    # 检查VLAN配置并生成提示
    missing_bcmc_vlans = check_vlan_config(content)
    if missing_bcmc_vlans:
        vlan_list = ', '.join(missing_bcmc_vlans)
        analysis_results.append({
            'type': 'warning',
            'message': f'VLAN {vlan_list} need to configure bcmc-optimization'
        })
    
    # 检查spanning-tree配置
    def check_spanning_tree(text):
        # 检查是否存在no spanning-tree配置
        return 'no spanning-tree' not in text
    
    # 检查spanning-tree配置
    if check_spanning_tree(content):
        analysis_results.append({
            'type': 'warning',
            'message': 'Spanning tree may be working'
        })
    
    return analysis_results

def decode_file_content(file_content):
    """
    尝试使用多种编码解码文件内容
    
    Args:
        file_content (bytes): 文件二进制内容
    
    Returns:
        str: 解码后的文本内容，解码失败返回None
    """
    # 试不同的编码方式
    encodings = ['utf-8', 'gbk', 'gb2312', 'gb18030', 'big5', 'latin1']
    
    for encoding in encodings:
        try:
            content = file_content.decode(encoding)
            logger.info(f'Successfully decoded file using {encoding} encoding')
            return content
        except UnicodeDecodeError:
            continue
    
    logger.error('Failed to decode file with all attempted encodings')
    return None

# 添加一个辅助函数来安全地获取引号中的内容
def get_quoted_name(text):
    """
    安全地从带引号的文本中提取名称
    
    Args:
        text (str): 包含引号的文本
    
    Returns:
        str: 提取的名称，如果无法提取则返回None
    """
    try:
        if not text:
            logger.warning("Empty text provided to get_quoted_name")
            return None
            
        start = text.find('"')
        if start >= 0:
            end = text.find('"', start + 1)
            if end > start:
                name = text[start + 1:end]
                logger.debug(f"Successfully extracted name: {name}")
                return name
            else:
                logger.warning(f"Could not find closing quote in text: {text}")
        else:
            logger.warning(f"Could not find opening quote in text: {text}")
    except Exception as e:
        logger.error(f"Error in get_quoted_name: {str(e)}, text: {text}")
    return None

@app.route('/')
def index():
    counter = get_counter()
    return render_template('index.html', counter=counter)

@app.route('/upload', methods=['POST'])
def upload_file():
    """处理配置文件上传，支持文件上传和文本粘贴两种方式"""
    content = None
    
    # 处理文件上传
    if 'config_file' in request.files:
        file = request.files['config_file']
        if file.filename != '':
            try:
                file_content = file.read()
                content = decode_file_content(file_content)
                if not content:
                    return jsonify({'error': 'Unable to decode file content'})
                logger.info(f'File uploaded: {file.filename}')
            except Exception as e:
                logger.error(f'Error processing file: {str(e)}')
                return jsonify({'error': 'Error processing file'})
    
    # 处理粘贴文本
    elif 'config_text' in request.form:
        content = request.form['config_text']
        if not content.strip():
            return jsonify({'error': 'Configuration content cannot be empty'})
    
    if not content:
        return jsonify({'error': 'Please provide configuration content'})
    
    try:
        # 增加计数器
        counter = increment_counter()
        
        # 保存原始内容
        saved_filename = save_content(content)
        if not saved_filename:
            logger.warning('Failed to save content to file')
        
        # 解析和保存配置段落
        sections = parse_config_sections(content)
        stats = save_config_sections(sections)
        logger.info(f'Processed {stats["total"]} sections, saved {stats["saved"]} successfully')
        
        # 原有的配置分析和处理
        analysis_results = analyze_config(content)
        config_structure = parse_config(content)
        
        # 检查 config_structure 是否为 None
        if config_structure is None:
            return jsonify({'error': 'Failed to parse configuration structure'})
        
        with open(os.path.join('templates', '812default.log'), 'r', encoding='utf-8') as f:
            default_content = f.read()
            
        # 添加配置结构验证
        if config_structure:
            for group_name, group_data in config_structure.items():
                if 'profiles' in group_data:
                    for profile_type, profiles in group_data['profiles'].items():
                        if profile_type == 'virtual-ap':
                            for vap_name, vap_data in profiles.items():
                                if 'aaa_profile' in vap_data:
                                    aaa_profile = vap_data['aaa_profile']
                                    logger.debug(f"Validating aaa-profile structure: {json.dumps(aaa_profile, indent=2)}")
        
        return render_template('result.html',
                             config=config_structure,
                             uploaded_content=content,
                             default_content=default_content,
                             analysis_results=analysis_results,
                             save_stats=stats,
                             counter=counter)
            
    except Exception as e:
        error_msg = f'Error processing configuration: {str(e)}'
        logger.error(error_msg)
        return jsonify({'error': error_msg})

# 读取配置文件
def load_config():
    config_path = os.path.join('templates', 'config.json')
    try:
        with open(config_path, 'r') as f:
            return json.load(f)
    except Exception as e:
        logger.error(f"Error loading config: {str(e)}")
        return None

# 新增聊天页面路由
@app.route('/chat')
def chat():
    return render_template('chat.html')

# 新增配置分析API路由 - 重命名为analyze_config_chat以避免冲突
@app.route('/analyze_config_chat', methods=['POST'])
def analyze_config_chat():
    try:
        logger.debug("="*50)
        logger.debug("Starting new API request")
        
        config = load_config()
        if not config:
            logger.error("Config file not found or empty")
            return jsonify({'error': '无法加载API配置'}), 500

        data = request.json
        if not data:
            logger.error("No JSON data in request")
            return jsonify({'error': '无效的请求数据'}), 400

        config_text = data.get('config', '').strip()
        model_id = data.get('model', config.get('default_model'))
        
        # 根据model设置timeout
        timeout_value = (30, 120) if model_id == 'lucastest' else 30
        logger.info(f"Using model: {model_id}, timeout: {timeout_value}")

        if not config_text:
            logger.error("No config text in request data")
            return jsonify({'error': '配置内容不能为空'}), 400

        # 记录接收到的配置内容
        logger.info("Received configuration text:")
        logger.info("-"*30)
        logger.info(config_text)
        logger.info("-"*30)

        # 检查是否是后门命令
        is_backdoor = config_text.startswith('lucas')
        if is_backdoor:
            config_text = config_text[5:].strip()
            logger.info("Using backdoor mode")
            messages = [
                {
                    "role": "system",
                    "content": "你是基于大语言模型的AI智能助手，旨在回答并解决人们的任何问题,并且可以使用多种语言与人交流。"
                },
                {
                    "role": "user",
                    "content": config_text
                }
            ]
        else:
            logger.info("Using normal mode")
            messages = [
                {
                    "role": "system",
                    "content": "你是一个Aruba wireless 配置的专家，只回答关于配置的相关问题，如果问题中有与配置无关的问题，你将拒绝回答."
                },
                {
                    "role": "user",
                    "content": f"以下为aruba AOS8控制器上的配置，解释含义并分析下有没有问题:\n\n{config_text}"
                }
            ]

        # 准备API请求
        api_url = f"{config['base_url']}/v1/chat/completions"
        headers = {
            "Content-Type": "application/json",
            "Authorization": f"Bearer {config['api_key']}"
        }
        
        payload = {
            "model": model_id,  # 使用选择的模型
            "messages": messages
        }

        # 记录API请求详情
        logger.info("Sending API request:")
        logger.info(f"URL: {api_url}")
        logger.info("Payload:")
        logger.info("-"*30)
        logger.info(json.dumps(payload, ensure_ascii=False, indent=2))
        logger.info("-"*30)

        try:
            response = requests.post(
                api_url,
                headers=headers,
                json=payload,
                timeout=timeout_value  # 使用动态的timeout值
            )
            
            # 记录API响应
            logger.info("API Response:")
            logger.info(f"Status Code: {response.status_code}")
            logger.info("-"*30)
            logger.info(json.dumps(response.json(), ensure_ascii=False, indent=2))
            logger.info("-"*30)
            
            response.raise_for_status()
            result = response.json()
            ai_response = result['choices'][0]['message']['content']
            
            return jsonify({'analysis': ai_response})

        except Exception as e:
            logger.error(f"API request error: {str(e)}", exc_info=True)
            return jsonify({'error': '服务暂时不可用'}), 503

    except Exception as e:
        logger.error(f"Global error: {str(e)}", exc_info=True)
        return jsonify({'error': '服务器内部错误'}), 500

# 添加新路由获取模型列表
@app.route('/get_models')
def get_models():
    try:
        config = load_config()
        if not config:
            logger.error("Could not load config file")
            return jsonify({'error': '无法加载配置'}), 500
            
        models = config.get('models', [])
        default_model = config.get('default_model')
        
        logger.info(f"Returning {len(models)} models, default: {default_model}")
        return jsonify({
            'models': models,
            'default_model': default_model
        })
    except Exception as e:
        logger.error(f"Error getting models: {str(e)}")
        return jsonify({'error': '获取模型列表失败'}), 500

# 添加新路由
@app.route('/tran')
def tran():
    # 确保pdf2zh目录存在
    pdf_dir = Path('./pdf2zh')
    pdf_dir.mkdir(exist_ok=True)
    
    # 获取prompt文件列表
    prompt_files = glob.glob('./*.txt')
    prompt_files = [Path(f).name for f in prompt_files]
    
    return render_template('tran.html', prompt_files=prompt_files)

# 添加文件上传和翻译处理路由
@app.route('/translate_pdf', methods=['POST'])
def translate_pdf():
    try:
        pdf_dir = Path('./pdf2zh')
        pdf_dir.mkdir(exist_ok=True)
        
        tasks_dir = Path('./tasks')
        tasks_dir.mkdir(exist_ok=True)
        
        if 'file' not in request.files:
            logger.error("No file in request")
            return jsonify({'error': '没有选择文件'}), 400
            
        file = request.files['file']
        if file.filename == '':
            logger.error("Empty filename")
            return jsonify({'error': '没有选择文件'}), 400
        
        filename = secure_filename(file.filename)
        base_name = Path(filename).stem
        
        # 检查并删除可能存在的旧翻译文件
        mono_file = pdf_dir / f"{base_name}-mono.pdf"
        dual_file = pdf_dir / f"{base_name}-dual.pdf"
        
        try:
            if mono_file.exists():
                logger.info(f"Removing existing mono file: {mono_file}")
                mono_file.unlink()
            if dual_file.exists():
                logger.info(f"Removing existing dual file: {dual_file}")
                dual_file.unlink()
        except Exception as e:
            logger.error(f"Error removing existing translation files: {str(e)}")
            return jsonify({'error': '无法清理旧的翻译文件'}), 500
        
        # 保存上传的文件
        filepath = pdf_dir / filename
        file.save(filepath)
        logger.info(f"Saved file: {filepath}")
        
        # 构建命令
        cmd = ['pdf2zh', str(filename)]
        
        # 添加参数
        params = {
            'p': request.form.get('partial'),
            'li': request.form.get('sourceLang'),
            'lo': request.form.get('targetLang'),
            's': request.form.get('service'),
            't': request.form.get('threads'),
            'f': request.form.get('fontExceptions'),
            'c': request.form.get('stringExceptions'),
            'prompt': request.form.get('prompt')
        }
        
        for key, value in params.items():
            if value:
                if key == 'prompt':
                    cmd.extend(['--prompt', value])
                else:
                    cmd.extend([f'-{key}', value])

        logger.info(f"Executing command: {' '.join(cmd)}")
        
        # 创建stderr输出文件
        task_id = str(int(time.time()))
        stderr_file = tasks_dir / f"{task_id}.stderr"
        
        # 启动进程
        if app.debug:
            # 本地开发环境：使用管道
            process = subprocess.Popen(
                cmd,
                cwd=str(pdf_dir),
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
                bufsize=1,
                universal_newlines=True
            )
            # 存储进程对象供本地使用
            app.config[f'process_{task_id}'] = process
        else:
            # 生产环境：重定向到文件
            with open(stderr_file, 'w') as f:
                process = subprocess.Popen(
                    cmd,
                    cwd=str(pdf_dir),
                    stdout=subprocess.PIPE,
                    stderr=f,
                    text=True,
                    bufsize=1,
                    universal_newlines=True
                )
        
        # 存储任务信息
        task_info = {
            'pid': process.pid,
            'filename': filename,
            'created_at': time.time()
        }
        
        with open(tasks_dir / f"{task_id}.json", 'w') as f:
            json.dump(task_info, f)
            
        logger.info(f"Created task {task_id} for file {filename}")
        return jsonify({'task_id': task_id})
        
    except Exception as e:
        logger.error(f"Error in translate_pdf: {str(e)}", exc_info=True)
        return jsonify({'error': f'处理失败: {str(e)}'}), 500

# 添加文件下载路由
@app.route('/download/<filename>')
def download_file(filename):
    return send_from_directory('pdf2zh', filename, as_attachment=True)

# 添加SSE路由
@app.route('/stream_progress/<task_id>')
def stream_progress(task_id):
    def generate():
        logger.info(f"Starting progress stream for task {task_id}")
        
        pdf_dir = Path('./pdf2zh')
        tasks_dir = Path('./tasks')
        task_file = tasks_dir / f"{task_id}.json"
        stderr_file = tasks_dir / f"{task_id}.stderr"
        
        if not task_file.exists():
            logger.error(f"Task file not found: {task_file}")
            yield "data: {\"error\": \"任务不存在\"}\n\n"
            return
            
        try:
            with open(task_file) as f:
                task_info = json.load(f)
            
            logger.info(f"Found task {task_id} for file {task_info['filename']}")
            base_name = Path(task_info['filename']).stem
            mono_file = pdf_dir / f"{base_name}-mono.pdf"
            dual_file = pdf_dir / f"{base_name}-dual.pdf"
            
            # 本地开发环境：使用存储的进程对象
            if app.debug:
                process = app.config.get(f'process_{task_id}')
                if process is None:
                    logger.error("Process not found in app.config")
                    yield "data: {\"error\": \"任务不存在\"}\n\n"
                    return
                
                yield "data: {\"progress\": \"开始翻译...\n\"}\n\n"
                progress_100_seen = False
                
                # 监控进度（本地环境）
                while True:
                    return_code = process.poll()
                    
                    line = process.stderr.readline()
                    if line:
                        line = line.strip()
                        if line:
                            logger.debug(f"Raw output: {line}")
                            if '%' in line or 'it/s' in line:
                                logger.debug(f"Task {task_id} progress: {line}")
                                yield f"data: {json.dumps({'progress': line, 'refresh': True})}\n\n"
                                if '100%' in line:
                                    progress_100_seen = True
                                    time.sleep(2)
                                    mono_exists = mono_file.exists()
                                    dual_exists = dual_file.exists()
                                    
                                    if mono_exists or dual_exists:
                                        logger.info(f"Task {task_id} completed, files found: mono={mono_exists}, dual={dual_exists}")
                                        files = {
                                            'mono': {
                                                'name': f"{base_name}-mono.pdf",
                                                'exists': mono_exists,
                                                'description': '单语翻译版本'
                                            },
                                            'dual': {
                                                'name': f"{base_name}-dual.pdf",
                                                'exists': dual_exists,
                                                'description': '双语对照版本'
                                            }
                                        }
                                        yield f"data: {json.dumps({'complete': True, 'files': files})}\n\n"
                                        return
                            elif line.strip():  # 只处理非空行且不包含进度信息的行
                                logger.debug(f"Task {task_id} output: {line}")
                                yield f"data: {json.dumps({'progress': line, 'refresh': False})}\n\n"
                    
                    if return_code is not None:
                        if not progress_100_seen:
                            logger.error(f"Process ended but never reached 100% for task {task_id}")
                            yield f"data: {json.dumps({'error': '翻译进程异常结束'})}\n\n"
                            break
                        time.sleep(1)  # 等待文件写入完成
                        break
                    
                    time.sleep(0.1)
            
            # 生产环境：使用文件和psutil
            else:
                try:
                    process = psutil.Process(task_info['pid'])
                except psutil.NoSuchProcess:
                    logger.error(f"Process {task_info['pid']} not found")
                    yield "data: {\"error\": \"任务已结束\"}\n\n"
                    return
                
                yield "data: {\"progress\": \"开始翻译...\n\"}\n\n"
                
                # 监控翻译进度（生产环境）
                start_time = time.time()
                max_wait_time = 300  # 最长等待5分钟
                last_position = 0
                progress_100_seen = False
                
                while True:
                    # 检查是否超时
                    if time.time() - start_time > max_wait_time:
                        logger.error(f"Task {task_id} timed out after {max_wait_time} seconds")
                        yield f"data: {json.dumps({'error': '翻译超时'})}\n\n"
                        break
                    
                    # 读取进度输出
                    try:
                        if stderr_file.exists():
                            with open(stderr_file, 'r') as f:
                                f.seek(last_position)
                                lines = f.readlines()
                                last_position = f.tell()
                            
                            for line in lines:
                                line = line.strip()
                                if line:
                                    logger.debug(f"Raw output: {line}")
                                    if '%' in line or 'it/s' in line:
                                        logger.debug(f"Task {task_id} progress: {line}")
                                        yield f"data: {json.dumps({'progress': line, 'refresh': True})}\n\n"
                                        if '100%' in line:
                                            progress_100_seen = True
                                            time.sleep(2)
                                            mono_exists = mono_file.exists()
                                            dual_exists = dual_file.exists()
                                            
                                            if mono_exists or dual_exists:
                                                logger.info(f"Task {task_id} completed, files found: mono={mono_exists}, dual={dual_exists}")
                                                files = {
                                                    'mono': {
                                                        'name': f"{base_name}-mono.pdf",
                                                        'exists': mono_exists,
                                                        'description': '单语翻译版本'
                                                    },
                                                    'dual': {
                                                        'name': f"{base_name}-dual.pdf",
                                                        'exists': dual_exists,
                                                        'description': '双语对照版本'
                                                    }
                                                }
                                                yield f"data: {json.dumps({'complete': True, 'files': files})}\n\n"
                                                return
                                        else:
                                            # 只有非进度信息才输出为普通消息
                                            if not any(x in line for x in ['%', 'it/s']):
                                                logger.debug(f"Task {task_id} output: {line}")
                                                yield f"data: {json.dumps({'progress': line, 'refresh': False})}\n\n"
                    except Exception as e:
                        logger.error(f"Error reading progress: {str(e)}")
                    
                    # 检查进程是否还在运行
                    try:
                        if not process.is_running():
                            if progress_100_seen:
                                # 已经看到100%，最后检查一次文件
                                time.sleep(2)
                                mono_exists = mono_file.exists()
                                dual_exists = dual_file.exists()
                                
                                if mono_exists or dual_exists:
                                    logger.info(f"Task {task_id} completed, files found: mono={mono_exists}, dual={dual_exists}")
                                    files = {
                                        'mono': {
                                            'name': f"{base_name}-mono.pdf",
                                            'exists': mono_exists,
                                            'description': '单语翻译版本'
                                        },
                                        'dual': {
                                            'name': f"{base_name}-dual.pdf",
                                            'exists': dual_exists,
                                            'description': '双语对照版本'
                                        }
                                    }
                                    yield f"data: {json.dumps({'complete': True, 'files': files})}\n\n"
                                    return
                                else:
                                    logger.error(f"Process ended, saw 100% but no files found for task {task_id}")
                                    yield f"data: {json.dumps({'error': '翻译完成但未找到输出文件'})}\n\n"
                            else:
                                logger.error(f"Process ended but never reached 100% for task {task_id}")
                                yield f"data: {json.dumps({'error': '翻译进程异常结束'})}\n\n"
                            break
                    except psutil.NoSuchProcess:
                        if progress_100_seen:
                            # 进程已结束但看到了100%，最后检查一次文件
                            time.sleep(2)
                            mono_exists = mono_file.exists()
                            dual_exists = dual_file.exists()
                            
                            if mono_exists or dual_exists:
                                logger.info(f"Task {task_id} completed, files found: mono={mono_exists}, dual={dual_exists}")
                                files = {
                                    'mono': {
                                        'name': f"{base_name}-mono.pdf",
                                        'exists': mono_exists,
                                        'description': '单语翻译版本'
                                    },
                                    'dual': {
                                        'name': f"{base_name}-dual.pdf",
                                        'exists': dual_exists,
                                        'description': '双语对照版本'
                                    }
                                }
                                yield f"data: {json.dumps({'complete': True, 'files': files})}\n\n"
                                return
                            else:
                                logger.error(f"Process died, saw 100% but no files found for task {task_id}")
                                yield f"data: {json.dumps({'error': '翻译完成但未找到输出文件'})}\n\n"
                        else:
                            logger.error(f"Process died unexpectedly for task {task_id}")
                            yield f"data: {json.dumps({'error': '翻译进程意外终止'})}\n\n"
                        break
                    
                    time.sleep(0.1)
            
            # 检查输出文件（两种环境通用）
            mono_exists = mono_file.exists()
            dual_exists = dual_file.exists()
            
            if mono_exists or dual_exists:
                logger.info(f"Task {task_id} completed, files found: mono={mono_exists}, dual={dual_exists}")
                files = {
                    'mono': {
                        'name': f"{base_name}-mono.pdf",
                        'exists': mono_exists,
                        'description': '单语翻译版本'
                    },
                    'dual': {
                        'name': f"{base_name}-dual.pdf",
                        'exists': dual_exists,
                        'description': '双语对照版本'
                    }
                }
                yield f"data: {json.dumps({'complete': True, 'files': files})}\n\n"
            else:
                logger.error(f"No output files found for task {task_id}")
                yield f"data: {json.dumps({'error': '未找到翻译后的文件'})}\n\n"
                
        except Exception as e:
            logger.error(f"Error in stream_progress for task {task_id}: {str(e)}", exc_info=True)
            yield f"data: {json.dumps({'error': f'监控进度出错: {str(e)}'})}\n\n"
        finally:
            # 清理任务文件
            try:
                if not app.debug and stderr_file.exists():
                    stderr_file.unlink()
                task_file.unlink()
                if app.debug and f'process_{task_id}' in app.config:
                    del app.config[f'process_{task_id}']
                logger.info(f"Cleaned up task files for {task_id}")
            except Exception as e:
                logger.error(f"Error cleaning up: {str(e)}")
        
    return Response(generate(), mimetype='text/event-stream')

# 添加新的转换路由
@app.route('/convert_to_docx/<filename>')
def convert_to_docx(filename):
    try:
        pdf_dir = Path('./pdf2zh')
        pdf_path = pdf_dir / filename
        docx_path = pdf_dir / filename.replace('.pdf', '.docx')
        
        # 执行转换命令

        logging.info(f"OPENAI_BASE_URL: {os.environ['OPENAI_BASE_URL']}")
        logging.info(f"OPENAI_API_KEY: {os.environ['OPENAI_API_KEY']}")
        logging.info(f"DEEPLX_ENDPOINT: {os.environ['DEEPLX_ENDPOINT']}")
              
        cmd = ['pdf2docx', 'convert', str(pdf_path), str(docx_path)]
        process = subprocess.run(cmd, capture_output=True, text=True)
        
        if process.returncode != 0:
            logger.error(f"Convert failed: {process.stderr}")
            return jsonify({'error': '转换失败'}), 500
            
        # 检查文件是否生成
        if docx_path.exists():
            return send_from_directory('pdf2zh', docx_path.name, as_attachment=True)
        else:
            return jsonify({'error': '转换后的文件未找到'}), 500
            
    except Exception as e:
        logger.error(f"Error in convert_to_docx: {str(e)}")
        return jsonify({'error': f'转换失败: {str(e)}'}), 500



if __name__ == '__main__':
    app.run(debug=True) 