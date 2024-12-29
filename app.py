#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Aruba Configuration Analysis Tool
Author: Lucas.Mei
"""

from flask import Flask, render_template, request, jsonify
import re
import os
import time
from datetime import datetime
import logging
import json

app = Flask(__name__)
# 设置最大文件大小为1MB
app.config['MAX_CONTENT_LENGTH'] = 1 * 1024 * 1024

# 创建日志目录
log_dir = os.path.join(os.path.dirname(__file__), 'log')
if not os.path.exists(log_dir):
    os.makedirs(log_dir)

# 配置日志
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler(os.path.join(log_dir, 'app.log'), encoding='utf-8'),
        logging.StreamHandler()
    ]
)
logger = logging.getLogger(__name__)

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

if __name__ == '__main__':
    app.run(debug=True) 