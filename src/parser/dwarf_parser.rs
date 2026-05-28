//! DWARF debug information parsing using gimli crate
//!
//! Provides DWARF parsing for struct member offset lookup and variable value reading.

use crate::error::{DebugError, Result};
use gimli::{Dwarf, EndianSlice, LittleEndian, UnitOffset};
use object::{File, Object, ObjectSection};
use serde::{Deserialize, Serialize};
use std::path::Path;
use tracing::debug;

type DwarfData<'a> = Dwarf<EndianSlice<'a, LittleEndian>>;
type DebuggingInformationEntry<'a> = gimli::DebuggingInformationEntry<'a, 'a, EndianSlice<'a, LittleEndian>>;
type Abbreviations = gimli::Abbreviations;

// =============================================================================
// Type System
// =============================================================================

/// 基本类型枚举
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum PrimitiveType {
    U8, I8, U16, I16, U32, I32, U64, I64, F32, F64, Bool, Char,
}

impl PrimitiveType {
    pub fn size(&self) -> u64 {
        match self {
            PrimitiveType::U8 | PrimitiveType::I8 | PrimitiveType::Bool | PrimitiveType::Char => 1,
            PrimitiveType::U16 | PrimitiveType::I16 => 2,
            PrimitiveType::U32 | PrimitiveType::I32 | PrimitiveType::F32 => 4,
            PrimitiveType::U64 | PrimitiveType::I64 | PrimitiveType::F64 => 8,
        }
    }
}

/// 类型信息
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum TypeInfo {
    Primitive(PrimitiveType),
    Pointer { target: Box<TypeInfo>, size: u64 },
    Array { element: Box<TypeInfo>, count: usize, size: u64 },
    Struct { name: String, size: u64, members: Vec<TypedMember> },
    Enum { name: String, size: u64, variants: Vec<EnumVariant> },
    Unknown { size: u64, name: Option<String> },
}

impl TypeInfo {
    pub fn size(&self) -> u64 {
        match self {
            TypeInfo::Primitive(p) => p.size(),
            TypeInfo::Pointer { size, .. } => *size,
            TypeInfo::Array { size, .. } => *size,
            TypeInfo::Struct { size, .. } => *size,
            TypeInfo::Enum { size, .. } => *size,
            TypeInfo::Unknown { size, .. } => *size,
        }
    }

    pub fn type_name(&self) -> String {
        match self {
            TypeInfo::Primitive(p) => format!("{:?}", p).to_lowercase(),
            TypeInfo::Pointer { target, .. } => format!("*{}", target.type_name()),
            TypeInfo::Array { element, count, .. } => format!("[{}; {}]", element.type_name(), count),
            TypeInfo::Struct { name, .. } => format!("struct {}", name),
            TypeInfo::Enum { name, .. } => format!("enum {}", name),
            TypeInfo::Unknown { name, .. } => name.clone().unwrap_or_else(|| "unknown".to_string()),
        }
    }
}

/// 带类型的结构体成员
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TypedMember {
    pub name: String,
    pub offset: u64,
    pub type_info: TypeInfo,
}

/// 枚举变体
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EnumVariant {
    pub name: String,
    pub value: i64,
}

/// 变量信息
#[derive(Debug, Clone)]
pub struct VariableInfo {
    pub name: String,
    pub address: u64,
    pub type_info: TypeInfo,
}

/// 解析后的符号信息
#[derive(Debug, Clone)]
pub struct ResolvedSymbol {
    pub expression: String,
    pub address: u64,
    pub type_info: TypeInfo,
}

/// Get DWARF data from ELF file
fn load_dwarf_data(elf_path: &Path) -> Result<DwarfData<'static>> {
    let file = crate::rtt::elf_parser::get_elf_file(elf_path)?;

    let debug_abbrev_data = leak_section(&file, ".debug_abbrev")?;
    let debug_info_data = leak_section(&file, ".debug_info")?;
    let debug_str_data = leak_section(&file, ".debug_str").unwrap_or(&[]);
    let debug_line_data = leak_section(&file, ".debug_line").unwrap_or(&[]);

    let dwarf = Dwarf::load(|section_id| {
        let data = match section_id {
            gimli::SectionId::DebugAbbrev => debug_abbrev_data,
            gimli::SectionId::DebugInfo => debug_info_data,
            gimli::SectionId::DebugLine => debug_line_data,
            gimli::SectionId::DebugStr => debug_str_data,
            _ => return Err(Box::new(std::io::Error::new(std::io::ErrorKind::NotFound, "unsupported"))),
        };
        Ok(EndianSlice::new(data, LittleEndian))
    }).map_err(|e| DebugError::DwarfError(e.to_string()))?;

    Ok(dwarf)
}

fn leak_section(file: &File, name: &str) -> Result<&'static [u8]> {
    for section in file.sections() {
        if let Ok(section_name) = section.name() {
            if section_name == name {
                let data = section.data().map_err(|e| DebugError::DwarfError(e.to_string()))?;
                let boxed = data.to_vec().into_boxed_slice();
                return Ok(Box::leak(boxed));
            }
        }
    }
    Err(DebugError::DwarfError(format!("Section {} not found", name)))
}

fn get_string(entry: &gimli::DebuggingInformationEntry<EndianSlice<LittleEndian>>, dwarf: &DwarfData, attr_name: gimli::constants::DwAt) -> Option<String> {
    entry.attr(attr_name).ok().flatten().and_then(|attr| {
        match attr.value() {
            gimli::AttributeValue::DebugStrRef(offset) => {
                dwarf.debug_str.get_str(offset).ok().map(|s| s.to_string_lossy().into_owned())
            }
            _ => None,
        }
    })
}

fn get_attr_u64(entry: &gimli::DebuggingInformationEntry<EndianSlice<LittleEndian>>, attr_name: gimli::constants::DwAt) -> Option<u64> {
    entry.attr(attr_name).ok().flatten().and_then(|attr| {
        match attr.value() {
            gimli::AttributeValue::Udata(val) => Some(val),
            _ => None,
        }
    })
}

fn get_member_offset(entry: &gimli::DebuggingInformationEntry<EndianSlice<LittleEndian>>) -> u64 {
    get_attr_u64(entry, gimli::constants::DW_AT_data_member_location).unwrap_or(0)
}

pub fn get_struct_layout(elf_path: &Path, struct_name: &str) -> Result<StructLayout> {
    let dwarf = load_dwarf_data(elf_path)?;
    let debug_abbrev = &dwarf.debug_abbrev;

    let mut units = dwarf.units();
    while let Some(header) = units.next().map_err(|e| DebugError::DwarfError(e.to_string()))? {
        let abbrev = header.abbreviations(debug_abbrev).map_err(|e| DebugError::DwarfError(e.to_string()))?;

        let mut entries = header.entries(&abbrev);
        while let Some((depth, entry)) = entries.next_dfs().map_err(|e| DebugError::DwarfError(e.to_string()))? {
            if entry.tag() == gimli::constants::DW_TAG_structure_type {
                let name = get_string(&entry, &dwarf, gimli::constants::DW_AT_name);
                if let Some(name_str) = name {
                    if name_str == struct_name {
                        let size = get_attr_u64(&entry, gimli::constants::DW_AT_byte_size).unwrap_or(0);
                        let mut members = Vec::new();

                        while let Some((child_depth, child)) = entries.next_dfs().map_err(|e| DebugError::DwarfError(e.to_string()))? {
                            if child_depth <= depth {
                                break;
                            }

                            if child.tag() == gimli::constants::DW_TAG_member {
                                let member_name = get_string(&child, &dwarf, gimli::constants::DW_AT_name);
                                let member_size = get_attr_u64(&child, gimli::constants::DW_AT_byte_size).unwrap_or(0);
                                let offset = get_member_offset(&child);

                                if let Some(mname) = member_name {
                                    members.push(StructMember {
                                        name: mname.to_string(),
                                        offset,
                                        size: member_size,
                                        type_name: "unknown".to_string(),
                                    });
                                }
                            }
                        }

                        members.sort_by_key(|m| m.offset);

                        return Ok(StructLayout {
                            name: struct_name.to_string(),
                            size,
                            alignment: 0,
                            members,
                        });
                    }
                }
            }
        }
    }

    Err(DebugError::StructNotFound(struct_name.to_string()))
}

pub fn get_struct_member_offset(elf_path: &Path, struct_name: &str, member_name: &str) -> Result<u64> {
    let layout = get_struct_layout(elf_path, struct_name)?;

    layout.members
        .iter()
        .find(|m| m.name == member_name)
        .map(|m| m.offset)
        .ok_or_else(|| DebugError::MemberNotFound(struct_name.to_string(), member_name.to_string()))
}

pub fn list_structs(elf_path: &Path) -> Result<Vec<StructInfo>> {
    let dwarf = load_dwarf_data(elf_path)?;
    let debug_abbrev = &dwarf.debug_abbrev;
    let mut structs = Vec::new();

    let mut units = dwarf.units();
    while let Some(header) = units.next().map_err(|e| DebugError::DwarfError(e.to_string()))? {
        let abbrev = header.abbreviations(debug_abbrev).map_err(|e| DebugError::DwarfError(e.to_string()))?;

        let mut entries = header.entries(&abbrev);
        while let Some((_, entry)) = entries.next_dfs().map_err(|e| DebugError::DwarfError(e.to_string()))? {
            if entry.tag() == gimli::constants::DW_TAG_structure_type {
                if let Some(name) = get_string(&entry, &dwarf, gimli::constants::DW_AT_name) {
                    let size = get_attr_u64(&entry, gimli::constants::DW_AT_byte_size).unwrap_or(0);
                    structs.push(StructInfo { name, size });
                }
            }
        }
    }

    Ok(structs)
}

// =============================================================================
// Variable Lookup (for read_symbol)
// =============================================================================

/// 查找全局/静态变量信息
pub fn get_variable_info(elf_path: &Path, var_name: &str) -> Result<VariableInfo> {
    debug!("Looking up variable '{}' in {}", var_name, elf_path.display());
    let dwarf = load_dwarf_data(elf_path)?;
    let debug_abbrev = &dwarf.debug_abbrev;

    let mut units = dwarf.units();
    while let Some(header) = units.next().map_err(|e| DebugError::DwarfError(e.to_string()))? {
        let abbrev = header.abbreviations(debug_abbrev).map_err(|e| DebugError::DwarfError(e.to_string()))?;
        let unit = dwarf.unit(header).map_err(|e| DebugError::DwarfError(e.to_string()))?;

        let mut entries = unit.entries();
        while let Some((_, entry)) = entries.next_dfs().map_err(|e| DebugError::DwarfError(e.to_string()))? {
            // 查找 DW_TAG_variable（全局变量）
            if entry.tag() == gimli::constants::DW_TAG_variable {
                if let Some(name) = get_string(&entry, &dwarf, gimli::constants::DW_AT_name) {
                    if name == var_name {
                        // 获取地址
                        let address = get_variable_address(&entry, unit.encoding())?;
                        // 获取类型
                        let type_info = resolve_type_from_entry(&entry, &unit, &abbrev, &dwarf)?;

                        return Ok(VariableInfo {
                            name: name.to_string(),
                            address,
                            type_info,
                        });
                    }
                }
            }
        }
    }

    Err(DebugError::VariableNotFound(var_name.to_string()))
}

/// 从 DW_AT_location 获取变量地址
fn get_variable_address(entry: &DebuggingInformationEntry, encoding: gimli::Encoding) -> Result<u64> {
    if let Some(attr) = entry.attr(gimli::constants::DW_AT_location)
        .map_err(|e| DebugError::DwarfError(e.to_string()))?
    {
        match attr.value() {
            gimli::AttributeValue::Exprloc(expr) => {
                // 解析简单的 DW_OP_addr 表达式
                let mut ops = expr.operations(encoding);
                if let Ok(Some(op)) = ops.next() {
                    if let gimli::Operation::Address { address } = op {
                        return Ok(address);
                    }
                }
            }
            gimli::AttributeValue::Udata(addr) => return Ok(addr),
            _ => {}
        }
    }
    Err(DebugError::DwarfError("Cannot determine variable address".to_string()))
}

/// 从 DW_AT_type 引用解析类型信息
fn resolve_type_from_entry(
    entry: &DebuggingInformationEntry,
    unit: &gimli::Unit<EndianSlice<LittleEndian>>,
    abbrev: &Abbreviations,
    dwarf: &DwarfData,
) -> Result<TypeInfo> {
    if let Some(attr) = entry.attr(gimli::constants::DW_AT_type)
        .map_err(|e| DebugError::DwarfError(e.to_string()))?
    {
        match attr.value() {
            gimli::AttributeValue::UnitRef(offset) => {
                return resolve_type_at_offset(offset, unit, abbrev, dwarf);
            }
            _ => {}
        }
    }
    Ok(TypeInfo::Unknown { size: 0, name: None })
}

/// 根据偏移量解析类型
fn resolve_type_at_offset(
    offset: UnitOffset,
    unit: &gimli::Unit<EndianSlice<LittleEndian>>,
    abbrev: &Abbreviations,
    dwarf: &DwarfData,
) -> Result<TypeInfo> {
    let mut entries = unit.entries_at_offset(offset)
        .map_err(|e| DebugError::DwarfError(e.to_string()))?;

    if let Some((_, entry)) = entries.next_dfs().map_err(|e| DebugError::DwarfError(e.to_string()))? {
        return parse_type_entry(&entry, unit, abbrev, dwarf);
    }

    Ok(TypeInfo::Unknown { size: 0, name: None })
}

/// 解析类型 DIE
fn parse_type_entry(
    entry: &DebuggingInformationEntry,
    unit: &gimli::Unit<EndianSlice<LittleEndian>>,
    abbrev: &Abbreviations,
    dwarf: &DwarfData,
) -> Result<TypeInfo> {
    let tag = entry.tag();
    let size = get_attr_u64(entry, gimli::constants::DW_AT_byte_size).unwrap_or(0);
    let name = get_string(entry, dwarf, gimli::constants::DW_AT_name);

    match tag {
        gimli::constants::DW_TAG_base_type => {
            let encoding = entry.attr(gimli::constants::DW_AT_encoding)
                .ok().flatten()
                .and_then(|a| match a.value() {
                    gimli::AttributeValue::Encoding(e) => Some(e),
                    _ => None,
                });

            let prim = match (encoding, size) {
                (Some(gimli::constants::DW_ATE_unsigned), 1) => PrimitiveType::U8,
                (Some(gimli::constants::DW_ATE_signed), 1) => PrimitiveType::I8,
                (Some(gimli::constants::DW_ATE_unsigned), 2) => PrimitiveType::U16,
                (Some(gimli::constants::DW_ATE_signed), 2) => PrimitiveType::I16,
                (Some(gimli::constants::DW_ATE_unsigned), 4) => PrimitiveType::U32,
                (Some(gimli::constants::DW_ATE_signed), 4) => PrimitiveType::I32,
                (Some(gimli::constants::DW_ATE_unsigned), 8) => PrimitiveType::U64,
                (Some(gimli::constants::DW_ATE_signed), 8) => PrimitiveType::I64,
                (Some(gimli::constants::DW_ATE_float), 4) => PrimitiveType::F32,
                (Some(gimli::constants::DW_ATE_float), 8) => PrimitiveType::F64,
                (Some(gimli::constants::DW_ATE_boolean), _) => PrimitiveType::Bool,
                (Some(gimli::constants::DW_ATE_unsigned_char), _) => PrimitiveType::Char,
                (Some(gimli::constants::DW_ATE_signed_char), _) => PrimitiveType::Char,
                _ => return Ok(TypeInfo::Unknown { size, name }),
            };
            Ok(TypeInfo::Primitive(prim))
        }

        gimli::constants::DW_TAG_pointer_type => {
            let target = resolve_type_from_entry(entry, unit, abbrev, dwarf)?;
            Ok(TypeInfo::Pointer { target: Box::new(target), size })
        }

        gimli::constants::DW_TAG_array_type => {
            let element = resolve_type_from_entry(entry, unit, abbrev, dwarf)?;
            // 获取数组大小（从子 DIE DW_TAG_subrange_type）
            let count = get_array_count(entry, unit, abbrev)?;
            let total_size = element.size() * count as u64;
            Ok(TypeInfo::Array {
                element: Box::new(element),
                count,
                size: total_size
            })
        }

        gimli::constants::DW_TAG_structure_type => {
            let struct_name = name.unwrap_or_else(|| "<anonymous>".to_string());
            let members = parse_struct_members(entry, unit, abbrev, dwarf)?;
            Ok(TypeInfo::Struct { name: struct_name, size, members })
        }

        gimli::constants::DW_TAG_enumeration_type => {
            let enum_name = name.unwrap_or_else(|| "<anonymous>".to_string());
            let variants = parse_enum_variants(entry, unit, abbrev, dwarf)?;
            Ok(TypeInfo::Enum { name: enum_name, size, variants })
        }

        gimli::constants::DW_TAG_typedef | gimli::constants::DW_TAG_const_type | gimli::constants::DW_TAG_volatile_type => {
            // 透传到底层类型
            resolve_type_from_entry(entry, unit, abbrev, dwarf)
        }

        _ => Ok(TypeInfo::Unknown { size, name }),
    }
}

/// 获取数组元素数量
fn get_array_count(
    _entry: &DebuggingInformationEntry,
    _unit: &gimli::Unit<EndianSlice<LittleEndian>>,
    _abbrev: &Abbreviations,
) -> Result<usize> {
    // 简化实现：从 DW_AT_count 或 DW_TAG_subrange_type 获取
    // 完整实现需要遍历子 DIE
    Ok(1) // 默认返回 1，后续可完善
}

/// 解析结构体成员
fn parse_struct_members(
    _entry: &DebuggingInformationEntry,
    _unit: &gimli::Unit<EndianSlice<LittleEndian>>,
    _abbrev: &Abbreviations,
    _dwarf: &DwarfData,
) -> Result<Vec<TypedMember>> {
    // 简化实现：需要遍历子 DIE 获取成员
    // 完整实现需要递归解析每个 DW_TAG_member
    Ok(Vec::new())
}

/// 解析枚举变体
fn parse_enum_variants(
    _entry: &DebuggingInformationEntry,
    _unit: &gimli::Unit<EndianSlice<LittleEndian>>,
    _abbrev: &Abbreviations,
    _dwarf: &DwarfData,
) -> Result<Vec<EnumVariant>> {
    Ok(Vec::new())
}

// =============================================================================
// Expression Resolution
// =============================================================================

/// 解析表达式并返回地址和类型
/// 支持: "var", "var.member", "var[index]", "var.member[index]"
pub fn resolve_expression(elf_path: &Path, expr: &str) -> Result<ResolvedSymbol> {
    let parts: Vec<&str> = expr.split('.').collect();
    if parts.is_empty() {
        return Err(DebugError::DwarfError("Empty expression".to_string()));
    }

    // 解析第一部分（可能包含数组索引）
    let (var_name, index) = parse_name_and_index(parts[0]);
    let var_info = get_variable_info(elf_path, var_name)?;

    let mut current_address = var_info.address;
    let mut current_type = var_info.type_info;

    // 处理数组索引
    if let Some(idx) = index {
        if let TypeInfo::Array { element, .. } = &current_type {
            current_address += idx as u64 * element.size();
            current_type = (**element).clone();
        } else {
            return Err(DebugError::DwarfError(format!("'{}' is not an array", var_name)));
        }
    }

    // 处理成员访问
    for part in parts.iter().skip(1) {
        let (member_name, member_index) = parse_name_and_index(part);

        if let TypeInfo::Struct { members, .. } = &current_type {
            let member = members.iter()
                .find(|m| m.name == member_name)
                .ok_or_else(|| DebugError::MemberNotFound(
                    current_type.type_name(),
                    member_name.to_string()
                ))?;

            current_address += member.offset;
            current_type = member.type_info.clone();

            // 处理成员的数组索引
            if let Some(idx) = member_index {
                if let TypeInfo::Array { element, .. } = &current_type {
                    current_address += idx as u64 * element.size();
                    current_type = (**element).clone();
                }
            }
        } else {
            return Err(DebugError::DwarfError(format!(
                "Cannot access member '{}' on non-struct type", member_name
            )));
        }
    }

    Ok(ResolvedSymbol {
        expression: expr.to_string(),
        address: current_address,
        type_info: current_type,
    })
}

/// 解析名称和可选的数组索引: "name[5]" -> ("name", Some(5))
fn parse_name_and_index(s: &str) -> (&str, Option<usize>) {
    if let Some(bracket_pos) = s.find('[') {
        let name = &s[..bracket_pos];
        let index_str = &s[bracket_pos + 1..s.len() - 1];
        let index = index_str.parse().ok();
        (name, index)
    } else {
        (s, None)
    }
}

// =============================================================================
// Value Interpretation
// =============================================================================

/// 将原始字节解释为类型化的 JSON 值
pub fn interpret_value(data: &[u8], type_info: &TypeInfo) -> Result<serde_json::Value> {
    match type_info {
        TypeInfo::Primitive(prim) => interpret_primitive(data, prim),

        TypeInfo::Pointer { size, .. } => {
            let addr = match *size {
                4 => read_u32_le(data) as u64,
                8 => read_u64_le(data),
                _ => 0,
            };
            Ok(serde_json::json!(format!("0x{:08X}", addr)))
        }

        TypeInfo::Array { element, count, .. } => {
            let elem_size = element.size() as usize;
            let mut values = Vec::new();
            for i in 0..*count {
                let start = i * elem_size;
                let end = start + elem_size;
                if end <= data.len() {
                    values.push(interpret_value(&data[start..end], element)?);
                }
            }
            Ok(serde_json::Value::Array(values))
        }

        TypeInfo::Struct { members, .. } => {
            let mut obj = serde_json::Map::new();
            for member in members {
                let start = member.offset as usize;
                let end = start + member.type_info.size() as usize;
                if end <= data.len() {
                    let value = interpret_value(&data[start..end], &member.type_info)?;
                    obj.insert(member.name.clone(), value);
                }
            }
            Ok(serde_json::Value::Object(obj))
        }

        TypeInfo::Enum { size, variants, .. } => {
            let raw_value = match *size {
                1 => data[0] as i64,
                2 => read_u16_le(data) as i64,
                4 => read_u32_le(data) as i64,
                _ => 0,
            };
            // 查找匹配的枚举变体
            if let Some(variant) = variants.iter().find(|v| v.value == raw_value) {
                Ok(serde_json::json!({ "variant": variant.name, "value": raw_value }))
            } else {
                Ok(serde_json::json!(raw_value))
            }
        }

        TypeInfo::Unknown { size, .. } => {
            // 返回原始十六进制
            let hex: Vec<String> = data.iter().take(*size as usize).map(|b| format!("{:02X}", b)).collect();
            Ok(serde_json::json!(hex.join(" ")))
        }
    }
}

fn interpret_primitive(data: &[u8], prim: &PrimitiveType) -> Result<serde_json::Value> {
    Ok(match prim {
        PrimitiveType::U8 => serde_json::json!(data[0]),
        PrimitiveType::I8 => serde_json::json!(data[0] as i8),
        PrimitiveType::U16 => serde_json::json!(read_u16_le(data)),
        PrimitiveType::I16 => serde_json::json!(read_u16_le(data) as i16),
        PrimitiveType::U32 => serde_json::json!(read_u32_le(data)),
        PrimitiveType::I32 => serde_json::json!(read_u32_le(data) as i32),
        PrimitiveType::U64 => serde_json::json!(read_u64_le(data)),
        PrimitiveType::I64 => serde_json::json!(read_u64_le(data) as i64),
        PrimitiveType::F32 => serde_json::json!(f32::from_le_bytes([data[0], data[1], data[2], data[3]])),
        PrimitiveType::F64 => serde_json::json!(f64::from_le_bytes([
            data[0], data[1], data[2], data[3], data[4], data[5], data[6], data[7]
        ])),
        PrimitiveType::Bool => serde_json::json!(data[0] != 0),
        PrimitiveType::Char => serde_json::json!((data[0] as char).to_string()),
    })
}

fn read_u16_le(data: &[u8]) -> u16 {
    u16::from_le_bytes([data[0], data[1]])
}

fn read_u32_le(data: &[u8]) -> u32 {
    u32::from_le_bytes([data[0], data[1], data[2], data[3]])
}

fn read_u64_le(data: &[u8]) -> u64 {
    u64::from_le_bytes([data[0], data[1], data[2], data[3], data[4], data[5], data[6], data[7]])
}

// =============================================================================
// Legacy Types (保持向后兼容)
// =============================================================================

#[derive(Debug, Clone)]
pub struct StructLayout {
    pub name: String,
    pub size: u64,
    pub alignment: u64,
    pub members: Vec<StructMember>,
}

#[derive(Debug, Clone)]
pub struct StructMember {
    pub name: String,
    pub offset: u64,
    pub size: u64,
    pub type_name: String,
}

#[derive(Debug, Clone)]
pub struct StructInfo {
    pub name: String,
    pub size: u64,
}