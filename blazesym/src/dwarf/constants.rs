pub const DW_UT_compile: u8 = 0x1;
pub const DW_UT_type: u8 = 0x2;

pub const DW_TAG_array_type: u8 = 0x1;
pub const DW_TAG_enumeration_type: u8 = 0x4;
pub const DW_TAG_compile_unit: u8 = 0x11;
pub const DW_TAG_subprogram: u8 = 0x2e;
pub const DW_TAG_variable: u8 = 0x34;
pub const DW_TAG_namespace: u8 = 0x39;

pub const DW_CHILDREN_no: u8 = 0x00;
pub const DW_CHILDREN_yes: u8 = 0x01;

pub const DW_AT_sibling: u8 = 0x01;
pub const DW_AT_location: u8 = 0x02;
pub const DW_AT_name: u8 = 0x03;
pub const DW_AT_lo_pc: u8 = 0x11;
pub const DW_AT_hi_pc: u8 = 0x12;
pub const DW_AT_entry_pc: u8 = 0x52;
pub const DW_AT_linkage_name: u8 = 0x6e;

pub const DW_FORM_addr: u8 = 0x01;
pub const DW_FORM_block2: u8 = 0x03;
pub const DW_FORM_block4: u8 = 0x04;
pub const DW_FORM_data2: u8 = 0x05;
pub const DW_FORM_data4: u8 = 0x06;
pub const DW_FORM_data8: u8 = 0x07;
pub const DW_FORM_string: u8 = 0x08;
pub const DW_FORM_block: u8 = 0x09;
pub const DW_FORM_block1: u8 = 0x0a;
pub const DW_FORM_data1: u8 = 0x0b;
pub const DW_FORM_flag: u8 = 0x0c;
pub const DW_FORM_sdata: u8 = 0x0d;
pub const DW_FORM_strp: u8 = 0x0e;
pub const DW_FORM_udata: u8 = 0x0f;
pub const DW_FORM_ref_addr: u8 = 0x10;
pub const DW_FORM_ref1: u8 = 0x11;
pub const DW_FORM_ref2: u8 = 0x12;
pub const DW_FORM_ref4: u8 = 0x13;
pub const DW_FORM_ref8: u8 = 0x14;
pub const DW_FORM_ref_udata: u8 = 0x15;
pub const DW_FORM_indirect: u8 = 0x16;
pub const DW_FORM_sec_offset: u8 = 0x17;
pub const DW_FORM_exprloc: u8 = 0x18;
pub const DW_FORM_flag_present: u8 = 0x19;
pub const DW_FORM_strx: u8 = 0x1a;
pub const DW_FORM_addrx: u8 = 0x1b;
pub const DW_FORM_ref_sup4: u8 = 0x1c;
pub const DW_FORM_strp_sup: u8 = 0x1d;
pub const DW_FORM_data16: u8 = 0x1e;
pub const DW_FORM_line_strp: u8 = 0x1f;
pub const DW_FORM_ref_sig8: u8 = 0x20;
pub const DW_FORM_implicit_const: u8 = 0x21;
pub const DW_FORM_loclistx: u8 = 0x22;
pub const DW_FORM_rnglistx: u8 = 0x23;
pub const DW_FORM_ref_sup8: u8 = 0x24;
pub const DW_FORM_str1: u8 = 0x25;
pub const DW_FORM_str2: u8 = 0x26;
pub const DW_FORM_str3: u8 = 0x27;
pub const DW_FORM_str4: u8 = 0x28;
pub const DW_FORM_addrx1: u8 = 0x29;
pub const DW_FORM_addrx2: u8 = 0x2a;
pub const DW_FORM_addrx3: u8 = 0x2b;
pub const DW_FORM_addrx4: u8 = 0x2c;
