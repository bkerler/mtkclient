class NandExtension:
    # uni=0, multi=1
    cellusage = 0
    # logical=0, physical=1, physical_pmt=2
    addr_type = 0
    # raw=0, ubi_img=1, ftl_img=2
    bin_type = 0
    region = 0
    # operation_type -> spare=0,page=1,page_ecc=2,page_spare_ecc=3,verify=4,page_spare_norandom,page_fdm
    # nand_format_level -> format_normal=0,force=1,mark_bad_block=2,level_end=3
    operation_type = 0  # or nand_format_level
    format_level = 0
    sys_slc_percent = 0
    usr_slc_percent = 0
    phy_max_size = 0
