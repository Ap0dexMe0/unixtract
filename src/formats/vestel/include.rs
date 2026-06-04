pub const VESTEL_PARTITIONS: &[(&str, (usize, usize))] = &[
    ("kernel", (0x000000, 0x700000)),
    ("rootfs", (0x700000, 0x1A00000)),
    ("vendor", (0x2100000, 0x9A00000)),
    ("conf",   (0xBB00000, 0x1E00000)),
    ("apd",    (0xD900000, 0x1100000)),
    ("tee",    (0xEA00000, 0x504800)),
    ("buf",    (0xEF04800, 0x400000)),
];

pub const MB230_PARTITIONS: &[(&str, (usize, usize))] = &[
    ("xboot",         (0x000000, 0x0C0000)),
    ("xboot_code",    (0x0C0000, 0x200000)),
    ("uboot",         (0x380000, 0x140000)),
    ("kernel_dtb",    (0x4C0000, 0xD20000)),
    ("ubi_volume",    (0x1280000, 0x9B40000)),
    ("ubifs",         (0xADC0000, 0x1BC0000)),
    ("squashfs_area", (0xC980000, 0x680000)),
    ("app_modules",   (0xD000000, 0x1600000)),
];