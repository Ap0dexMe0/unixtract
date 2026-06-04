pub const VESTEL_PARTITIONS: &[(&str, (usize, usize))] = &[
    ("kernel", (0x000000, 0x700000)),
    ("rootfs", (0x700000, 0x1A00000)),
    ("vendor", (0x2100000, 0x9A00000)),
    ("conf",   (0xBB00000, 0x1E00000)),
    ("apd",    (0xD900000, 0x1100000)),
    ("tee",    (0xEA00000, 0x504800)),
    ("buf",    (0xEF04800, 0x400000)),
];

pub struct VestelCtx {
    pub is_encrypted: bool,
}
