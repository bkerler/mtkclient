class DAmodes:
    LEGACY = 3
    XFLASH = 5
    XML = 6


class Efuse:
    efuses = []
    internal_fuses = []
    external_fuses = []

    def __init__(self, base, hwcode):
        if hwcode in [0x6570, 0x6580, 0x321, 0x335]:
            self.efuses = [base + 0x20, base + 0x30, base + 0x38, base + 0x40, base + 0x44,
                           base + 0x48, base + 0x60, base + 0x180, base + 0x184, base + 0x188,
                           base + 0x120, base + 0x130, base + 0x140, base + 0x144, base + 0x18C,
                           base + 0x190, base + 0x194, base + 0x198, base + 0x19C, base + 0x1A0,
                           0x8000000, base + 0x1A4, base + 0x1A8, base + 0x1AC, base + 0x1B0,
                           base + 0x270, base + 0x300, base + 0x304, base + 0x308, base + 0x30C,
                           base + 0x310, base + 0x314]
        elif hwcode in [0x1209]:
            self.efuses = [base + 0x020, base + 0x030, base + 0x038, base + 0x040, base + 0x044,
                           base + 0x048, base + 0x04C, base + 0x050, base + 0xC3C, 0x8000000,
                           0xA, 0x8000008, base + 0x140, base + 0x144, base + 0x148,
                           base + 0x14C, base + 0x7A0, base + 0x7A4, base + 0x7A8, base + 0x7AC,
                           0x8000000, base + 0x7B0, base + 0x7B4, base + 0x7B8, base + 0x7BC,
                           base + 0x7C0, base + 0x7C4, base + 0x7C8, base + 0x7CC, 0x1D,
                           0x1E, base + 0x060, base + 0x130, base + 0x008, base + 0x120,
                           base + 0x260, base + 0x264, base + 0x268, base + 0x284, 0x8000000,
                           base + 0x5B4, base + 0x5B8, base + 0x5BC, base + 0x5C0, base + 0x5C4,
                           base + 0x5C8, base + 0x5CC, 0x8000000, 0x8000000, 0x8000000,
                           0x8000000, 0x8000000, 0x8000000, 0x8000000, 0x8000000,
                           0x8000000, base + 0x090, base + 0x094, base + 0x098, base + 0x09C,
                           base + 0x0A0, base + 0x0A4, base + 0x0A8, base + 0x0AC, 0x8000000,
                           0x8000000, 0x8000000, 0x8000000, 0x8000000, 0x8000000,
                           0x8000000, 0x8000000, 0x8000000, 0x8000000, 0x8000000,
                           0x8000000, 0x8000000, 0x8000000, 0x8000000, 0x8000000,
                           0x8000000, 0x8000000, 0x8000000, 0x8000000, 0x8000000,
                           0x8000000, 0x8000000, 0x8000000, 0x8000000, 0x8000000,
                           0x8000000, 0x8000000, 0x8000000, 0x8000000, 0x8000000,
                           0x8000000, 0x8000000, 0x8000000, 0x8000000, 0x8000000,
                           0x8000000, 0x8000000, 0x8000000, 0x8000000, base + 0x4A0,
                           base + 0x4E0, base + 0x4A8, base + 0x810, base + 0x814, base + 0x818,
                           base + 0x81C, base + 0x820, base + 0x824, base + 0x828, base + 0x82C,
                           base + 0x5E4, base + 0x5E8, base + 0x580]
        elif hwcode in [0x551]:
            self.efuses = [base + 0x20, base + 0x30, base + 0x38, base + 0x40, base + 0x44,
                           base + 0x48, base + 0x60, base + 0x260, base + 0x264, base + 0x268,
                           base + 0x120, base + 0x130, base + 0x140, base + 0x144, base + 0x26C,
                           base + 0x270, base + 0x274, base + 0x760, base + 0x7A0, 0x8000000,
                           0x8000000, base + 0x4C, base + 0x50, base + 0x7A4, base + 0x7B0,
                           base + 0x278, base + 0x27C, base + 0x280, base + 0x284, base + 0x58,
                           base + 0x54, base + 0x288, 0x8000000, 0x8000000, 0x8000008, base + 0x580,
                           base + 0x7C8]
        elif hwcode in [0x1208]:
            self.efuses = [base + 0x20, base + 0x30, base + 0x38, base + 0x40, base + 0x44,
                           base + 0x48, base + 0x4C, base + 0x50, base + 0x6A0, base + 0x6A4,
                           0xA, 0x8000008, base + 0x140, base + 0x144, base + 0x148,
                           base + 0x14C, base + 0x7A0, base + 0x7A4, base + 0x7A8, base + 0x7AC,
                           0x8000000, base + 0x7B0, base + 0x7B4, base + 0x7B8, base + 0x7BC,
                           base + 0x7C0, base + 0x7C4, base + 0x7C8, base + 0x7CC, 0x1D,
                           0x1E, base + 0x060, base + 0x130, base + 0x11C, base + 0x120,
                           base + 0x260, base + 0x264, base + 0x268, base + 0x6A8, base + 0x6AC,
                           base + 0x5B4, base + 0x5B8, base + 0x5BC, base + 0x5C0, base + 0x5C4,
                           base + 0x5C8, base + 0x5CC, base + 0x5D0, base + 0x5D4, base + 0x5D8,
                           base + 0x5DC, base + 0x5E0, base + 0x580, base + 0x5E4, base + 0x5E8,
                           base + 0x090, base + 0x094, base + 0x098, base + 0x09C, base + 0x0A0,
                           base + 0x0A4, base + 0x0A8, base + 0x0AC, base + 0x810, base + 0x814,
                           base + 0x818, base + 0x81C, base + 0x820, base + 0x824, base + 0x828,
                           base + 0x82C, base + 0x964]
        elif hwcode in [0x6582, 0x6595, 0x6752, 0x6795, 0x6592]:
            self.efuses = [base + 0x20, base + 0x30, base + 0x38, base + 0x40, base + 0x44,
                           base + 0x48, base + 0x60, base + 0x100, base + 0x104, base + 0x108,
                           base + 0x120, base + 0x130, base + 0x140, base + 0x144, base + 0x170,
                           base + 0x174, base + 0x178, base + 0x17C, base + 0x180, base + 0x184,
                           0x8000000, base + 0x188, base + 0x504, base + 0x514, base + 0x518,
                           base + 0x51C, base + 0x520, base + 0x524, base + 0x528, base + 0x52C,
                           base + 0x530, base + 0x534, base + 0x538, base + 0x540, base + 0x544,
                           base + 0x548, base + 0x4C4, base + 0x4C8]
        elif hwcode in [0x6572]:
            self.efuses = [0x40, 0x100000, base + 0x20, base + 0x30, base + 0x38,
                           base + 0x40, base + 0x44, base + 0x48, base + 0x60, base + 0x100,
                           base + 0x104, base + 0x108, base + 0x120, base + 0x130, base + 0x140,
                           base + 0x144, base + 0x170, base + 0x174, base + 0x178, base + 0x17C,
                           base + 0x180, base + 0x184, 0x8000008, base + 0x10C, base + 0x110,
                           base + 0x114, base + 0x118, base + 0x11c]
        elif hwcode in [0x601, 0x326, 0x6757, 0x8695]:
            self.efuses = [base + 0x20, base + 0x30, base + 0x38, base + 0x40, base + 0x44,
                           base + 0x48, base + 0x60, base + 0x180, base + 0x184, base + 0x188,
                           base + 0x120, base + 0x130, base + 0x140, base + 0x144, base + 0x18C,
                           base + 0x190, base + 0x194, base + 0x27C, base + 0x540, 0x8000000,
                           0x8000000, base + 0x4C]
        elif hwcode in [0x688]:
            self.efuses = [
                base + 0x514, 0xFFFFFFFF, 0xE030312, base + 0x408, 0xFFFFFFFF,
                1, base + 0x518, 0xFFFFFFFF, 0xF030313, base + 0x408, 0xFFFFFFFF,
                2, base + 0x51C, 0xFFFFFFFF, 0x10030314, base + 0x408,
                0xFFFFFFFF, 3, base + 0x520, 0xFFFFFFFF, 0x11030315,
                base + 0x408, 0xFFFFFFFF, 4, base + 0x524, 0xFFFFFFFF,
                0x12030316, base + 0x408, 0xFFFFFFFF, 5, base + 0x850,
                0xFFFFFFFF, 0x13040317, base + 0x408, 0xFFFFFFFF, 0xFFFFFFFF,
                base + 0x854, 0xFFFFFFFF, 0x14040318, base + 0x408, 0xFFFFFFFF,
                0xFFFFFFFF, base + 0x858, 0xFFFFFFFF, 0x15040319, base + 0x408,
                0xFFFFFFFF, 0xFFFFFFFF, base + 0x85C, 0xFFFFFFFF, 0x1604031A,
                base + 0x408, 0xFFFFFFFF, 0xFFFFFFFF, base + 0x830, 0x7F,
                0x1805012A, base + 0x52C, 0x7F000000, 0xFFFFFFFF, base + 0x80C,
                0xFFFFFFFF, 0x5012B, base + 0x554, 0xFFFFFFFF, 0xFFFFFFFF,
                base + 0x020, 0x1417, 0x5011B, base + 0x52C, 0x1417, 0xFFFFFFFF,
                base + 0x060, 0x27F, 0x5011C, base + 0x530, 0x27F, 0xFFFFFFFF,
                base + 0x4A0, 3, 0x1405011D, base + 0x530, 0x300000, 0xFFFFFFFF,
                base + 0x4C4, 0xFFFFFFFF, 0x5011E, base + 0x540, 0xFFFFFFFF,
                6, base + 0x4C8, 0xFFFFFFFF, 0x5011F, base + 0x544, 0xFFFFFFFF,
                7, base + 0x808, 0x8000, 0x50120, base + 0xA48, 0x8000,
                0xFFFFFFFF, base + 0x4A4, 8, 0x1C050121, base + 0x550,
                0x80000000, 0xFFFFFFFF, base + 0x4C0, 1, 0xF050122, base + 0x534,
                0x8000, 0xFFFFFFFF, base + 0x4CC, 0x1FF, 0x10050123,
                base + 0x534, 0x1FF0000, 0xFFFFFFFF, base + 0x068, 0x1F,
                0x7050124, base + 0x534, 0xF80, 0xFFFFFFFF, base + 0x028,
                6, 0x1C050125, base + 0x530, 0x60000000, 0xFFFFFFFF,
                base + 0x020, base + 0x030, base + 0x038, base + 0x040, base + 0x044,
                base + 0x048, base + 0x04C, base + 0x050, 0x8000000, 0x8000000,
                0xA, 0x8000008, base + 0x140, base + 0x144, base + 0x148,
                base + 0x14C, base + 0x7A0, base + 0x7A4, base + 0x7A8, base + 0x7AC,
                0x8000000, base + 0x7B0, base + 0x7B4, base + 0x7B8, base + 0x7BC,
                base + 0x7C0, base + 0x7C4, base + 0x7C8, base + 0x7CC, 0x1D,
                0x1E, base + 0x060, base + 0x130, base + 0x11C, base + 0x120,
                base + 0x260, base + 0x264, base + 0x268
            ]
        elif hwcode in [0x699, 0x766]:
            self.efuses = [base + 0x20, base + 0x30, base + 0x38, base + 0x40, base + 0x44,
                           base + 0x48, base + 0x4C, base + 0x50, 0x8000000, base + 0x6A4,
                           0xA, 0x8000008, base + 0x140, base + 0x144, base + 0x148,
                           base + 0x14C, base + 0x7A0, base + 0x7A4, base + 0x7A8, base + 0x7AC,
                           0x8000000, base + 0x7B0, base + 0x7B4, base + 0x7B8, base + 0x7BC,
                           base + 0x7C0, base + 0x7C4, base + 0x7C8, base + 0x7CC, 0x1D,
                           0x1E, base + 0x60, base + 0x130, base + 0x100, base + 0x120,
                           0x8000000, 0x8000000, 0x8000000, base + 0x6A8, base + 0x6AC,
                           base + 0x5BC, base + 0x5A8, base + 0x580]
        elif hwcode in [0x788]:
            self.efuses = [base + 0x20, base + 0x30, base + 0x38, base + 0x40, base + 0x44,
                           base + 0x48, base + 0x4C, base + 0x50, base + 0x6A0, base + 0x6A4,
                           0xA, 0x8000008, base + 0x140, base + 0x144, base + 0x148,
                           base + 0x14C, base + 0x7A0, base + 0x7A4, base + 0x7A8, base + 0x7AC,
                           0x8000000, base + 0x7B0, base + 0x7B4, base + 0x7B8, base + 0x7BC,
                           base + 0x7C0, base + 0x7C4, base + 0x7C8, base + 0x7CC, 0x1D,
                           0x1E, base + 0x60, base + 0x130, base + 0x11C, base + 0x120,
                           base + 0x260, base + 0x264, base + 0x268, base + 0x6A8, base + 0x6AC,
                           base + 0x5BC, base + 0x580, base + 0x928, base + 0x810, base + 0x430,
                           base + 0x40c, 0x20200, base + 0x430, base + 0x40c, 0x30301,
                           base + 0x430, base + 0x40C, 0x40402, base + 0x430, base + 0x40C,
                           0x50503, base + 0x430, base + 0x40C, 0x60604, base + 0x70]
        elif hwcode in [0x717]:
            self.efuses = [base + 0x20, base + 0x30, base + 0x38, base + 0x40, base + 0x44,
                           base + 0x48, base + 0x4C, base + 0x50, 0x8000000, base + 0x6A4,
                           0xA, 0x8000008, base + 0x140, base + 0x144, base + 0x148,
                           base + 0x14C, base + 0x7A0, base + 0x7A4, base + 0x7A8, base + 0x7AC,
                           0x8000000, base + 0x7B0, base + 0x7B4, base + 0x7B8, base + 0x7BC,
                           base + 0x7C0, base + 0x7C4, base + 0x7C8, base + 0x7CC, 0x1D,
                           0x1E, base + 0x60, base + 0x130, base + 0x100, base + 0x120,
                           base + 0x598, 0x8000000, 0x8000000, base + 0x6A8, base + 0x6AC,
                           base + 0x5BC, base + 0x5A8, base + 0x580]
        elif hwcode in [0x690]:
            self.efuses = [base + 0x20, base + 0x30, base + 0x38, base + 0x40, base + 0x44,
                           base + 0x48, base + 0x4C, base + 0x50, 0x8000000, base + 0x6A4,
                           0xA, 0x8000008, base + 0x140, base + 0x144, base + 0x148,
                           base + 0x14C, base + 0x7A0, base + 0x7A4, base + 0x7A8, base + 0x7AC,
                           0x8000000, base + 0x7B0, base + 0x7B4, base + 0x7B8, base + 0x7BC,
                           base + 0x7C0, base + 0x7C4, base + 0x7C8, base + 0x7CC, 0x1D,
                           0x1E, base + 0x60, base + 0x130, base + 0x100, base + 0x120,
                           base + 0x260, base + 0x264, base + 0x268, base + 0x6A8, base + 0x6AC]
        elif hwcode in [0x707, 0x725, 0x813]:
            self.efuses = [base + 0x20, base + 0x30, base + 0x38, base + 0x40, base + 0x44,
                           base + 0x48, base + 0x4C, base + 0x50, base + 0x6A0, base + 0x6A4,
                           0xA, 0x8000008, base + 0x140, base + 0x144, base + 0x148,
                           base + 0x14C, base + 0x7A0, base + 0x7A4, base + 0x7A8, base + 0x7AC,
                           0x8000000, base + 0x7B0, base + 0x7B4, base + 0x7B8, base + 0x7BC,
                           base + 0x7C0, base + 0x7C4, base + 0x7C8, base + 0x7CC, 0x1D,
                           0x1E, base + 0x60, base + 0x130, base + 0x11C, base + 0x120,
                           base + 0x260, base + 0x264, base + 0x268, base + 0x6A8, base + 0x6AC,
                           base + 0x5b4, base + 0x5b8, base + 0x5bc, base + 0x5c0, base + 0x5c4,
                           base + 0x5c8, base + 0x5cc, base + 0x5d0, base + 0x5d4, base + 0x5d8,
                           base + 0x5dc, base + 0x5e0, base + 0x580]
        elif hwcode in [0x279]:
            self.efuses = [base + 0x20, base + 0x30, base + 0x38, base + 0x40, base + 0x44,
                           base + 0x48, base + 0x60, base + 0x180, base + 0x184, base + 0x188,
                           base + 0x120, base + 0x130, base + 0x140, base + 0x144, base + 0x18C,
                           base + 0x190, base + 0x194, base + 0x71C, base + 0x720, base + 0x710,
                           0x8000000, base + 0x4C, base + 0x50, base + 0x54, base + 0x58,
                           base + 0x198, base + 0x19c, base + 0x1A0, base + 0x1A4, 0x1A8,
                           base + 0x714, base + 0x718, base + 0x724, base + 0x8D8, 0x8000008]
        elif hwcode in [0x562]:
            self.efuses = [base + 0x20, base + 0x30, base + 0x38, base + 0x40, base + 0x44,
                           base + 0x48, base + 0x4C, base + 0x260, base + 0x264, base + 0x268,
                           0xA, base + 0x130, base + 0x140, base + 0x144, base + 0x148,
                           base + 0x14C, base + 0x7A8, base + 0x7AC, base + 0x7A0, base + 0x11C,
                           0x8000000, base + 0x4C, base + 0x50, base + 0x7A4, base + 0x7B0,
                           base + 0x120, base + 0x7B4, base + 0x7B8, base + 0x7BC, 0x1D,
                           0x1E, base + 0x288, base + 0x7CC, base + 0x770, 0x8000008,
                           base + 0x7C0, base + 0x7C4, base + 0x7C8, base + 0x94C]
        elif hwcode in [0x989, 0x996, 0x816]:
            self.efuses = [base + 0x20, base + 0x30, base + 0x38, base + 0x40, base + 0x44,
                           base + 0x48, base + 0x4C, base + 0x50, base + 0x6A0, base + 0x6A4,
                           0xA, 0x8000008, base + 0x140, base + 0x144, base + 0x148,
                           base + 0x14C, base + 0x7A0, base + 0x7A4, base + 0x7A8, base + 0x7AC,
                           0x8000000, base + 0x7B0, base + 0x7B4, base + 0x7B8, base + 0x7BC,
                           base + 0x7C0, base + 0x7C4, base + 0x7C8, base + 0x7CC, 0x1D,
                           0x1E, base + 0x60, base + 0x130, base + 0x11C, base + 0x120,
                           base + 0x260, base + 0x264, base + 0x268, base + 0x6A8, base + 0x6AC,
                           base + 0x5b4, base + 0x5b8, base + 0x5bc, base + 0x5c0, base + 0x5c4,
                           base + 0x5c8, base + 0x5cc, base + 0x5d0, base + 0x5d4, base + 0x5d8,
                           base + 0x5dc, base + 0x5e0, base + 0x580, base + 0x5E4, base + 0x5e8]
            self.internal_fuses = [(base + 0x810, 0xFFFFFFFF, 0, 1, 5, 0, base + 0x558, 0xFFFFFFFF, 0),
                                   (base + 0x814, 0xFFFFFFFF, 0, 1, 5, 0, base + 0x55C, 0xFFFFFFFF, 0),
                                   (base + 0x818, 0xFFFFFFFF, 0, 1, 5, 0, base + 0x560, 0xFFFFFFFF, 0),
                                   (base + 0x81C, 0xFFFFFFFF, 0, 1, 5, 0, base + 0x564, 0xFFFFFFFF, 0),
                                   (base + 0x820, 0xFFFFFFFF, 0, 1, 5, 0, base + 0x568, 0xFFFFFFFF, 0),
                                   (base + 0x824, 0xFFFFFFFF, 0, 1, 5, 0, base + 0x56C, 0xFFFFFFFF, 0),
                                   (base + 0x828, 0xFFFFFFFF, 0, 1, 5, 0, base + 0x570, 0xFFFFFFFF, 0),
                                   (base + 0x82C, 0xFFFFFFFF, 0, 1, 5, 0, base + 0x574, 0xFFFFFFFF, 0),
                                   (base + 0x160, 0xFFFFFFFF, 0, 3, 5, 0x1B, base + 0xA18, 0x7F, 1),
                                   (base + 0x164, 0xFFFFFFFF, 0, 3, 5, 0x1C, base + 0xA18, 0x3F80, 1),
                                   (base + 0x168, 0xFFFFFFFF, 0, 3, 5, 0x1D, base + 0xA18, 0x1FC000, 1),
                                   (base + 0x16C, 0xFFFFFFFF, 0, 3, 5, 0x1E, base + 0xA18, 0xFE00000, 1),
                                   (base + 0x170, 0xFFFFFFFF, 0, 3, 5, 0x1F, base + 0xA1C, 0x7F, 1),
                                   (base + 0x174, 0xFFFFFFFF, 0, 3, 5, 0x20, base + 0xA1C, 0x3F80, 1),
                                   (base + 0x178, 0xFFFFFFFF, 0, 3, 5, 0x21, base + 0xA1C, 0x1FC000, 1),
                                   (base + 0x17C, 0xFFFFFFFF, 0, 3, 5, 0x22, base + 0xA1C, 0xFE00000, 1),
                                   (base + 0x070, 0xFFFFFFFF, 0, 3, 0, 0, base + 0x528, 0x7F, 0),
                                   (base + 0x074, 0xFFFFFFFF, 0, 3, 0, 1, base + 0x528, 0x3F80, 0),
                                   (base + 0x078, 0xFFFFFFFF, 0, 3, 0, 2, base + 0x528, 0x1FC000, 0),
                                   (base + 0x07C, 0xFFFFFFFF, 0, 3, 0, 3, base + 0x528, 0xFE00000, 0),
                                   (base + 0x850, 0xFFFFFFFF, 0, 3, 4, 0x13, base + 0x550, 0x7F, 0),
                                   (base + 0x854, 0xFFFFFFFF, 0, 3, 4, 0x14, base + 0x550, 0x3F80, 0),
                                   (base + 0x858, 0xFFFFFFFF, 0, 3, 4, 0x15, base + 0x550, 0x1FC000, 0),
                                   (base + 0x85C, 0xFFFFFFFF, 0, 3, 4, 0x16, base + 0x550, 0xFE00000, 0),
                                   (base + 0x808, 0xFFFFFFFF, 0, 1, 5, 0, base + 0xA48, 0xFFFFFFFF, 1),
                                   (base + 0x80C, 0xFFFFFFFF, 0, 1, 5, 0, base + 0x554, 0xFFFFFFFF, 0),
                                   (base + 0x830, 0x7F, 0, 1, 5, 0x18, base + 0x52C, 0x7F000000, 0),
                                   (base + 0x800, 0xFFFFFFFF, 0, 1, 5, 0, base + 0xA40, 0xFFFFFFFF, 1),
                                   (base + 0x804, 0xFFFFFFFF, 0, 1, 5, 0, base + 0xA44, 0xFFFFFFFF, 1),
                                   (base + 0x870, 0xFFFFFFFF, 0, 3, 5, 0x53, base + 0xA30, 0x7F, 1),
                                   (base + 0x874, 0xFFFFFFFF, 0, 3, 5, 0x54, base + 0xA30, 0x3F80, 1)]
            self.external_fuses = [base + 0x510, base + 0x514, base + 0x518, base + 0x51C,
                                   base + 0x520, base + 0x524, base + 0x4C4, base + 0x4C8]
        elif hwcode in [0x8163]:
            self.efuses = [base + 0x20, base + 0x30, base + 0x38, base + 0x40, base + 0x44,
                           base + 0x48, base + 0x60, base + 0x100, base + 0x104, base + 0x108,
                           base + 0x120, base + 0x130, base + 0x140, base + 0x144, base + 0x170,
                           base + 0x174, base + 0x178, base + 0x17C, base + 0x180, base + 0x184,
                           0x8000000, base + 0x188, base + 0x1B0, base + 0x1B4, base + 0x1B8,
                           base + 0x1BC, base + 0x1C0, base + 0x1C4, base + 0x1C8, base + 0x1CC,
                           base + 0x4C, base + 0x50, base + 0x54, base + 0x90, base + 0x94,
                           base + 0x98, base + 0x9C, base + 0xA0, base + 0xA4, base + 0xA8,
                           base + 0xAC]
        elif hwcode in [0x8167]:
            self.efuses = [base + 0x20, base + 0x30, base + 0x38, base + 0x40, base + 0x44,
                           0x8000000, base + 0x60, base + 0x260, base + 0x264, base + 0x268,
                           base + 0x120, base + 0x130, base + 0x140, base + 0x144, base + 0x26C,
                           base + 0x270, base + 0x274, base + 0x278, base + 0x27C, base + 0x280,
                           0x8000000, base + 0x284, base + 0x850, base + 0x854, base + 0x858,
                           base + 0x85C, base + 0x860, base + 0x864, base + 0x868, base + 0x86C,
                           base + 0x320, 0x8000008, base + 0x560, base + 0x90, base + 0x94,
                           base + 0x98, base + 0x9C, base + 0xA0, base + 0xA4, base + 0xA8,
                           base + 0xAC, base + 0x250, base + 0x254, base + 0x258, base + 0x25C,
                           base + 0x300, base + 0x304, base + 0x308, base + 0x30C, 0x8000000,
                           base + 0x310, base + 0x540, base + 0x544, base + 0x548, base + 0x54C,
                           base + 0x550, base + 0x558, base + 0x55C, base + 0x050, 0x8000000,
                           base + 0x180, base + 0x184, base + 0x188, base + 0x18C, base + 0x190,
                           base + 0x194, base + 0x198, base + 0x580, base + 0x584, base + 0x588,
                           base + 0x58C, base + 0x590, base + 0x594, base + 0x598, base + 0x068,
                           base + 0x028, base + 0x070, base + 0x074, base + 0x078, base + 0x07C
                           ]
        elif hwcode in [0x8176]:
            self.efuses = [base + 0x20, base + 0x30, base + 0x38, base + 0x40, base + 0x44,
                           base + 0x274, base + 0x60, base + 0x100, base + 0x104, base + 0x108,
                           base + 0x120, base + 0x130, base + 0x140, base + 0x144, base + 0x170,
                           base + 0x174, base + 0x178, base + 0x17C, base + 0x180, base + 0x184,
                           0x8000000, base + 0x188, base + 0x504, base + 0x514, base + 0x700,
                           base + 0x704, base + 0x708, base + 0x70C, base + 0x528, base + 0x52C,
                           base + 0x530, base + 0x534, base + 0x538, base + 0x540, base + 0x544,
                           base + 0x548, base + 0x4C4, base + 0x4C8, base + 0x4B0, base + 0x4B8,
                           base + 0x90, base + 0x94, base + 0x98, base + 0x9C, base + 0xA0,
                           base + 0xA4, base + 0xA8, base + 0xAC]
        elif hwcode in [0x1172]:
            self.efuses = [
                base + 0x20, base + 0x30, base + 0x38, base + 0x40, base + 0x44,
                base + 0x48, base + 0x4C, base + 0x50, base + 0x54, base + 0x58,
                0xA, 0x8000008, base + 0x140, base + 0x144, base + 0x148,
                base + 0x14C, base + 0x7A0, base + 0x7A4, base + 0x7A8, base + 0x7AC,
                0x8000000, base + 0x7B0, base + 0x7B4, base + 0x7B8, base + 0x7BC,
                base + 0x7C0, base + 0x7C4, base + 0x7C8, base + 0x7CC, 0x1D,
                0x1E, base + 0x60, base + 0x130, base + 0x08, base + 0x120,
                base + 0x260, base + 0x264, base + 0x268, base + 0x8F8, base + 0x810,
                base + 0x5B4, base + 0x5B8, base + 0x5BC, base + 0x5C0, base + 0x5C4,
                base + 0x5C8, base + 0x5CC, base + 0x5D0, base + 0x5D4, base + 0x5D8,
                base + 0x5DC, base + 0x5E0, base + 0x580, base + 0x5E4, base + 0x5E8,
                base + 0x64, base + 0x4A0, base + 0x4E0, base + 0x4A8, base + 0x90,
                base + 0x94, base + 0x98, base + 0x9C, base + 0xA0, base + 0xA4,
                base + 0xA8, base + 0xAC, base + 0x810, base + 0x814, base + 0x818,
                base + 0x81C, base + 0x820, base + 0x824, base + 0x828, base + 0x82C,
                base + 0xCB8, base + 0xD74
            ]
        elif hwcode in [0x1471]:
            self.efuses = [
                base + 0x20, base + 0x30, base + 0x38, base + 0x1000, base + 0x1004,
                base + 0x1008, base + 0x100C, base + 0x1010, base + 0x1014, base + 0x1018,
                0xA, 0xF00008, base + 0x140, base + 0x144, base + 0x148,
                base + 0x14C, base + 0x4000, base + 0x4004, base + 0x4008, base + 0x400C,
                0xF00000, base + 0x4010, base + 0x4014, base + 0x4018, base + 0x401C,
                base + 0x4020, base + 0x4024, base + 0x4028, base + 0x402C, 0x1D,
                0x1E, base + 0x60, base + 0x130, base + 0xA000, 0xF00000,
                base + 0x7500, base + 0x7504, base + 0x7508, base + 0xA51C, base + 0xA520,
                base + 0x5034, base + 0x5038, base + 0x503C, base + 0x5040, base + 0x5044,
                base + 0x5048, base + 0x504C, base + 0x5050, base + 0x5054, base + 0x5058,
                base + 0x505C, base + 0x5060, base + 0x5000, base + 0x5064, base + 0x5068,
                base + 0x64, base + 0x90, base + 0x94, base + 0x98, base + 0x9C,
                base + 0xA0, base + 0xA4, base + 0xA8, base + 0xAC, base + 0xB0,
                base + 0xBC, base + 0xC0, base + 0xC4, base + 0xC8, base + 0xCC,
                base + 0xD0, base + 0xD4, base + 0xD8, base + 0xDC, base + 0xE0,
                base + 0xE4, base + 0xE8, base + 0xEC, base + 0xF0, base + 0xF4,
                base + 0xF8, base + 0xFC, base + 0x100, base + 0x104, base + 0x108,
                base + 0x10C, base + 0x110, base + 0x114, base + 0x118, base + 0x11C,
                0xF00000, 0xF00000, 0xF00000
            ]
        else:
            self.efuses = []


class Chipconfig:
    var1 = None
    watchdog = None
    uart = None
    brom_payload_addr = None
    da_payload_addr = None
    pl_payload_addr = None
    cqdma_base = None
    ap_dma_mem = None
    sej_base = None
    dxcc_base = None
    name = ""
    description = ""
    dacode = None
    blacklist = None
    blacklist_count = None
    send_ptr = None
    ctrl_buffer = None
    cmd_handler = None
    brom_register_access = None
    meid_addr = None
    socid_addr = None
    prov_addr = None
    gcpu_base = None
    dacode = None
    damode = None
    loader = None
    misc_lock = None
    efuse_addr = None
    has64bit = False
    iot = False

    def __init__(self, var1=None, watchdog=None, uart=None, brom_payload_addr=None,
                 da_payload_addr=None, pl_payload_addr=None, cqdma_base=None, sej_base=None, dxcc_base=None,
                 gcpu_base=None, ap_dma_mem=None, name="", description="", dacode=None,
                 meid_addr=None, socid_addr=None, blacklist=(), blacklist_count=None,
                 send_ptr=None, ctrl_buffer=(), cmd_handler=None, brom_register_access=None,
                 damode=DAmodes.LEGACY, loader=None, prov_addr=None, misc_lock=None,
                 efuse_addr=None, has64bit=False, iot=False):
        self.iot = iot
        self.var1 = var1
        self.watchdog = watchdog
        self.uart = uart
        self.brom_payload_addr = brom_payload_addr
        self.da_payload_addr = da_payload_addr
        self.pl_payload_addr = pl_payload_addr
        self.cqdma_base = cqdma_base
        self.ap_dma_mem = ap_dma_mem
        self.sej_base = sej_base
        self.dxcc_base = dxcc_base
        self.name = name
        self.description = description
        self.dacode = dacode
        self.blacklist = blacklist
        self.blacklist_count = blacklist_count,
        self.send_ptr = send_ptr,
        self.ctrl_buffer = ctrl_buffer,
        self.cmd_handler = cmd_handler,
        self.brom_register_access = brom_register_access,
        self.meid_addr = meid_addr
        self.socid_addr = socid_addr
        self.prov_addr = prov_addr
        self.gcpu_base = gcpu_base
        self.dacode = dacode
        self.damode = damode
        self.loader = loader
        self.misc_lock = misc_lock
        self.efuse_addr = efuse_addr
        self.has64bit = has64bit

    # Credits to cyrozap and Chaosmaster for some values
    """
    0x0:    chipconfig(var1=0x0,
                       watchdog=0x0,
                       uart=0x0,
                       brom_payload_addr=0x0,
                       da_payload_addr=0x0,
                       cqdma_base=0x0,
                       gcpu_base=0x0,
                       blacklist=[(0x0, 0x0),(0x00105704, 0x0)],
                       dacode=0x0,
                       name=""),

                       Needed fields

                       For hashimoto:
                       cqdma_base,
                       ap_dma_mem,
                       blacklist

                       For kamakiri:
                       var1

                       For amonet:
                       gpu_base
                       blacklist
    """


"""
    0x5700: chipconfig(  # var1
        # watchdog
        # uart
        # brom_payload_addr
        # da_payload_addr
        gcpu_base=0x10016000,
        # sej_base
        # no dxcc
        # cqdma_base
        # ap_dma_mem
        # blacklist
        damode=damodes.LEGACY,
        # dacode
        name="MT5700"),
    0x6588: chipconfig(  # var1
        watchdog=0x10000000,
        # uart
        # brom_payload_addr
        # da_payload_addr
        # gcpu_base
        # sej_base
        # dxcc_base
        # cqdma_base
        ap_dma_mem=0x11000000 + 0x1A0,
        # blacklist
        damode=damodes.LEGACY,
        dacode=0x6588,
        name="MT6588"),
"""

hwconfig = {
    0x571: Chipconfig(  # var1
        watchdog=0x10007000,
        # uart
        # brom_payload_addr
        # da_payload_addr
        # gcpu_base
        # sej_base
        # cqdma_base
        # ap_dma_mem
        # blacklist
        damode=DAmodes.LEGACY,  #
        dacode=0x0571,
        name="MT0571"),
    0x598: Chipconfig(  # var1
        watchdog=0x10211000,
        uart=0x11020000,
        brom_payload_addr=0x100A00,  # todo:check
        da_payload_addr=0x201000,  # todo:check
        gcpu_base=0x10224000,
        sej_base=0x1000A000,
        cqdma_base=0x10212c00,
        ap_dma_mem=0x11000000 + 0x1A0,
        # blacklist
        damode=DAmodes.LEGACY,
        dacode=0x0598,
        name="ELBRUS/MT0598"),
    0x992: Chipconfig(  # var1
        watchdog=0x10007000,
        # uart
        # brom_payload_addr
        # da_payload_addr
        # gcpu_base
        # sej_base
        # cqdma_base
        # ap_dma_mem
        # blacklist
        efuse_addr=0x11EC0000,
        damode=DAmodes.XFLASH,
        dacode=0x0992,
        name="MT6880/MT6890"),
    0x2601: Chipconfig(
        var1=0xA,  # Smartwatch, confirmed
        watchdog=0x10007000,
        uart=0x11005000,
        brom_payload_addr=0x100A00,
        da_payload_addr=0x2008000,
        pl_payload_addr=0x81E00000,  #
        # no gcpu_base =0x10210000,
        sej_base=0x1000A000,  # hacc
        # no dxcc
        # no cqdma_base
        # no ap_dma_mem
        blacklist=[(0x11141F0C, 0x0), (0x11144BC4, 0x0)],
        blacklist_count=0x00000008,
        send_ptr=(0x11141f4c, 0xba68),
        ctrl_buffer=0x11142BE0,
        cmd_handler=0x0040C5AF,
        brom_register_access=(0x40bd48, 0x40befc),
        meid_addr=0x11142C34,
        dacode=0x2601,
        damode=DAmodes.LEGACY,  #
        name="MT2601",
        iot=True,
        loader="mt2601_payload.bin"),
    0x2523: Chipconfig(
        var1=0xA,  # Smartwatch, confirmed
        watchdog=0x10007000,
        uart=0x11005000,
        brom_payload_addr=0x100A00,
        da_payload_addr=0x2008000,
        pl_payload_addr=0x81E00000,  #
        # no gcpu_base =0x10210000,
        sej_base=0x1000A000,  # hacc
        # no dxcc
        # no cqdma_base
        # no ap_dma_mem
        # blacklist=[(0x11141F0C, 0x0), (0x11144BC4, 0x0)],
        # blacklist_count=0x00000008,
        send_ptr=(0x11141f4c, 0xba68),
        ctrl_buffer=0x11142BE0,
        cmd_handler=0x0040C5AF,
        # brom_register_access=(0x40bd48, 0x40befc),
        meid_addr=0x11142C34,
        dacode=0x2523,
        damode=DAmodes.LEGACY,  #
        iot=True,
        name="MT2523",
        # loader="mt2601_payload.bin"
    ),
    0x2625: Chipconfig(
        var1=0xA,  # Smartwatch, confirmed
        watchdog=0x10007000,
        uart=0x11005000,
        brom_payload_addr=0x100A00,
        da_payload_addr=0x4001000,
        # pl_payload_addr=0x81E00000,  #
        # no gcpu_base =0x10210000,
        sej_base=0x1000A000,  # hacc
        # no dxcc
        # no cqdma_base
        # no ap_dma_mem
        # blacklist=[(0x11141F0C, 0x0), (0x11144BC4, 0x0)],
        # blacklist_count=0x00000008,
        # send_ptr=(0x11141f4c, 0xba68),
        # ctrl_buffer=0x11142BE0,
        # cmd_handler=0x0040C5AF,
        # brom_register_access=(0x40bd48, 0x40befc),
        # meid_addr=0x11142C34,
        dacode=0x2625,
        damode=DAmodes.LEGACY,  #
        iot=True,
        name="MT2625",
        # loader="mt2601_payload.bin"
    ),
    0x3967: Chipconfig(  # var1
        # watchdog
        # uart
        brom_payload_addr=0x100A00,
        da_payload_addr=0x201000,
        pl_payload_addr=0x40020000,
        # gcpu_base
        # sej_base
        # no dxcc
        # cqdma_base
        # ap_dma_mem
        # blacklist
        dacode=0x3967,
        damode=DAmodes.LEGACY,
        name="MT3967"),
    0x5932: Chipconfig(  # var1
        # watchdog
        # uart
        brom_payload_addr=0x100A00,
        da_payload_addr=0x201000,
        pl_payload_addr=0x40020000,
        # gcpu_base
        # sej_base
        # no dxcc
        # cqdma_base
        # ap_dma_mem
        # blacklist
        dacode=0x5932,
        damode=DAmodes.LEGACY,
        iot=True,
        name="MT5932"),
    0x7682: Chipconfig(  # var1
        # watchdog
        # uart
        brom_payload_addr=0x100A00,
        da_payload_addr=0x201000,
        pl_payload_addr=0x40020000,
        # gcpu_base
        # sej_base
        # no dxcc
        # cqdma_base
        # ap_dma_mem
        # blacklist
        dacode=0x7682,
        damode=DAmodes.LEGACY,
        iot=True,
        name="MT7682"),
    0x7686: Chipconfig(  # var1
        # watchdog
        # uart
        brom_payload_addr=0x100A00,
        da_payload_addr=0x201000,
        pl_payload_addr=0x40020000,
        # gcpu_base
        # sej_base
        # no dxcc
        # cqdma_base
        # ap_dma_mem
        # blacklist
        dacode=0x7686,
        damode=DAmodes.LEGACY,
        iot=True,
        name="MT7686"),
    0x6225: Chipconfig(  # var1
        # watchdog
        # uart
        # brom_payload_addr
        # da_payload_addr
        # gcpu_base
        sej_base=0x80140000,
        # no dxcc
        # cqdma_base
        # ap_dma_mem
        # blacklist
        damode=DAmodes.LEGACY,
        dacode=0x6225,
        iot=True,
        name="MT6225"),
    0x6226: Chipconfig(  # var1
        # watchdog
        # uart
        # brom_payload_addr
        # da_payload_addr
        # gcpu_base
        sej_base=0x80140000,
        # no dxcc
        # cqdma_base
        # ap_dma_mem
        # blacklist
        damode=DAmodes.LEGACY,
        dacode=0x6226,
        iot=True,
        name="MT6226"),
    0x6236: Chipconfig(  # var1
        # watchdog
        # uart
        # brom_payload_addr
        # da_payload_addr
        # gcpu_base
        # sej_base=0x80140000,
        # no dxcc
        # cqdma_base
        # ap_dma_mem
        # blacklist
        damode=DAmodes.LEGACY,
        dacode=0x6236,
        iot=True,
        name="MT6236"),
    0x6238: Chipconfig(  # var1
        # watchdog
        # uart
        # brom_payload_addr
        # da_payload_addr
        # gcpu_base
        # sej_base=0x80140000,
        # no dxcc
        # cqdma_base
        # ap_dma_mem
        # blacklist
        damode=DAmodes.LEGACY,
        dacode=0x6238,
        iot=True,
        name="MT6238"),
    0x6253: Chipconfig(  # var1
        # watchdog
        # uart
        # brom_payload_addr
        # da_payload_addr
        # gcpu_base
        # sej_base=0x80140000,
        # no dxcc
        # cqdma_base
        # ap_dma_mem
        # blacklist
        damode=DAmodes.LEGACY,
        dacode=0x6253,
        iot=True,
        name="MT6253"),
    0x6255: Chipconfig(  # var1
        # watchdog
        # uart
        # brom_payload_addr
        # da_payload_addr
        # gcpu_base
        sej_base=0x80140000,
        # no dxcc
        # cqdma_base
        # ap_dma_mem
        # blacklist
        damode=DAmodes.LEGACY,
        dacode=0x6255,
        iot=True,
        name="MT6255"),
    0x6256: Chipconfig(  # var1
        # watchdog
        # uart
        # brom_payload_addr
        # da_payload_addr
        # gcpu_base
        #sej_base=0x80140000,
        # no dxcc
        # cqdma_base
        # ap_dma_mem
        # blacklist
        damode=DAmodes.LEGACY,
        dacode=0x6256,
        iot=True,
        name="MT6256"),
    0x625a: Chipconfig(  # var1
        # watchdog
        # uart
        # brom_payload_addr
        # da_payload_addr
        # gcpu_base
        # sej_base=0x80140000,
        # no dxcc
        # cqdma_base
        # ap_dma_mem
        # blacklist
        damode=DAmodes.LEGACY,
        dacode=0x625a,
        iot=True,
        name="MT625a"),
    0x6261: Chipconfig(
        var1=0x28,  # Smartwatch, confirmed
        watchdog=0xA0030000,
        uart=0xA0080000,
        brom_payload_addr=0x100A00,
        da_payload_addr=0x201000,
        # no gcpu_base
        sej_base=0xA0110000,
        # no dxcc
        # no cqdma_base
        # no ap_dma_mem
        blacklist=[(0xE003FC83, 0)],
        send_ptr=(0x700044b0, 0x700058EC),
        ctrl_buffer=0x700041A8,
        cmd_handler=0x700061F6,
        damode=DAmodes.LEGACY,
        iot=True,
        dacode=0x6261,
        name="MT6261/MT2503",
        loader="mt6261_payload.bin"
    ),
    0x6268: Chipconfig(  # var1
        # watchdog
        # uart
        # brom_payload_addr
        # da_payload_addr
        # gcpu_base
        # sej_base=0x80080000,
        # no dxcc
        # cqdma_base
        # ap_dma_mem
        # blacklist
        iot=True,
        damode=DAmodes.LEGACY,
        dacode=0x6268,
        name="MT6268"
    ),
    0x6270: Chipconfig(  # var1
        # watchdog
        # uart
        # brom_payload_addr
        # da_payload_addr
        # gcpu_base
        # sej_base=0x80080000,
        # no dxcc
        # cqdma_base
        # ap_dma_mem
        # blacklist
        iot=True,
        damode=DAmodes.LEGACY,
        dacode=0x6270,
        name="MT6270"
    ),
    0x6276: Chipconfig(  # var1
        # watchdog
        # uart
        # brom_payload_addr
        # da_payload_addr
        # gcpu_base
        # sej_base=0x80080000,
        # no dxcc
        # cqdma_base
        # ap_dma_mem
        # blacklist
        iot=True,
        damode=DAmodes.LEGACY,
        dacode=0x6276,
        name="MT6276"
    ),
    0x6280: Chipconfig(  # var1
        # watchdog
        # uart
        # brom_payload_addr
        # da_payload_addr
        # gcpu_base
        sej_base=0x80080000,
        # no dxcc
        # cqdma_base
        # ap_dma_mem
        # blacklist
        iot=True,
        damode=DAmodes.LEGACY,
        name="MT6280"
    ),
    0x6291: Chipconfig(  # var1
        # watchdog
        # uart
        # brom_payload_addr
        # da_payload_addr
        # gcpu_base
        # sej_base=0x80080000,
        # no dxcc
        # cqdma_base
        # ap_dma_mem
        # blacklist
        iot=True,
        damode=DAmodes.LEGACY,
        dacode=0x6291,
        name="MT6291"
    ),
    0x6516: Chipconfig(  # var1
        watchdog=0x10003000,
        uart=0x10023000,
        da_payload_addr=0x201000,  # todo: check
        # gcpu_base
        sej_base=0x1002D000,
        # no dxcc
        # cqdma_base
        # ap_dma_mem
        # blacklist
        damode=DAmodes.LEGACY,
        dacode=0x6516,
        name="MT6516"),
    0x633: Chipconfig(  # var1
        watchdog=0x10007000,
        uart=0x11002000,
        brom_payload_addr=0x100A00,  # todo: check
        da_payload_addr=0x201000,
        pl_payload_addr=0x80001000,  #
        gcpu_base=0x1020D000,
        sej_base=0x1000A000,
        # no dxcc
        cqdma_base=0x1020ac00,
        ap_dma_mem=0x11000000 + 0x1A0,  # AP_P_DMA_I2C_RX_MEM_ADDR
        efuse_addr=0x10009000,
        damode=DAmodes.XFLASH,
        dacode=0x6570,
        name="MT6570/MT8321"),
    0x6571: Chipconfig(  # var1
        watchdog=0x10007400,
        # uart
        da_payload_addr=0x2009000,
        pl_payload_addr=0x80001000,
        # gcpu_base
        # sej_base
        # no dxcc
        # cqdma_base
        # ap_dma_mem
        # blacklist
        misc_lock=0x1000141C,
        damode=DAmodes.LEGACY,  #
        dacode=0x6571,
        name="MT6571"),
    0x6572: Chipconfig(
        var1=0xA,
        watchdog=0x10007000,
        uart=0x11005000,
        brom_payload_addr=0x10036A0,
        da_payload_addr=0x2008000,
        pl_payload_addr=0x81E00000,  #
        # gcpu_base
        # sej_base
        # no dxcc
        # cqdma_base
        ap_dma_mem=0x11000000 + 0x19C,  # AP_P_DMA_I2C_1_MEM_ADDR
        blacklist=[(0x11141F0C, 0), (0x11144BC4, 0)],
        blacklist_count=0x00000008,
        send_ptr=(0x11141f4c, 0x40ba68),
        ctrl_buffer=0x11142BE0,
        cmd_handler=0x40C5AF,
        brom_register_access=(0x40bd48, 0x40befc),
        meid_addr=0x11142C34,
        misc_lock=0x1000141C,
        efuse_addr=0x10009000,
        damode=DAmodes.LEGACY,  #
        dacode=0x6572,
        name="MT6572",
        loader="mt6572_payload.bin"),
    0x6573: Chipconfig(  # var1
        watchdog=0x70025000,
        # uart
        da_payload_addr=0x90006000,
        pl_payload_addr=0xf1020000,
        # gcpu_base
        sej_base=0x7002A000,
        # no dxcc
        # cqdma_base
        # ap_dma_mem
        # blacklist
        damode=DAmodes.LEGACY,
        dacode=0x6573,
        name="MT6573/MT6260"),
    0x6575: Chipconfig(  # var1
        watchdog=0xC0000000,
        uart=0xC1009000,
        brom_payload_addr=0xf0000a00,
        da_payload_addr=0xc2001000,
        pl_payload_addr=0xc2058000,
        # gcpu_base
        sej_base=0xC101A000,
        # no dxcc
        # cqdma_base
        ap_dma_mem=0xC100119C,
        # blacklist
        send_ptr=(0xf00025fc,0xffffa0a0),
        cmd_handler=0xffffad5c,
        brom_register_access=(0xffffa3aa, 0xffffa4c4),
        meid_addr=0xf0002af4,
        efuse_addr=0xc1019000,
        damode=DAmodes.LEGACY,
        dacode=0x6575,
        name="MT6575/MT8317",
        loader="mt6575_payload.bin"),
    0x6577: Chipconfig(  # var1
        watchdog=0xC0000000,
        uart=0xC1009000,
        da_payload_addr=0xc2001000,
        pl_payload_addr=0xc2058000,
        # gcpu_base
        sej_base=0xC101A000,
        # no dxcc
        # cqdma_base
        ap_dma_mem=0xC100119C,
        # blacklist
        damode=DAmodes.LEGACY,
        dacode=0x6577,
        name="MT6577"),
    0x6580: Chipconfig(var1=0xAC,
                       watchdog=0x10007000,
                       uart=0x11005000,
                       brom_payload_addr=0x100A00,
                       da_payload_addr=0x201000,
                       pl_payload_addr=0x80001000,  #
                       # no gcpu_base
                       sej_base=0x1000A000,
                       # dxcc_base
                       cqdma_base=0x1020AC00,
                       ap_dma_mem=0x11000000 + 0x1A0,  # AP_P_DMA_I2C_1_RX_MEM_ADDR
                       blacklist=[(0x102764, 0x0), (0x001071D4, 0x0)],
                       blacklist_count=0x00000008,
                       send_ptr=(0x1027a4, 0xb60c),
                       ctrl_buffer=0x00103060,
                       cmd_handler=0x0000C113,
                       brom_register_access=(0xb8e0, 0xba94),
                       efuse_addr=0x10009000,
                       misc_lock=0x10001838,
                       meid_addr=0x1030B4,
                       damode=DAmodes.LEGACY,
                       dacode=0x6580,
                       name="MT6580",
                       loader="mt6580_payload.bin"),
    0x6582: Chipconfig(
        var1=0xA,  # confirmed
        watchdog=0x10007000,
        uart=0x11002000,
        brom_payload_addr=0x100A00,
        da_payload_addr=0x201000,
        pl_payload_addr=0x80001000,  #
        gcpu_base=0x1101B000,
        sej_base=0x1000A000,
        # no dxcc
        # no cqdma_base
        ap_dma_mem=0x11000000 + 0x320,  # AP_DMA_I2C_0_RX_MEM_ADDR
        blacklist=[(0x102788, 0x0), (0x00105BE4, 0x0)],
        blacklist_count=0x00000008,
        send_ptr=(0x1027c8, 0xa5fc),
        ctrl_buffer=0x00103078,
        cmd_handler=0x0000B2E7,
        brom_register_access=(0xa8d0, 0xaa84),
        efuse_addr=0x10206000,
        meid_addr=0x1030CC,
        misc_lock=0x10002050,
        damode=DAmodes.LEGACY,  #
        dacode=0x6582,
        name="MT6582/MT6574/MT8382",
        loader="mt6582_payload.bin"),
    0x6583: Chipconfig(  # var1
        watchdog=0x10000000,  # fixme
        uart=0x11006000,
        brom_payload_addr=0x100A00,
        da_payload_addr=0x12001000,
        pl_payload_addr=0x80001000,  #
        gcpu_base=0x10210000,
        sej_base=0x1000A000,
        # no dxcc
        # blacklist
        cqdma_base=0x10212000,  # This chip might not support cqdma
        ap_dma_mem=0x11000000 + 0x320,  # AP_DMA_I2C_0_RX_MEM_ADDR
        misc_lock=0x10002050,
        damode=DAmodes.LEGACY,
        dacode=0x6589,
        name="MT6583/6589"),
    0x6592: Chipconfig(
        var1=0xA,  # confirmed
        watchdog=0x10007000,
        uart=0x11002000,
        brom_payload_addr=0x100A00,
        da_payload_addr=0x111000,
        pl_payload_addr=0x80001000,
        gcpu_base=0x10210000,
        sej_base=0x1000A000,
        # no dxcc
        cqdma_base=0x10212000,  # This chip might not support cqdma
        ap_dma_mem=0x11000000 + 0x320,  # AP_DMA_I2C_0_RX_MEM_ADDR
        blacklist=[(0x00102764, 0), (0x00105BF0, 0)],
        blacklist_count=0x00000008,
        send_ptr=(0x1027a4, 0xa564),
        ctrl_buffer=0x00103054,
        cmd_handler=0x0000B09F,
        brom_register_access=(0xa838, 0xa9ec),
        meid_addr=0x1030A8,
        misc_lock=0x10002050,
        efuse_addr=0x10206000,
        dacode=0x6592,
        damode=DAmodes.LEGACY,  #
        name="MT6592/MT8392",
        loader="mt6592_payload.bin"),
    0x6595: Chipconfig(var1=0xA,
                       watchdog=0x10007000,
                       uart=0x11002000,
                       brom_payload_addr=0x100A00,
                       da_payload_addr=0x111000,
                       # gcpu_base
                       sej_base=0x1000A000,
                       # dxcc_base
                       # cqdma_base
                       ap_dma_mem=0x11000000 + 0x1A0,
                       blacklist=[(0x00102768, 0), (0x0106c88, 0)],
                       blacklist_count=0x00000008,
                       send_ptr=(0x1027a8, 0xb218),
                       ctrl_buffer=0x00103050,
                       cmd_handler=0x0000BD53,
                       brom_register_access=(0xb4ec, 0xb6a0),
                       meid_addr=0x1030A4,
                       efuse_addr=0x10206000,
                       dacode=0x6595,
                       damode=DAmodes.LEGACY,  #
                       name="MT6595",
                       loader="mt6595_payload.bin"),
    # 6725
    0x321: Chipconfig(
        var1=0x28,
        watchdog=0x10212000,
        uart=0x11002000,
        brom_payload_addr=0x100A00,
        da_payload_addr=0x201000,
        pl_payload_addr=0x40200000,  #
        gcpu_base=0x10216000,
        sej_base=0x10008000,  # hacc
        # no dxcc
        cqdma_base=0x10217C00,
        ap_dma_mem=0x11000000 + 0x1A0,  # AP_DMA_I2C_O_RX_MEM_ADDR
        blacklist=[(0x00102760, 0x0), (0x00105704, 0x0)],
        blacklist_count=0x00000008,
        send_ptr=(0x1027a0, 0x95f8),
        ctrl_buffer=0x0010305C,
        cmd_handler=0x0000A17F,
        brom_register_access=(0x98cc, 0x9a94),
        meid_addr=0x1030B0,
        misc_lock=0x10001838,
        efuse_addr=0x11c50000,
        damode=DAmodes.LEGACY,  #
        dacode=0x6735,
        name="MT6735/T,MT8735A",
        loader="mt6735_payload.bin"),
    0x335: Chipconfig(
        var1=0x28,  # confirmed
        watchdog=0x10212000,
        uart=0x11002000,
        brom_payload_addr=0x100A00,
        da_payload_addr=0x201000,
        pl_payload_addr=0x40200000,  #
        gcpu_base=0x10216000,
        sej_base=0x10008000,
        # no dxcc
        cqdma_base=0x10217C00,
        ap_dma_mem=0x11000000 + 0x1A0,  # AP_DMA_I2C_O_RX_MEM_ADDR
        blacklist=[(0x00102760, 0x0), (0x00105704, 0x0)],
        blacklist_count=0x00000008,
        send_ptr=(0x1027a0, 0x9608),
        ctrl_buffer=0x0010305C,
        cmd_handler=0x0000A18F,
        brom_register_access=(0x98dc, 0x9aa4),
        meid_addr=0x1030B0,
        efuse_addr=0x10206000,
        damode=DAmodes.LEGACY,  #
        dacode=0x6735,
        name="MT6737M/MT6735G",
        loader="mt6737_payload.bin"),
    # MT6738
    0x699: Chipconfig(
        var1=0xB4,
        watchdog=0x10007000,
        uart=0x11002000,
        brom_payload_addr=0x100A00,
        da_payload_addr=0x201000,
        pl_payload_addr=0x40200000,  #
        gcpu_base=0x10050000,
        sej_base=0x1000A000,  # hacc
        dxcc_base=0x10210000,
        cqdma_base=0x10212000,
        ap_dma_mem=0x11000000 + 0x1a0,  # AP_DMA_I2C_1_RX_MEM_ADDR
        blacklist=[(0x10282C, 0x0), (0x001076AC, 0x0)],
        blacklist_count=0x0000000A,
        send_ptr=(0x102870, 0xdf1c),
        ctrl_buffer=0x00102A28,
        cmd_handler=0x0000EC49,
        brom_register_access=(0xe330, 0xe3e8),
        meid_addr=0x102AF8,
        socid_addr=0x102b08,
        prov_addr=0x10720C,
        misc_lock=0x1001a100,
        efuse_addr=0x11c00000,
        damode=DAmodes.XFLASH,
        dacode=0x6739,
        name="MT6739/MT6731/MT8765",
        loader="mt6739_payload.bin"),
    0x601: Chipconfig(
        var1=0xA,
        watchdog=0x10007000,
        uart=0x11002000,
        brom_payload_addr=0x100A00,
        da_payload_addr=0x201000,
        pl_payload_addr=0x40200000,  #
        gcpu_base=0x10210000,
        sej_base=0x1000A000,  # hacc
        cqdma_base=0x10212C00,
        ap_dma_mem=0x11000000 + 0x1A0,  # AP_DMA_I2C_1_RX_MEM_ADDR
        # blacklist
        efuse_addr=0x10206000,
        misc_lock=0x10001838,
        damode=DAmodes.XFLASH,
        dacode=0x6755,
        name="MT6750"),
    0x6752: Chipconfig(
        var1=0x28,
        watchdog=0x10007000,
        uart=0x11002000,
        brom_payload_addr=0x100A00,
        da_payload_addr=0x201000,  #
        pl_payload_addr=0x40001000,  #
        gcpu_base=0x10210000,
        sej_base=0x1000A000,  # hacc
        # no dxcc
        cqdma_base=0x10212C00,
        ap_dma_mem=0x11000000 + 0x1A0,  # AP_DMA_I2C_0_RX_MEM_ADDR
        blacklist=[(0x00102764, 0x0), (0x00105704, 0x0)],
        blacklist_count=0x00000008,
        send_ptr=(0x1027a4, 0x990c),
        ctrl_buffer=0x00103060,
        cmd_handler=0x0000A493,
        brom_register_access=(0x9be0, 0x9da8),
        efuse_addr=0x10206000,
        meid_addr=0x1030B4,
        # no socid
        damode=DAmodes.LEGACY,
        dacode=0x6752,
        # misc_lock=0x10001838,
        name="MT6752",
        loader="mt6752_payload.bin"),
    0x337: Chipconfig(
        var1=0x28,  # confirmed
        watchdog=0x10212000,
        uart=0x11002000,
        brom_payload_addr=0x100A00,
        da_payload_addr=0x201000,
        pl_payload_addr=0x40200000,  #
        gcpu_base=0x10216000,
        sej_base=0x10008000,
        # no dxcc
        cqdma_base=0x10217C00,
        ap_dma_mem=0x11000000 + 0x1A0,  # AP_DMA_I2C_0_RX_MEM_ADDR
        blacklist=[(0x00102760, 0x0), (0x00105704, 0x0)],
        blacklist_count=0x00000008,
        send_ptr=(0x1027a0, 0x9668),
        ctrl_buffer=0x0010305C,
        cmd_handler=0x0000A1EF,
        brom_register_access=(0x993c, 0x9b04),
        meid_addr=0x1030B0,
        damode=DAmodes.LEGACY,  #
        dacode=0x6735,
        misc_lock=0x10001838,
        name="MT6753",
        loader="mt6753_payload.bin"),
    0x326: Chipconfig(
        var1=0xA,
        watchdog=0x10007000,
        uart=0x11002000,
        brom_payload_addr=0x100A00,
        da_payload_addr=0x201000,
        pl_payload_addr=0x40200000,  #
        gcpu_base=0x10210000,
        sej_base=0x1000A000,  # hacc
        # no dxcc
        cqdma_base=0x10212C00,
        ap_dma_mem=0x11000000 + 0x1A0,  # AP_DMA_I2C_1_RX_MEM_ADDR
        blacklist=[(0x10276C, 0x0), (0x00105704, 0x0)],
        blacklist_count=0x00000008,
        send_ptr=(0x1027b0, 0x9a6c),
        ctrl_buffer=0x00103058,
        cmd_handler=0x0000A5FF,
        brom_register_access=(0x9d4c, 0x9f14),
        meid_addr=0x1030AC,
        misc_lock=0x10001838,
        efuse_addr=0x10206000,
        damode=DAmodes.XFLASH,
        dacode=0x6755,
        name="MT6755/MT6750/M/T/S",
        description="Helio P10/P15/P18",
        loader="mt6755_payload.bin"),
    0x551: Chipconfig(
        var1=0xA,
        watchdog=0x10007000,
        uart=0x11002000,
        brom_payload_addr=0x100A00,
        da_payload_addr=0x201000,
        pl_payload_addr=0x40200000,  #
        gcpu_base=0x10210000,
        sej_base=0x1000A000,
        # no dxcc
        cqdma_base=0x10212C00,
        ap_dma_mem=0x11000000 + 0x1A0,  # AP_DMA_I2C_1_RX_MEM_ADDR
        blacklist=[(0x102774, 0x0), (0x00105704, 0x0)],
        blacklist_count=0x0000000A,
        send_ptr=(0x1027b8, 0x9c2c),
        ctrl_buffer=0x00103060,
        cmd_handler=0x0000A8FB,
        brom_register_access=(0xa030, 0xa0e8),
        meid_addr=0x1030B4,
        misc_lock=0x10001838,
        efuse_addr=0x10206000,
        damode=DAmodes.XFLASH,
        dacode=0x6757,
        name="MT6757/MT6757D",
        description="Helio P20",
        loader="mt6757_payload.bin"),
    0x688: Chipconfig(
        var1=0xA,
        watchdog=0x10211000,  #
        uart=0x11020000,
        brom_payload_addr=0x100A00,  #
        da_payload_addr=0x201000,  #
        pl_payload_addr=0x40200000,  #
        gcpu_base=0x10050000,  #
        sej_base=0x10080000,  # hacc
        dxcc_base=0x11240000,  #
        cqdma_base=0x10200000,  #
        ap_dma_mem=0x11000000 + 0x1A0,  #
        blacklist=[(0x102830, 0), (0x106A60, 0)],
        blacklist_count=0xA,
        send_ptr=(0x102874, 0xd860),
        ctrl_buffer=0x102B28,
        cmd_handler=0xE58D,
        brom_register_access=(0xdc74, 0xdd2c),
        meid_addr=0x102bf8,
        socid_addr=0x102c08,
        efuse_addr=0x10450000,
        damode=DAmodes.XFLASH,
        dacode=0x6758,
        name="MT6758",
        description="Helio P30",
        loader="mt6758_payload.bin"
    ),
    0x507: Chipconfig(  # var1
        watchdog=0x10210000,
        uart=0x11020000,
        brom_payload_addr=0x100A00,  # todo
        da_payload_addr=0x201000,
        # pl_payload_addr
        gcpu_base=0x10210000,
        # sej_base
        # dxcc_base
        # cqdma_base
        ap_dma_mem=0x1030000 + 0x1A0,  # todo
        # blacklist
        # blacklist_count
        # send_ptr
        # ctrl_buffer
        # cmd_handler
        # brom_Register_access
        # meid_addr
        damode=DAmodes.LEGACY,
        dacode=0x6758,
        name="MT6759",
        description="Helio P30"
        # loader
    ),

    0x717: Chipconfig(
        var1=0x25,
        watchdog=0x10007000,
        uart=0x11002000,
        brom_payload_addr=0x100A00,
        da_payload_addr=0x201000,
        pl_payload_addr=0x40200000,  #
        gcpu_base=0x10050000,
        sej_base=0x1000A000,  # hacc
        dxcc_base=0x10210000,
        cqdma_base=0x10212000,
        ap_dma_mem=0x11000a80 + 0x1a0,  # AP_DMA_I2C_CH0_RX_MEM_ADDR
        blacklist=[(0x102828, 0x0), (0x00105994, 0x0)],
        blacklist_count=0x0000000A,
        send_ptr=(0x10286c, 0xbc8c),
        ctrl_buffer=0x00102A28,
        cmd_handler=0x0000C9B9,
        brom_register_access=(0xc0a0, 0xc158),
        meid_addr=0x102AF8,
        socid_addr=0x102b08,
        prov_addr=0x1054F4,
        misc_lock=0x1001a100,
        efuse_addr=0x11c50000,
        damode=DAmodes.XFLASH,
        dacode=0x6761,
        name="MT6761/MT6762/MT3369/MT8766B/MT8761/AC8259/AC8257",
        description="Helio A20/P22/A22/A25/G25",
        loader="mt6761_payload.bin"),
    0x690: Chipconfig(
        var1=0x7F,
        watchdog=0x10007000,
        uart=0x11002000,
        brom_payload_addr=0x100A00,
        da_payload_addr=0x201000,
        pl_payload_addr=0x40200000,  #
        gcpu_base=0x10050000,
        dxcc_base=0x10210000,
        sej_base=0x1000A000,  # hacc
        cqdma_base=0x10212000,
        ap_dma_mem=0x11000a80 + 0x1a0,
        blacklist=[(0x102834, 0x0), (0x00106CA4, 0x0)],
        blacklist_count=0x0000000A,
        send_ptr=(0x102878, 0xd66c),
        ctrl_buffer=0x00102A90,
        cmd_handler=0x0000E383,
        brom_register_access=(0xda80, 0xdb38),
        meid_addr=0x102B78,
        socid_addr=0x102b88,
        prov_addr=0x106804,
        misc_lock=0x1001a100,
        efuse_addr=0x11f10000,
        damode=DAmodes.XFLASH,
        dacode=0x6763,
        name="MT6763",
        description="Helio P23",
        loader="mt6763_payload.bin"),
    0x766: Chipconfig(
        var1=0x25,  # confirmed
        watchdog=0x10007000,
        uart=0x11002000,
        brom_payload_addr=0x100A00,
        da_payload_addr=0x201000,
        pl_payload_addr=0x40200000,  #
        gcpu_base=0x10050000,  # not confirmed
        sej_base=0x1000a000,  # hacc
        dxcc_base=0x10210000,
        cqdma_base=0x10212000,
        ap_dma_mem=0x11000000 + 0x1a0,  # AP_DMA_I2C2_CH0_RX_MEM_ADDR
        blacklist=[(0x102828, 0x0), (0x00105994, 0x0)],
        blacklist_count=0x0000000A,
        send_ptr=(0x10286c, 0xbdc0),
        ctrl_buffer=0x00102A28,
        cmd_handler=0x0000CAED,
        brom_register_access=(0xc1d4, 0xc28c),
        meid_addr=0x102AF8,
        socid_addr=0x102b08,  # 0x10B72C
        prov_addr=0x1054F4,
        misc_lock=0x1001a100,
        efuse_addr=0x11c50000,
        damode=DAmodes.XFLASH,
        dacode=0x6765,
        name="MT6765/MT8768t",
        description="Helio P35/G35",
        loader="mt6765_payload.bin"),
    0x707: Chipconfig(
        var1=0x25,
        watchdog=0x10007000,
        uart=0x11002000,
        brom_payload_addr=0x100A00,
        da_payload_addr=0x201000,
        pl_payload_addr=0x40200000,  #
        gcpu_base=0x10050000,
        sej_base=0x1000A000,  # hacc
        dxcc_base=0x10210000,
        cqdma_base=0x10212000,
        ap_dma_mem=0x11000000 + 0x1A0,
        blacklist=[(0x10282C, 0x0), (0x00105994, 0)],
        blacklist_count=0x0000000A,
        send_ptr=(0x10286c, 0xc190),
        ctrl_buffer=0x00102A28,
        cmd_handler=0x0000CF15,
        brom_register_access=(0xc598, 0xc650),
        meid_addr=0x102AF8,
        socid_addr=0x102b08,
        prov_addr=0x1054F4,
        misc_lock=0x1001a100,
        efuse_addr=0x11ce0000,
        damode=DAmodes.XFLASH,
        dacode=0x6768,
        name="MT6768/MT6769",
        description="Helio P65/G85 k68v1",
        loader="mt6768_payload.bin"),
    0x788: Chipconfig(
        var1=0xA,
        watchdog=0x10007000,
        uart=0x11002000,
        brom_payload_addr=0x100A00,
        da_payload_addr=0x201000,
        pl_payload_addr=0x40200000,  #
        gcpu_base=0x10050000,
        sej_base=0x1000A000,  # hacc
        dxcc_base=0x10210000,  # dxcc_sec
        cqdma_base=0x10212000,
        ap_dma_mem=0x11000000 + 0x158,  # AP_DMA_I2C_1_RX_MEM_ADDR
        blacklist=[(0x00102834, 0x0), (0x00106A60, 0x0)],
        blacklist_count=0x0000000A,
        send_ptr=(0x102878, 0xdebc),
        ctrl_buffer=0x00102A80,
        cmd_handler=0x0000EBE9,
        brom_register_access=(0xe2d0, 0xe388),
        meid_addr=0x102B38,
        socid_addr=0x102B48,
        prov_addr=0x1065C0,
        misc_lock=0x1001a100,
        efuse_addr=0x11f10000,
        damode=DAmodes.XFLASH,
        dacode=0x6771,
        name="MT6771/MT8385/MT8183/MT8666",
        description="Helio P60/P70/G80",
        loader="mt6771_payload.bin"),
    # blacklist=[(0x00102830, 0x00200008),  # Static permission table pointer
    #           (0x00102834, 2),  # Static permission table entry count
    #           (0x00200000, 0x00000000),  # Memory region minimum address
    #           (0x00200004, 0xfffffffc),  # Memory region maximum address
    #           (0x00200008, 0x00000200),  # Memory read command bitmask
    #           (0x0020000c, 0x00200000),  # Memory region array pointer
    #           (0x00200010, 0x00000001),  # Memory region array length
    #           (0x00200014, 0x00000400),  # Memory write command bitmask
    #           (0x00200018, 0x00200000),  # Memory region array pointer
    #           (0x0020001c, 0x00000001),  # Memory region array length
    #           (0x00106A60, 0)],  # Dynamic permission table entry count?
    0x725: Chipconfig(var1=0xA,  # confirmed
                      watchdog=0x10007000,
                      uart=0x11002000,
                      brom_payload_addr=0x100A00,
                      da_payload_addr=0x201000,
                      pl_payload_addr=0x40200000,  #
                      gcpu_base=0x10050000,
                      sej_base=0x1000a000,  # hacc
                      dxcc_base=0x10210000,
                      cqdma_base=0x10212000,
                      ap_dma_mem=0x11000000 + 0x158,
                      blacklist=[(0x102838, 0x0), (0x00106A60, 0x0)],
                      blacklist_count=0x0000000A,
                      send_ptr=(0x102878, 0xe04c),
                      ctrl_buffer=0x00102A80,
                      cmd_handler=0x0000ED6D,
                      brom_register_access=(0xe454, 0xe50c),
                      meid_addr=0x102B38,
                      socid_addr=0x102B48,
                      prov_addr=0x1065C0,
                      misc_lock=0x1001a100,
                      efuse_addr=0x11c10000,
                      damode=DAmodes.XFLASH,
                      dacode=0x6779,
                      name="MT6779",
                      description="Helio P90 k79v1",
                      loader="mt6779_payload.bin"),
    0x1066: Chipconfig(
        var1=0x73,  # confirmed
        watchdog=0x10007000,
        uart=0x11002000,
        brom_payload_addr=0x100A00,
        da_payload_addr=0x201000,
        pl_payload_addr=0x40200000,
        gcpu_base=0x10050000,
        sej_base=0x1000A000,  # hacc
        dxcc_base=0x10210000,
        # cqdma_base=0x10212000,
        # ap_dma_mem=0x11000000 + 0x158,
        blacklist=[(0x10284C, 0x106B54)],
        blacklist_count=0x0000000A,
        send_ptr=(0x102890, 0xe5d8),
        ctrl_buffer=0x00102AB4,
        cmd_handler=0x0000F3C1,
        brom_register_access=(0xe9dc, 0xea94),
        meid_addr=0x102B98,
        socid_addr=0x102BA8,
        efuse_addr=0x11cb0000,
        damode=DAmodes.XFLASH,
        dacode=0x6781,
        name="MT6781",
        description="Helio G96",
        loader="mt6781_payload.bin"
    ),
    0x813: Chipconfig(var1=0xA,  # confirmed
                      watchdog=0x10007000,
                      uart=0x11002000,
                      brom_payload_addr=0x100A00,
                      da_payload_addr=0x201000,
                      pl_payload_addr=0x40200000,  #
                      gcpu_base=0x10050000,
                      sej_base=0x1000A000,  # hacc
                      dxcc_base=0x10210000,
                      cqdma_base=0x10212000,
                      ap_dma_mem=0x11000000 + 0x158,
                      blacklist=[(0x102838, 0x0), (0x00106A60, 0x0)],
                      blacklist_count=0x0000000A,
                      send_ptr=(0x102878, 0xe2a4),
                      ctrl_buffer=0x00102A80,
                      cmd_handler=0x0000F029,
                      brom_register_access=(0xe6ac, 0xe764),
                      meid_addr=0x102B38,
                      socid_addr=0x102B48,
                      prov_addr=0x1065C0,
                      misc_lock=0x1001a100,
                      efuse_addr=0x11c10000,
                      damode=DAmodes.XFLASH,
                      dacode=0x6785,
                      name="MT6785",
                      description="Helio G90",
                      loader="mt6785_payload.bin"),
    0x6795: Chipconfig(
        var1=0xA,  # confirmed
        watchdog=0x10007000,
        uart=0x11002000,
        brom_payload_addr=0x100A00,
        da_payload_addr=0x110000,
        pl_payload_addr=0x40200000,  #
        gcpu_base=0x10210000,
        sej_base=0x1000A000,  # hacc
        # no dxcc
        cqdma_base=0x10212c00,
        ap_dma_mem=0x11000000 + 0x1A0,
        blacklist=[(0x102764, 0x0), (0x00105704, 0x0)],
        blacklist_count=0x00000008,
        send_ptr=(0x1027a4, 0x978c),
        ctrl_buffer=0x0010304C,
        cmd_handler=0x0000A313,  #
        brom_register_access=(0x9a60, 0x9c28),
        meid_addr=0x1030A0,
        efuse_addr=0x10206000,
        damode=DAmodes.LEGACY,  #
        dacode=0x6795,
        name="MT6795",
        description="Helio X10",
        loader="mt6795_payload.bin"),
    0x279: Chipconfig(
        var1=0xA,  # confirmed
        watchdog=0x10007000,
        uart=0x11002000,
        brom_payload_addr=0x100A00,
        da_payload_addr=0x201000,
        pl_payload_addr=0x40200000,  #
        gcpu_base=0x10210000,
        # no dxcc
        sej_base=0x1000A000,  # hacc
        cqdma_base=0x10212C00,
        ap_dma_mem=0x11000000 + 0x1A0,  # AP_DMA_I2C_1_RX_MEM_ADDR
        blacklist=[(0x0010276C, 0x0), (0x00105704, 0x0)],
        blacklist_count=0x00000008,
        send_ptr=(0x1027b0, 0x9eac),
        ctrl_buffer=0x00103058,
        cmd_handler=0x0000AA3F,
        brom_register_access=(0xa18c, 0xa354),
        meid_addr=0x1030AC,
        misc_lock=0x10002050,
        efuse_addr=0x10206000,
        damode=DAmodes.XFLASH,
        dacode=0x6797,
        name="MT6797/MT6767",
        description="Helio X23/X25/X27",
        loader="mt6797_payload.bin"),
    0x562: Chipconfig(
        var1=0xA,  # confirmed
        watchdog=0x10211000,
        uart=0x11020000,
        brom_payload_addr=0x100A00,
        da_payload_addr=0x201000,
        pl_payload_addr=0x40200000,  # not confirmed
        gcpu_base=0x10210000,
        cqdma_base=0x11B30000,
        ap_dma_mem=0x11000000 + 0x1A0,  # AP_DMA_I2C_2_RX_MEM_ADDR
        dxcc_base=0x11B20000,
        sej_base=0x1000A000,
        blacklist=[(0x00102870, 0x0), (0x00107070, 0x0)],
        blacklist_count=0x0000000A,
        send_ptr=(0x1028b4, 0xf5ac),
        ctrl_buffer=0x001032F0,
        cmd_handler=0x000102C3,
        brom_register_access=(0xf9c0, 0xfa78),
        meid_addr=0x1033B8,
        socid_addr=0x1033C8,
        efuse_addr=0x11F10000,
        damode=DAmodes.XFLASH,
        dacode=0x6799,
        name="MT6799",
        description="Helio X30/X35",
        loader="mt6799_payload.bin"),
    0x989: Chipconfig(
        var1=0x73,
        watchdog=0x10007000,
        uart=0x11002000,
        brom_payload_addr=0x100A00,  #
        da_payload_addr=0x201000,  #
        pl_payload_addr=0x40200000,  #
        gcpu_base=0x10050000,
        dxcc_base=0x10210000,
        sej_base=0x1000a000,  # hacc
        cqdma_base=0x10212000,
        ap_dma_mem=0x10217a80 + 0x1a0,
        blacklist=[(0x00102844, 0x0), (0x00106B54, 0x0)],
        blacklist_count=0x0000000A,
        send_ptr=(0x102884, 0xdfe0),
        ctrl_buffer=0x00102AA4,
        cmd_handler=0x0000EDAD,
        brom_register_access=(0xe3e8, 0xe4a0),
        meid_addr=0x102b98,
        socid_addr=0x102ba8,
        prov_addr=0x1066B4,
        efuse_addr=0x11c10000,
        damode=DAmodes.XFLASH,
        dacode=0x6833,
        name="MT6833",
        description="Dimensity 700 5G k6833",
        loader="mt6833_payload.bin"),
    0x996: Chipconfig(var1=0xA,
                      watchdog=0x10007000,
                      uart=0x11002000,
                      brom_payload_addr=0x100A00,
                      da_payload_addr=0x201000,
                      pl_payload_addr=0x40200000,  #
                      gcpu_base=0x10050000,
                      dxcc_base=0x10210000,
                      cqdma_base=0x10212000,
                      sej_base=0x1000a000,  # hacc
                      ap_dma_mem=0x10217a80 + 0x1A0,
                      blacklist=[(0x10284C, 0x0), (0x00106B60, 0x0)],
                      blacklist_count=0x0000000A,
                      send_ptr=(0x10288c, 0xea64),
                      ctrl_buffer=0x00102AA0,
                      cmd_handler=0x0000F831,
                      brom_register_access=(0xee6c, 0xef24),
                      meid_addr=0x102b78,
                      socid_addr=0x102b88,
                      prov_addr=0x1066C0,
                      misc_lock=0x1001A100,
                      efuse_addr=0x11c10000,
                      damode=DAmodes.XFLASH,
                      dacode=0x6853,
                      name="MT6853",
                      description="Dimensity 720 5G",
                      loader="mt6853_payload.bin"),
    0x886: Chipconfig(
        var1=0xA,
        watchdog=0x10007000,
        uart=0x11002000,
        brom_payload_addr=0x100A00,
        da_payload_addr=0x201000,
        pl_payload_addr=0x40200000,
        gcpu_base=0x10050000,
        dxcc_base=0x10210000,
        sej_base=0x1000a000,  # hacc
        cqdma_base=0x10212000,
        ap_dma_mem=0x10217a80 + 0x1A0,
        blacklist=[(0x10284C, 0x0), (0x00106B60, 0x0)],
        blacklist_count=0x0000000A,
        send_ptr=(0x10288c, 0xea78),
        ctrl_buffer=0x00102AA0,
        cmd_handler=0x0000F7FD,
        brom_register_access=(0xee80, 0xef38),
        meid_addr=0x102B78,
        socid_addr=0x102B88,
        prov_addr=0x1066C0,
        misc_lock=0x1001A100,
        efuse_addr=0x11c10000,
        damode=DAmodes.XFLASH,
        dacode=0x6873,
        name="MT6873",
        description="Dimensity 800/820 5G",
        loader="mt6873_payload.bin"),
    0x959: Chipconfig(
        var1=0xA,
        watchdog=0x10007000,
        uart=0x11002000,
        brom_payload_addr=0x100A00,
        da_payload_addr=0x201000,
        pl_payload_addr=0x40200000,
        gcpu_base=0x10050000,
        sej_base=0x1000a000,  # hacc
        dxcc_base=0x10210000,
        cqdma_base=0x10212000,
        ap_dma_mem=0x10217a80 + 0x1A0,
        blacklist=[(0x102848, 0x0), (0x00106B60, 0x0)],
        blacklist_count=0xA,
        send_ptr=(0x102888, 0xe8d0),
        ctrl_buffer=0x00102A9C,
        cmd_handler=0x0000F69D,
        brom_register_access=(0xecd8, 0xed90),
        meid_addr=0x102b98,
        socid_addr=0x102ba8,
        prov_addr=0x1066C0,
        efuse_addr=0x11f10000,
        damode=DAmodes.XFLASH,
        dacode=0x6877,  # todo
        name="MT6877/MT6877V/MT8791N",
        description="Dimensity 900/1080/7050",
        loader="mt6877_payload.bin"
    ),
    0x816: Chipconfig(
        var1=0xA,  # confirmed
        watchdog=0x10007000,
        uart=0x11002000,
        brom_payload_addr=0x100A00,
        da_payload_addr=0x201000,
        pl_payload_addr=0x40200000,
        gcpu_base=0x10050000,
        dxcc_base=0x10210000,
        sej_base=0x1000a000,  # hacc
        cqdma_base=0x10212000,
        ap_dma_mem=0x11000a80 + 0x1a0,
        blacklist=[(0x102848, 0x0), (0x00106B60, 0x0)],
        blacklist_count=0x0000000A,
        send_ptr=(0x102888, 0xE6FC),
        ctrl_buffer=0x00102A9C,
        cmd_handler=0x0000F481,
        brom_register_access=(0xeb04, 0xebbc),
        meid_addr=0x102B78,  # 0x1008EC
        socid_addr=0x102B88,
        prov_addr=0x1066C0,
        misc_lock=0x1001A100,
        efuse_addr=0x11c10000,
        damode=DAmodes.XFLASH,
        dacode=0x6885,
        name="MT6885/MT6883/MT6889/MT6880/MT6890",
        description="Dimensity 1000L/1000",
        loader="mt6885_payload.bin"),
    # Dimensity 1200 - MT6891 Realme Q3 Pro
    0x950: Chipconfig(
        var1=0xA,  # confirmed
        watchdog=0x10007000,
        uart=0x11002000,
        brom_payload_addr=0x100A00,
        da_payload_addr=0x201000,
        pl_payload_addr=0x40200000,
        gcpu_base=0x10050000,
        dxcc_base=0x10210000,
        sej_base=0x1000a000,  # hacc
        cqdma_base=0x10212000,
        ap_dma_mem=0x11000a80 + 0x1a0,
        blacklist=[(0x102848, 0x0), (0x00106B60, 0x0)],
        blacklist_count=0x0000000A,
        send_ptr=(0x102888, 0xE79C),
        ctrl_buffer=0x00102A9C,
        cmd_handler=0x0000F569,
        brom_register_access=(0xeba4, 0xec5c),
        meid_addr=0x102B98,
        socid_addr=0x102BA8,
        prov_addr=0x1066C0,
        efuse_addr=0x11c10000,
        damode=DAmodes.XFLASH,
        dacode=0x6893,
        name="MT6891/MT6893",
        description="Dimensity 1200",
        loader="mt6893_payload.bin"),
    #
    0x907: Chipconfig(
        var1=0xA,
        watchdog=0x1c007000,
        uart=0x11001000,
        brom_payload_addr=0x100A00,
        da_payload_addr=0x201000,
        pl_payload_addr=0x40200000,
        gcpu_base=0x10050000,
        dxcc_base=0x10210000,
        sej_base=0x1000a000,
        cqdma_base=0x10212000,
        ap_dma_mem=0x11300800 + 0x1a0,
        # blacklist=[(0x102848, 0x0), (0x00106B60, 0x0)],
        # blacklist_count=0x0000000A,
        # send_ptr=(0x102888, 0xE79C),
        # ctrl_buffer=0x00102A9C,
        # cmd_handler=0x0000F569,
        # brom_register_access=(0xeba4, 0xec5c),
        meid_addr=0x1008EC,
        socid_addr=0x100934,
        efuse_addr=0x11EE0000,
        # prov_addr=0x1066C0,
        damode=DAmodes.XML,
        dacode=0x907,
        name="MT6983",
        has64bit=True,
        description="Dimensity 9000/9000+"
        # loader="mt6983_payload.bin"
    ),
    # Dimensity 7020/930 - MT6855 - Motorola XT2415V
    0x1129: Chipconfig(
        var1=0xA,
        watchdog=0x1c007000,
        uart=0x11001000,
        brom_payload_addr=0x100A00,
        da_payload_addr=0x201000,
        pl_payload_addr=0x40200000,
        gcpu_base=0x10050000,
        dxcc_base=0x10210000,
        sej_base=0x1000a000,
        cqdma_base=0x10212000,
        ap_dma_mem=0x11300800 + 0x1a0,
        # blacklist=[(0x102848, 0x0), (0x00106B60, 0x0)],
        # blacklist_count=0x0000000A,
        # send_ptr=(0x102888, 0xE79C),
        # ctrl_buffer=0x00102A9C,
        # cmd_handler=0x0000F569,
        # brom_register_access=(0xeba4, 0xec5c),
        meid_addr=0x1008EC,
        socid_addr=0x100934,
        # prov_addr=0x1066C0,
        damode=DAmodes.XML,
        dacode=0x1129,
        name="MT6855",
        description="Dimensity 8100"
        # loader="mt6893_payload.bin"
    ),
    # Dimensity 1100 - MT6895 Dimensity 8200 - Vivo V27 Pro
    0x1172: Chipconfig(
        var1=0xA,
        watchdog=0x1c007000,
        uart=0x11001000,
        brom_payload_addr=0x100A00,
        da_payload_addr=0x201000,
        pl_payload_addr=0x40200000,
        gcpu_base=0x10050000,
        dxcc_base=0x10210000,
        sej_base=0x1000a000,
        cqdma_base=0x10212000,
        ap_dma_mem=0x11300800 + 0x1a0,
        # blacklist=[(0x102848, 0x0), (0x00106B60, 0x0)],
        # blacklist_count=0x0000000A,
        # send_ptr=(0x102888, 0xE79C),
        # ctrl_buffer=0x00102A9C,
        # cmd_handler=0x0000F569,
        # brom_register_access=(0xeba4, 0xec5c),
        meid_addr=0x1008EC,
        socid_addr=0x100934,
        efuse_addr=0x11F10000,
        # prov_addr=0x1066C0,
        damode=DAmodes.XML,
        dacode=0x1172,
        name="MT6895",
        description="Dimensity 8200"
        # loader="mt6893_payload.bin"
    ),
    0x1203: Chipconfig(
        var1=0xA,
        watchdog=0x1c007000,
        uart=0x11002000,
        brom_payload_addr=0x100A00,
        da_payload_addr=0x201000,
        pl_payload_addr=0x40200000,
        gcpu_base=0x1000D000,
        dxcc_base=0x10403000,
        sej_base=0x1040E000,
        # cqdma_base=0x10212000,
        # ap_dma_mem=0x11300800 + 0x1a0,
        # blacklist=[(0x102848, 0x0), (0x00106B60, 0x0)],
        # blacklist_count=0x0000000A,
        # send_ptr=(0x102888, 0xE79C),
        # ctrl_buffer=0x00102A9C,
        # cmd_handler=0x0000F569,
        # brom_register_access=(0xeba4, 0xec5c),
        # meid_addr=0x1008EC,
        socid_addr=0x20E7090,
        # prov_addr=0x1066C0,
        damode=DAmodes.XML,
        dacode=0x1203,
        name="MT6897",
        description="Dimensity 8300 Ultra"
        # loader="mt6897_payload.bin"
    ),
    # MT6789 Oppo Realme 10 / Gigaset GX4
    0x1208: Chipconfig(
        var1=0xA,
        watchdog=0x10007000,
        uart=0x11002000,
        brom_payload_addr=0x100A00,
        da_payload_addr=0x201000,
        pl_payload_addr=0x40200000,
        # gcpu_base=0x10050000,
        dxcc_base=0x10210000,
        sej_base=0x1000a000,
        # cqdma_base=0x10212000,
        # ap_dma_mem=0x11300800 + 0x1a0,
        blacklist=[(0x102d5c, 0x0)],
        # blacklist_count=0x0000000A,
        # send_ptr=(0x102888, 0xE79C),
        ctrl_buffer=0x00103024,
        cmd_handler=0x000101E8,
        brom_register_access=(0xf99a, 0xfa0c),
        meid_addr=0x1008EC,
        socid_addr=0x100934,
        # prov_addr=0x1066C0,
        efuse_addr=0x11C10000,
        damode=DAmodes.XML,
        dacode=0x1208,
        name="MT6789/MT8781V",
        description="MTK Helio G99"
        # loader="mt6789_payload.bin"
    ),
    # Realme 12x 5G
    0x1209: Chipconfig(
        var1=0xA,
        watchdog=0x1C007000,
        uart=0x11002000,
        # brom_payload_addr=0x100A00,
        da_payload_addr=0x2001000,
        pl_payload_addr=0x40200000,
        # gcpu_base=0x10050000,
        dxcc_base=0x10210000,
        sej_base=0x1000a000,
        # cqdma_base=0x10212000,
        # ap_dma_mem=0x11300800 + 0x1a0,
        # blacklist=[(0x102d5c, 0x0)],
        # blacklist_count=0x0000000A,
        # send_ptr=(0x102888, 0xE79C),
        # ctrl_buffer=0x00103024,
        # cmd_handler=0x000101E8,
        # brom_register_access=(0xf99a, 0xfa0c),
        meid_addr=0x1008EC,
        socid_addr=0x100934,
        # prov_addr=0x1066C0,
        efuse_addr=0x11C10000,
        damode=DAmodes.XML,
        dacode=0x1209,
        name="MT6835V/ZA",
        description="MTK Dimensity 6100+"
        # loader="mt6789_payload.bin"
    ),
    0x1229: Chipconfig(
        var1=0xA,
        watchdog=0x1c007000,
        uart=0x11002000,
        brom_payload_addr=0x100A00,
        da_payload_addr=0x2001000,
        pl_payload_addr=0x40200000,
        gcpu_base=0x1000D000,
        dxcc_base=0x1C807000,
        sej_base=0x1C009000,
        # cqdma_base=0x10212000,
        # ap_dma_mem=0x11300800 + 0x1a0,
        # blacklist=[(0x102d5c, 0x0)],
        # blacklist_count=0x0000000A,
        # send_ptr=(0x102888, 0xE79C),
        # ctrl_buffer=0x00103024,
        # cmd_handler=0x000101E8,
        # brom_register_access=(0xf99a, 0xfa0c),
        meid_addr=0x1008EC,
        socid_addr=0x100934,
        # prov_addr=0x1066C0,
        efuse_addr=0x11E30000,
        damode=DAmodes.XML,
        dacode=0x1229,
        has64bit=True,
        name="MT6886",
        description="Dimensity 7200 Ultra"
        # loader="mt7200_payload.bin"
    ),
    0x1236: Chipconfig(
        # toDo: new crypto hw, Xiaomi 14T Pro
        #var1=0xA,
        watchdog=0x1C00B000,
        #uart=0x11002000,
        brom_payload_addr=0x100A00,
        da_payload_addr=0x2001000,
        pl_payload_addr=0x40200000,
        #gcpu_base=0x1000D000,
        dxcc_base=0x10403000,
        sej_base=0x1040E000,
        # cqdma_base=0x10212000,
        # ap_dma_mem=0x11300800 + 0x1a0,
        # blacklist=[(0x102d5c, 0x0)],
        # blacklist_count=0x0000000A,
        # send_ptr=(0x102888, 0xE79C),
        # ctrl_buffer=0x00103024,
        # cmd_handler=0x000101E8,
        # brom_register_access=(0xf99a, 0xfa0c),
        meid_addr=0x1008EC,
        socid_addr=0x100934,
        # prov_addr=0x1066C0,
        efuse_addr=0x11F10000,
        damode=DAmodes.XML,
        dacode=0x1236,
        has64bit=True,
        name="MT6989W",
        description="Dimensity 9300 Plus"
        # loader="mt9300_payload.bin"
    ),
    0x1296: Chipconfig(
        var1=0xA,
        watchdog=0x1C007000,
        uart=0x1C011000,
        brom_payload_addr=0x100A00,
        da_payload_addr=0x201000,
        pl_payload_addr=0x40200000,
        # gcpu_base=0x10050000,
        dxcc_base=0x1C807000,
        sej_base=0x1C009000,
        # cqdma_base=0x10212000,
        # ap_dma_mem=0x11300800 + 0x1a0,
        # blacklist=[(0x102d5c, 0x0)],
        # blacklist_count=0x0000000A,
        # send_ptr=(0x102888, 0xE79C),
        # ctrl_buffer=0x00103024,
        # cmd_handler=0x000101E8,
        # brom_register_access=(0xf99a, 0xfa0c),
        meid_addr=0x1008EC,
        socid_addr=0x100934,
        # prov_addr=0x1066C0,
        efuse_addr=0x11E80000,
        damode=DAmodes.XML,
        dacode=0x1296,
        has64bit=True,
        name="MT6985",
        description="Dimensity 9200/9200+"
        # loader="mt6985_payload.bin"
    ),
    # toDo: 0x1357 MT6991
    0x1375: Chipconfig(
        var1=0xA,
        watchdog=0x1C00A000,
        # uart=0x1C011000,
        brom_payload_addr=0x100A00,
        da_payload_addr=0x2010000,
        pl_payload_addr=0x40200000,
        # gcpu_base=0x10050000,
        dxcc_base=0x10400000,
        sej_base=0x1040E000,
        # cqdma_base=0x10212000,
        # ap_dma_mem=0x11300800 + 0x1a0,
        # blacklist=[(0x102d5c, 0x0)],
        # blacklist_count=0x0000000A,
        # send_ptr=(0x102888, 0xE79C),
        # ctrl_buffer=0x00103024,
        # cmd_handler=0x000101E8,
        # brom_register_access=(0xf99a, 0xfa0c),
        # meid_addr=0x1008EC,
        # socid_addr=0x100934,
        # prov_addr=0x1066C0,
        efuse_addr=0x11F10000,
        damode=DAmodes.XML,
        dacode=0x1375,
        has64bit=True,
        name="MT6878",
        description="Dimensity 7300"
        # loader="mt6878_payload.bin"
    ),
    0x1471: Chipconfig(
        var1=0xA,
        watchdog=0x1c010000,
        uart=0x16010000,
        brom_payload_addr=0x100A00,
        da_payload_addr=0x201000,
        pl_payload_addr=0x40200000,
        # gcpu_base=0x10050000,
        dxcc_base=0x18005000,
        sej_base=0x1800E000,
        # cqdma_base=0x10212000,
        # ap_dma_mem=0x11300800 + 0x1a0,
        # blacklist=[(0x102d5c, 0x0)],
        # blacklist_count=0x0000000A,
        # send_ptr=(0x102888, 0xE79C),
        # ctrl_buffer=0x00103024,
        # cmd_handler=0x000101E8,
        # brom_register_access=(0xf99a, 0xfa0c),
        meid_addr=0x1008EC,
        socid_addr=0x100934,
        # prov_addr=0x1066C0,
        efuse_addr=0x10160000,
        damode=DAmodes.XML,
        dacode=0x1471,
        has64bit=True,
        name="MT6993",
        description="Dimensity 9500"
        # loader="mt6985_payload.bin"
    ),
    0x8127: Chipconfig(
        var1=0xA,
        watchdog=0x10007000,
        uart=0x11002000,
        brom_payload_addr=0x100A00,
        da_payload_addr=0x201000,
        pl_payload_addr=0x80001000,
        gcpu_base=0x11010000,
        sej_base=0x1000A000,
        # no cqdma_base
        ap_dma_mem=0x11000000 + 0x1A0,
        blacklist=[(0x102870, 0x0), (0x00106C7C, 0x0)],
        blacklist_count=0x00000008,
        send_ptr=(0x1028b0, 0xb2b8),
        ctrl_buffer=0x00103178,
        cmd_handler=0x0000BDF3,
        brom_register_access=(0xb58c, 0xb740),
        meid_addr=0x1031CC,
        misc_lock=0x10002050,
        damode=DAmodes.LEGACY,  #
        dacode=0x8127,
        name="MT8127/MT3367/AC8227L",
        description="",
        loader="mt8127_payload.bin"),  # ford,austin,tank #mhmm wdt, nochmal checken
    0x8135: Chipconfig(  # var1
        watchdog=0x10000000,
        uart=0x11002000,
        # brom_payload_addr
        da_payload_addr=0x12001000,
        pl_payload_addr=0x80001000,
        gcpu_base=0x11018000,
        # sej_base
        # cqdma_base
        # ap_dma_mem
        # blacklist
        # blacklist_count
        # send_ptr
        # ctrl_buffer
        # cmd_handler
        # brom_register_access
        # meid_addr
        # socid_addr
        damode=DAmodes.LEGACY,  #
        dacode=0x8135,
        name="MT8135"
        # description
        # loader
    ),
    0x8163: Chipconfig(
        var1=0xB1,
        watchdog=0x10007000,
        uart=0x11002000,
        brom_payload_addr=0x100A00,
        da_payload_addr=0x201000,
        pl_payload_addr=0x40001000,  #
        gcpu_base=0x10210000,
        sej_base=0x1000A000,
        # no dxcc
        cqdma_base=0x10212C00,
        ap_dma_mem=0x11000000 + 0x1A0,
        blacklist=[(0x102868, 0x0), (0x001072DC, 0x0)],
        blacklist_count=0x00000008,
        send_ptr=(0x1028a8, 0xc12c),
        ctrl_buffer=0x0010316C,
        cmd_handler=0x0000CCB3,
        brom_register_access=(0xc400, 0xc5c8),
        meid_addr=0x1031C0,
        misc_lock=0x10002050,
        efuse_addr=0x10206000,
        damode=DAmodes.LEGACY,  #
        dacode=0x8163,
        name="MT8163",
        loader="mt8163_payload.bin"),  # douglas, karnak
    0x8167: Chipconfig(var1=0xCC,
                       watchdog=0x10007000,
                       uart=0x11005000,
                       brom_payload_addr=0x100A00,
                       da_payload_addr=0x201000,
                       pl_payload_addr=0x40001000,  #
                       gcpu_base=0x1020D000,
                       sej_base=0x1000A000,
                       # no dxcc
                       cqdma_base=0x10212C00,
                       ap_dma_mem=0x11000000 + 0x1A0,
                       blacklist=[(0x102968, 0x0), (0x00107954, 0x0)],
                       blacklist_count=0x0000000A,
                       send_ptr=(0x1029ac, 0xd2e4),
                       ctrl_buffer=0x0010339C,
                       cmd_handler=0x0000DFF7,
                       brom_register_access=(0xd6f2, 0xd7ac),
                       meid_addr=0x103478,
                       socid_addr=0x103488,
                       efuse_addr=0x10009000,
                       damode=DAmodes.XFLASH,
                       dacode=0x8167,
                       name="MT8167/MT8516/MT8362",
                       # description
                       loader="mt8167_payload.bin"),
    0x8168: Chipconfig(
        var1=0xA,
        watchdog=0x10007000,
        uart=0x11002000,
        brom_payload_addr=0x100A00,
        da_payload_addr=0x201000,
        pl_payload_addr=0x40001000,
        gcpu_base=0x10241000,
        sej_base=0x1000A000,
        # cqdma_base
        ap_dma_mem=0x11000280 + 0x1A0,
        blacklist=[(0x10303C, 0x0), (0x10A540, 0x0)],
        blacklist_count=0xA,
        send_ptr=(0x103080, 0x13834),
        ctrl_buffer=0x0010637C,
        cmd_handler=0x1436F,
        brom_register_access=(0x13c18, 0x13d78),
        meid_addr=0x106438,
        socid_addr=0x106448,
        efuse_addr=0x10009000,
        damode=DAmodes.XFLASH,
        dacode=0x8168,
        name="MT8168/MT6357",
        # description, device is patched against kamakiri
        loader="mt8168_payload.bin"),
    0x8172: Chipconfig(
        var1=0xA,
        watchdog=0x10007000,
        uart=0x11002000,
        brom_payload_addr=0x120A00,
        da_payload_addr=0xC0000,
        pl_payload_addr=0x40001000,  #
        gcpu_base=0x10210000,
        sej_base=0x1000a000,
        # no dxcc
        cqdma_base=0x10212c00,
        ap_dma_mem=0x11000000 + 0x1A0,
        blacklist=[(0x122774, 0x0), (0x00125904, 0x0)],
        blacklist_count=0x00000008,
        send_ptr=(0x1227b4, 0xa0e4),
        ctrl_buffer=0x0012305C,
        cmd_handler=0x0000AC6B,
        brom_register_access=(0xa3b8, 0xa580),
        meid_addr=0x1230B0,
        misc_lock=0x1202050,
        damode=DAmodes.LEGACY,  #
        dacode=0x8173,
        name="MT8173",
        # description
        loader="mt8173_payload.bin"),  # sloane, suez
    0x8176: Chipconfig(
        var1=0xA,
        watchdog=0x10007000,
        uart=0x11002000,
        brom_payload_addr=0x120A00,
        da_payload_addr=0xC0000,
        pl_payload_addr=0x40200000,
        gcpu_base=0x10210000,
        sej_base=0x1000A000,
        # no dxcc
        cqdma_base=0x10212c00,
        ap_dma_mem=0x11000000 + 0x1A0,
        blacklist=[(0x122774, 0x0), (0x00125904, 0x0)],
        blacklist_count=0x00000008,
        send_ptr=(0x1227b4, 0xa0e4),
        ctrl_buffer=0x0012305C,
        cmd_handler=0x0000AC6B,
        brom_register_access=(0xa3b8, 0xa580),
        meid_addr=0x1230B0,
        misc_lock=0x1202050,
        # socid_addr
        efuse_addr=0x10206000,
        dacode=0x8173,
        damode=DAmodes.LEGACY,
        # description
        name="MT8176",
        loader="mt8176_payload.bin"),
    0x930: Chipconfig(
        # var1
        watchdog=0x10007000,
        uart=0x11001200,
        brom_payload_addr=0x100A00,
        da_payload_addr=0x201000,
        pl_payload_addr=0x40200000,
        # gcpu_base
        # sej_base
        # cqdma_base
        # ap_dma_mem
        # blacklist
        # blacklist_count
        # send_ptr
        # ctrl_buffer
        # cmd_handler
        # brom_register_access
        # meid_addr
        # socid_addr
        efuse_addr=0x11c10000,
        misc_lock=0x1001A100,
        dacode=0x8195,
        damode=DAmodes.XFLASH,
        # description
        name="MT8195 Chromebook"
        # loader
    ),
    0x8512: Chipconfig(
        var1=0xA,
        watchdog=0x10007000,
        uart=0x11002000,
        brom_payload_addr=0x100A00,
        da_payload_addr=0x111000,
        pl_payload_addr=0x40200000,
        gcpu_base=0x1020F000,
        sej_base=0x1000A000,
        cqdma_base=0x10214000,
        ap_dma_mem=0x11000000 + 0x1A0,
        blacklist=[(0x001041E4, 0x0), (0x0010AA84, 0x0)],
        blacklist_count=0xA,
        send_ptr=(0x104258, 0xcc44),
        ctrl_buffer=0x00104570,
        cmd_handler=0x0000D7AB,
        brom_register_access=(0xd034, 0xd194),
        meid_addr=0x104638,
        socid_addr=0x104648,
        efuse_addr=0x11c50000,
        dacode=0x8512,
        damode=DAmodes.XFLASH,
        # description
        name="MT8512",
        loader="mt8512_payload.bin"
    ),
    0x8518: Chipconfig(  # var1
        # watchdog
        # uart
        # brom_payload_addr
        # da_payload_addr
        # gcpu_base
        # sej_base
        # cqdma_base
        # ap_dma_mem
        # blacklist
        # blacklist_count
        # send_ptr
        # ctrl_buffer
        # cmd_handler
        # brom_register_access
        # meid_addr
        # socid_addr
        efuse_addr=0x10009000,
        dacode=0x8518,
        damode=DAmodes.XFLASH,
        name="MT8518 VoiceAssistant"
        # loader
    ),
    0x8590: Chipconfig(
        var1=0xA,  # confirmed, router
        watchdog=0x10007000,
        uart=0x11002000,
        brom_payload_addr=0x100A00,
        da_payload_addr=0x201000,
        pl_payload_addr=0x80001000,
        gcpu_base=0x1101B000,
        sej_base=0x1000A000,
        # cqdma_base
        # ap_dma_mem=0x11000000 + 0x1A0,
        blacklist=[(0x102870, 0x0), (0x106c7c, 0x0)],
        blacklist_count=0x00000008,
        send_ptr=(0x1028b0, 0xbbe4),
        ctrl_buffer=0x00103184,
        cmd_handler=0x0000C71F,
        brom_register_access=(0xbeb8, 0xc06c),
        meid_addr=0x1031D8,
        dacode=0x8590,
        damode=DAmodes.LEGACY,
        name="MT8590/MT7683/MT8521/MT7623",
        # description=
        loader="mt8590_payload.bin"),
    0x8695: Chipconfig(
        var1=0xA,  # confirmed
        watchdog=0x10007000,
        uart=0x11002000,
        brom_payload_addr=0x100A00,
        da_payload_addr=0x201000,
        pl_payload_addr=0x40001000,  #
        # gcpu_base
        sej_base=0x1000A000,
        # cqdma_base
        ap_dma_mem=0x11000280 + 0x1A0,
        blacklist=[(0x103048, 0x0), (0x00106EC4, 0x0)],
        blacklist_count=0x0000000A,
        send_ptr=(0x103088, 0xbeec),
        ctrl_buffer=0x001031EC,
        cmd_handler=0x0000CAA7,
        brom_register_access=(0xc298, 0xc3f8),
        meid_addr=0x1032B8,
        efuse_addr=0x10206000,
        damode=DAmodes.XFLASH,
        dacode=0x8695,
        name="MT8695",  # mantis
        # description
        loader="mt8695_payload.bin"),
    0x908: Chipconfig(
        # var1
        watchdog=0x10007000,
        # uart
        brom_payload_addr=0x100A00,
        da_payload_addr=0x201000,
        # gcpu_base
        # sej_base
        # cqdma_base
        # ap_dma_mem
        # blacklist
        # blacklist_count
        # send_ptr
        # ctrl_buffer
        # cmd_handler
        # brom_register_access
        # meid_addr
        # socid_addr
        efuse_addr=0x11c10000,
        damode=DAmodes.XFLASH,
        dacode=0x8696,
        # description
        name="MT8696"
        # loader
    ),
}
