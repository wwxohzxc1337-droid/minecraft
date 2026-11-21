#!/usr/bin/env python3
"""
Decodes all XOR-encrypted strings from the RemoteWrapper.Proxy decompile.
Algorithm: XOR first (len - skip) bytes with key. That's it.
(key * 16843009 mod 2^32 == key repeated 4 times when key < 256)
"""

# (raw_bytes, key, skip, label)
entries = [
    (b'\x164\x165-|\x182\x177r<ZsEY3,}%YjRD2', 83, 13, "v_u_48[4]"),
    (b'\x156\x169-a\x169\x1651EF^', 72, 3, "v_u_48[9]"),
    (b'\x128\x171={\x168\x1311l\x166\x164 w\x177', 67, 0, "v_u_48[28]"),
    (b'\x184\x1851`\x170\x190`{c!}?5y', 79, 7, "v_u_48[38]"),
    (b'\x128\x166$_\x168\x174 s\x169\x166>h\x180', 71, 0, "v_u_48[42]"),
    (b'\x159\x155:t\x164\x161', 64, 0, "v_u_48[53]"),
    (b'\x162\x177&o\x163\x1605b\x190\x179', 80, 0, "v_u_48[61]"),
    (b'\x154\x191\x01\x188\x180,z\x156\x1914a\x190\x180', 85, 0, "v_u_48[65]"),
    (b'\x186\x189 i\x165\x1663d\x184\x181', 86, 0, "v_u_48[75]"),
    (b'\x234.', 50, 1, "v_u_48[78]"),
    (b'\x189\x190+|\x160\x173dl-', 78, 3, "v_u_48[88]"),
    (b',;?:+frHM(5P[p!_;1F4mp5p{&B{$2', 94, 24, "v_u_48[90]"),
    (b'\x181\x176%e\x181\x176yig7)Jq2^5K', 81, 11, "v_u_48[92]"),
    (b'q^RZ', 63, 0, "v_u_48[95]"),
    (b'\x182\x185\'g\x183\x178', 83, 0, "v_u_48[101]"),
    (b'cLW@v@WS@WX{M!8%#NzbE0nug&kXi', 37, 19, "v_u_48[111]"),
    (b'\x168\x1752{\x183\x180!v\x170\x167{6\x228\x169 ?\x170\x175\'?\x165\x1822v\x168\x1611s\x161', 68, 0, "v_u_48[119]"),
    (b'\x143\x142)v\x161\x173', 76, 0, "v_u_48[127]"),
    (b'\x180\x1670y\x179\x243g', 70, 0, "v_u_48[133]"),
    (b'`KBQB@WFQ', 35, 0, "v_u_48[136]"),
    (b'\x146\x1504s\x186\x1604r\x168\x177', 77, 0, "v_u_48[148]"),
    (b'h_WUN_|OTYNSUT0k', 58, 2, "v_u_48[152]"),
    (b'\x155\x1729b\x162\x187i^,AHlP@nzWq1^gf}B},3', 77, 20, "v_u_48[158]"),
    (b'\x176\x164&q\x179\x1791gzexjffwI1p', 67, 12, "v_u_48[161]"),
    (b'GDKAG#6CVYJYf4rT+vgksBVguc@*l.', 37, 26, "v_u_48[164]"),
    (b'\x222\x221K', 48, 0, "v_u_48[172]"),
    (b'\x165\x172?p\x162\x162>', 71, 0, "v_u_48[177]"),
    (b'\x151\x165>o_PHvRETIR##O^y$', 64, 15, "v_u_48[181]"),
    (b'\x156\x1745d\x141\x160.S\x163\x1660tBU9@FtL=]}@w', 75, 12, "v_u_48[296]"),
    (b'\x164', 79, 0, "v_u_48[?single]"),
    (b'\x227\x246r:\x244\x225', 0, 0, "v_u_48[?raw]"),
    (b'\x242\x225v?\x245\x183%', 0, 0, "v_u_48[?raw]"),
    (b'\x171\x184/f\x191\x238|', 89, 0, "v_u_48[?]"),
    (b'\x185\x170=t\x173\x249h', 75, 0, "v_u_48[?]"),
    (b'\x240\x240e', 0, 0, "v_u_48[?raw]"),
    (b'\x168\x187;pPdo', 74, 4, "v_u_48[?]"),
    (b'\x232c2j:);6?jZe', 49, 11, "v_u_48[?]"),
    (b'\x246\x225t/\x239\x246', 0, 0, "v_u_48[?raw]"),
    (b'\x218', 0, 0, "v_u_48[?raw]"),
    (b'\x148\x191+m\x148\x1917z\x166\x149-`\x190\x178', 82, 0, "v_u_48[?]"),
    (b'\x205\x229o\x26\x227\x240~-\x225\x240~4\x238\x192~(\x244\x229y8\x229', 0, 0, "v_u_48[?raw]"),
    (b'\x188\x185-v\x191ZDBW;Zik2$yd0DJxUxu', 88, 19, "v_u_48[?]"),
    (b'', 109, 0, "v_u_48[?empty]"),
    (b'\x143\x147q=_sB%q', 80, 7, "v_u_48[?]"),
    (b'\x243\x236v)\x229\x224', 0, 0, "v_u_48[?raw]"),
    (b'\x223\x219~5\x228\x225o', 0, 0, "v_u_48[?raw]"),
    (b'\x131\x166\x24{\x165\x1735c\x137\x190>y\x184', 76, 0, "v_u_48[?]"),
    (b'81:L^.Bv6fh[d6z', 84, 12, "v_u_48[?]"),
    (b'P\x224m\x193/7!J1S;gbdnqZ$czr5$Ud;[0,oX', 75, 27, "v_u_48[?]"),
    (b'\x190\x1917f\x172\x184o$8hk8^SXm(3N', 73, 11, "v_u_48[?]"),
    (b'\x164\x186>oMFK{-', 70, 5, "v_u_48[?]"),
    (b'\x160\x163-w\x187\x185', 73, 0, "v_u_48[?]"),
    (b'\x142\x173#h\x166\x1733yr9TBbigm+L7rPlm9namadd', 71, 22, "v_u_48[?]"),
    (b'E^BECX_V', 49, 0, "v_u_48[?]"),
    (b'\x232\x235x0\x230\x241y8\x244\x237x5', 0, 0, "v_u_48[?raw]"),
    (b'\x160\x178)x', 87, 0, "v_u_48[?]"),
    (b'\x195\x235y5\x229\x231c', 0, 0, "v_u_48[?raw]"),
    (b'\x197\x226q>\x227\x240C2\x237\x225', 0, 0, "v_u_48[?raw]"),
    (b'\x199\x225c\x08\x229\x246a2\x227\x225', 0, 0, "v_u_48[?raw]"),
    (b'\x238\x225`', 0, 0, "v_u_48[?raw]"),
    (b'\x247\x246~/\x229\x241$i', 0, 0, "v_u_48[?raw]"),
    (b'\x226\x241q=\x229\x246', 0, 0, "v_u_48[?raw]"),
    (b'\x244\x229u7\x229', 0, 0, "v_u_48[?raw]"),
    (b'\x210\x225g7\x233\x231v/\x229\x224D/\x239\x246v<\x229', 0, 0, "v_u_48[?raw]"),
    (b'\x201\x234a4\x235\x225D>\x242\x242r)', 0, 0, "v_u_48[?raw]"),
    (b'\x231\x225c<\x229\x234a', 0, 0, "v_u_48[?raw]"),
    (b'\x198\x237e>\x211\x225e-\x229\x246', 0, 0, "v_u_48[?raw]"),
    (b'\x210\x225z4\x244\x225d', 0, 0, "v_u_48[?raw]"),
    (b'\x236\x225y', 0, 0, "v_u_48[?raw]"),
    (b'\x238\x241z9\x229\x246', 0, 0, "v_u_48[?raw]"),
]

def decode(raw: bytes, key: int, skip: int) -> bytes:
    n = len(raw) - skip
    return bytes(b ^ key for b in raw[:n])

print(f"{'INDEX':<12} {'DECODED':<50}")
print("=" * 62)
for raw, key, skip, label in entries:
    result = decode(raw, key, skip)
    # Try to show as UTF-8, fallback to repr
    try:
        display = result.decode('utf-8')
    except UnicodeDecodeError:
        display = repr(result)
    print(f"{label:<12} {display}")
