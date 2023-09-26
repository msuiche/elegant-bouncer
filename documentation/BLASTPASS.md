

`CVE-2023-4863` & `CVE-2023-41064`

```cpp
// Memory needed for lookup tables of one Huffman tree group. Red, blue, alpha
// and distance alphabets are constant (256 for red, blue and alpha, 40 for
// distance) and lookup table sizes for them in worst case are 630 and 410
// respectively. Size of green alphabet depends on color cache size and is equal
// to 256 (green component values) + 24 (length prefix values)
// + color_cache_size (between 0 and 2048).
// All values computed for 8-bit first level lookup with Mark Adler's tool:
// https://github.com/madler/zlib/blob/v1.2.5/examples/enough.c
#define FIXED_TABLE_SIZE (630 * 3 + 410)
static const uint16_t kTableSize[12] = {
  FIXED_TABLE_SIZE + 654,
  FIXED_TABLE_SIZE + 656,
  FIXED_TABLE_SIZE + 658,
  FIXED_TABLE_SIZE + 662,
  FIXED_TABLE_SIZE + 670,
  FIXED_TABLE_SIZE + 686,
  FIXED_TABLE_SIZE + 718,
  FIXED_TABLE_SIZE + 782,
  FIXED_TABLE_SIZE + 912,
  FIXED_TABLE_SIZE + 1168,
  FIXED_TABLE_SIZE + 1680,
  FIXED_TABLE_SIZE + 2704
};
```

## File Format
```
+---------------------------------------------------------------+
|      'R'      |      'I'      |      'F'      |      'F'      |
+---------------------------------------------------------------+
|                           File Size                           |
+---------------------------------------------------------------+
|      'W'      |      'E'      |      'B'      |      'P'      |
+------------------------- Chunk Header-------------------------+
|      'V'      |      'P'      |      '8'      |      'L'      |
+---------------------------------------------------------------+
|                         VP8L data size                        |
+---------------------------------------------------------------+
|                           VP8L data                           |
+---------------------------------------------------------------+
```

1. `huffman_tables` is allocated inside `ReadHuffmanCodes()`
```cpp
  huffman_tables = (HuffmanCode*)WebPSafeMalloc(num_htree_groups * table_size,
                                                sizeof(*huffman_tables));
```
The off-by-one will occur later at `huffman_tables + (num_htree_groups * table_size)`

2. `ReadHuffmanCodes()` -> `ReadHuffmanCode()` -> (...) -> `BuildHuffmanTable()`
Now in the part where the 2nd level table happens, the OOF can be triggered.
```cpp
    // Fill in 2nd level tables and add pointers to root table.
```
To Be Verified: Compare `code_lengths_size` with the above `num_htree_groups * table_size`:
```cpp
        bool is_overflow = ((key >> root_bits) + table_size) > code_lengths_size;
```
The OOF happens with `ReplicateValue()` 
```cpp
        if (is_overflow) {
          printf("[key >> root_bits] = 0x%08x (key = 0x%08x, root_bits = 0x%x, idx = %03d, table_size = 0x%08x, step = 0x%08x, code_lengths_size = %03d, code = (bits = 0x%x, value = 0x%x))\n",
            key >> root_bits, key, root_bits, idx, table_size, step, code_lengths_size, code.bits, code.value);
          printf("%s", ((key >> root_bits) + table_size) > code_lengths_size ? "overflow\n": "");
          printf("Write at %p (starting at %p)\n", &table[key >> root_bits], &table[(key >> root_bits) + table_size - step]);
        }
        idx++;
        ReplicateValue(&table[key >> root_bits], step, table_size, code);
        key = GetNextKey(key, len);
```

----
//------------------------------------------------------------------------------
// Decodes the next Huffman code from bit-stream.
// VP8LFillBitWindow(br) needs to be called at minimum every second call
// to ReadSymbol, in order to pre-fetch enough bits.
static WEBP_INLINE int ReadSymbol(const HuffmanCode* table,
                                  VP8LBitReader* const br) {
  int nbits;
  uint32_t val = VP8LPrefetchBits(br);
  table += val & HUFFMAN_TABLE_MASK;
  nbits = table->bits - HUFFMAN_TABLE_BITS;
  if (nbits > 0) {
    VP8LSetBitPos(br, br->bit_pos_ + HUFFMAN_TABLE_BITS);
    val = VP8LPrefetchBits(br);
    table += table->value;
    table += val & ((1 << nbits) - 1);
  }
  VP8LSetBitPos(br, br->bit_pos_ + table->bits);
  return table->value;
}


----
pre-level2 table = 0x16fd362e0
total_size = 0x80 (128)
VP8LReadBits()
VP8LPrefetchBits() (value = 0x49b9d, pos = 1) = 0x24dce
VP8LReadBits(1) -> 0x0
num_symbols = 280
VP8LPrefetchBits() (value = 0x49b9d, pos = 2) = 0x126e7
P8LSetBitPos(2 + 5)
VP8LPrefetchBits() (value = 0x49b9d, pos = 7) = 0x937
P8LSetBitPos(7 + 5)
VP8LPrefetchBits() (value = 0x49b9d, pos = 12) = 0x49
P8LSetBitPos(12 + 3)
VP8LPrefetchBits() (value = 0x49b9d, pos = 15) = 0x9
P8LSetBitPos(15 + 3)
VP8LPrefetchBits() (value = 0x49b9d, pos = 18) = 0x1
P8LSetBitPos(18 + 3)
VP8LPrefetchBits() (value = 0x49b9d, pos = 21) = 0x0
P8LSetBitPos(21 + 1)
VP8LPrefetchBits() (value = 0x49b9d, pos = 22) = 0x0
P8LSetBitPos(22 + 1)
VP8LPrefetchBits() (value = 0x49b9d, pos = 23) = 0x0



code_lengths[0] -> WriteBits(7, 5) (code_lengths[0] = 1)
code_lengths[1] -> WriteBits(23, 5) (code_lengths[1] = 2)
code_lengths[2] -> WriteBits(1, 3) (code_lengths[2] = 9)
code_lengths[3] -> WriteBits(1, 3) (code_lengths[3] = 9)
code_lengths[4] -> WriteBits(1, 3) (code_lengths[4] = 9)
code_lengths[5] -> WriteBits(0, 1) (code_lengths[5] = 10)
code_lengths[6] -> WriteBits(0, 1) (code_lengths[6] = 10)
code_lengths[7] -> WriteBits(0, 1) (code_lengths[7] = 10)
code_lengths[8] -> WriteBits(0, 1) (code_lengths[8] = 10)
code_lengths[9] -> WriteBits(0, 1) (code_lengths[9] = 10)