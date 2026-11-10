// CRC-24 of the ASCII armor, RFC 4880 §6.1 (generator 0x864CFB, initial 0xB704CE).

export function crc24(data: Uint8Array): number {
  let crc = 0xb704ce;
  for (let i = 0; i < data.length; i++) {
    crc ^= data[i] << 16;
    for (let bit = 0; bit < 8; bit++) {
      crc <<= 1;
      if (crc & 0x1000000) crc ^= 0x1864cfb;
    }
  }
  return crc & 0xffffff;
}
