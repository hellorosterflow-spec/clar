/** Small byte helpers. No secrets are logged from here. */

export function hexToBytes(hex) {
  const body = hex.length >= 2 && hex[0] === '0' && (hex[1] === 'x' || hex[1] === 'X') ? hex.slice(2) : hex;
  if (body.length % 2 !== 0 || /[^0-9a-fA-F]/.test(body)) {
    throw new Error('hex invalid');
  }
  const out = new Uint8Array(body.length / 2);
  for (let i = 0; i < out.length; i += 1) {
    out[i] = Number.parseInt(body.slice(i * 2, i * 2 + 2), 16);
  }
  return out;
}

export function bytesToHex(bytes) {
  let out = '';
  for (let i = 0; i < bytes.length; i += 1) out += bytes[i].toString(16).padStart(2, '0');
  return out;
}

export function equalBytes(left, right) {
  if (left.length !== right.length) return false;
  let diff = 0;
  for (let i = 0; i < left.length; i += 1) diff |= left[i] ^ right[i];
  return diff === 0;
}

/** Force a copy so a small slice does not keep a multi-megabyte parent string alive. */
export function copyString(value) {
  return value.length ? `${value}` : '';
}
