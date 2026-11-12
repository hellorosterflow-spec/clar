import assert from 'node:assert/strict';
import test from 'node:test';
import { zipSync } from 'fflate';
import { extractKeysFromFile, FileReadError, MAX_FILE_BYTES } from './read-files.js';

const HARDHAT = 'ac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80';

test('reads a text file in chunks and finds a key across the chunk boundary', async () => {
  const token = `0x${HARDHAT}`;
  const offset = (256 * 1024) - 16;
  const bytes = new Uint8Array(offset + token.length + 20);
  bytes.fill(46);
  bytes.set(new TextEncoder().encode(token), offset);
  const file = new File([bytes], 'notes.txt', { type: 'text/plain' });
  let sawProgress = false;
  const result = await extractKeysFromFile(file, {
    onProgress: (event) => {
      if (event.phase === 'read' && event.loaded > 0 && event.loaded <= event.total) sawProgress = true;
    },
  });
  assert.equal(sawProgress, true);
  assert.equal(result.keys.length, 1);
  assert.equal(result.keys[0].hex.toLowerCase(), HARDHAT);
});

test('reads a docx document without keeping the XML wrapper', async () => {
  const xml = `<?xml version="1.0" encoding="UTF-8"?>
    <w:document xmlns:w="http://schemas.openxmlformats.org/wordprocessingml/2006/main">
      <w:p><w:r><w:t>0x${HARDHAT.slice(0, 20)}</w:t><w:t>${HARDHAT.slice(20)}</w:t></w:r></w:p>
    </w:document>`;
  const zipped = zipSync({ 'word/document.xml': new TextEncoder().encode(xml) });
  const file = new File([zipped], 'backup.docx');
  const result = await extractKeysFromFile(file);
  assert.equal(result.keys.length, 1);
  assert.equal(result.keys[0].hex.toLowerCase(), HARDHAT);
});

test('rejects unsupported files, files over the cap, and aborted reads', async () => {
  await assert.rejects(
    extractKeysFromFile(new File(['abc'], 'keys.zip')),
    (error) => error instanceof FileReadError && error.code === 'unsupported',
  );
  await assert.rejects(
    extractKeysFromFile({ name: 'big.txt', size: MAX_FILE_BYTES + 1 }),
    (error) => error instanceof FileReadError && error.code === 'too-big',
  );
  const controller = new AbortController();
  controller.abort();
  await assert.rejects(
    extractKeysFromFile(new File([`0x${HARDHAT}`], 'late.txt'), { signal: controller.signal }),
    (error) => error.name === 'AbortError',
  );
});

test('scans csv, json, log, md and html as text', async () => {
  const csv = new File([`id,secret\n1,${HARDHAT}\n`], 'wallets.csv');
  const result = await extractKeysFromFile(csv);
  assert.equal(result.keys.length, 1);
  assert.equal(result.keys[0].format, 'evm-hex');
});
