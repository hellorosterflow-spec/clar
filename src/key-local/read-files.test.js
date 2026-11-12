import assert from 'node:assert/strict';
import test from 'node:test';
import { zipSync } from 'fflate';
import {
  extractKeysFromFile,
  FileReadError,
  MAX_DOCUMENT_BYTES,
  MAX_FILE_BYTES,
  READ_CHUNK_BYTES,
} from './read-files.js';

const HARDHAT = 'ac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80';

test('reads a text file in chunks and finds a key across the chunk boundary', async () => {
  const token = `0x${HARDHAT}`;
  const offset = READ_CHUNK_BYTES - 16;
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
    (error) => error instanceof FileReadError && error.code === 'too-big' && error.message.includes('1 GB') && !error.message.includes('1024'),
  );
  const controller = new AbortController();
  controller.abort();
  await assert.rejects(
    extractKeysFromFile(new File([`0x${HARDHAT}`], 'late.txt'), { signal: controller.signal }),
    (error) => error.name === 'AbortError',
  );
});

test('accepts a decimal 1 GB text file and keeps PDF and DOCX at 100 MB', async () => {
  const oneDecimalGb = 1_000_000_000;
  assert.ok(oneDecimalGb <= MAX_FILE_BYTES);

  await assert.rejects(
    extractKeysFromFile({ name: 'notes.txt', size: oneDecimalGb }),
    (error) => !(error instanceof FileReadError),
  );
  await assert.rejects(
    extractKeysFromFile({ name: 'notes.csv', size: MAX_FILE_BYTES }),
    (error) => !(error instanceof FileReadError),
  );

  await assert.rejects(
    extractKeysFromFile({ name: 'scan.pdf', size: MAX_DOCUMENT_BYTES + 1 }),
    (error) => {
      assert.ok(error instanceof FileReadError);
      assert.equal(error.code, 'too-big-document');
      assert.match(error.message, /deschis ca întreg/);
      assert.match(error.message, /100 MB/);
      assert.match(error.message, /1 GB/);
      assert.match(error.message, /TXT, CSV, JSON, LOG, MD sau HTML/);
      assert.doesNotMatch(error.message, /1024/);
      return true;
    },
  );
  await assert.rejects(
    extractKeysFromFile({ name: 'backup.docx', size: MAX_FILE_BYTES }),
    (error) => error instanceof FileReadError && error.code === 'too-big-document',
  );
  await assert.rejects(
    extractKeysFromFile({ name: 'ok.pdf', size: MAX_DOCUMENT_BYTES }),
    (error) => !(error instanceof FileReadError && error.code === 'too-big-document'),
  );
  await assert.rejects(
    extractKeysFromFile({ name: 'ok.docx', size: MAX_DOCUMENT_BYTES }),
    (error) => !(error instanceof FileReadError && error.code === 'too-big-document'),
  );
});

test('scans csv, json, log, md and html as text', async () => {
  const csv = new File([`id,secret\n1,${HARDHAT}\n`], 'wallets.csv');
  const result = await extractKeysFromFile(csv);
  assert.equal(result.keys.length, 1);
  assert.equal(result.keys[0].format, 'evm-hex');
});
