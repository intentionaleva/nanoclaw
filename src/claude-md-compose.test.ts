/**
 * Tests for composeGroupClaudeMd — verifies the composed CLAUDE.md
 * always imports per-group CLAUDE.local.md (per-group memory/identity).
 */
import fs from 'fs';
import os from 'os';
import path from 'path';
import { describe, it, expect, beforeEach, afterEach, vi } from 'vitest';

import type { AgentGroup } from './types.js';

const TEST_ROOT = path.join(os.tmpdir(), 'nanoclaw-test-compose');
const TEST_GROUPS_DIR = path.join(TEST_ROOT, 'groups');

vi.mock('./config.js', async () => {
  const actual = await vi.importActual<typeof import('./config.js')>('./config.js');
  return { ...actual, GROUPS_DIR: TEST_GROUPS_DIR };
});

vi.mock('./db/container-configs.js', () => ({
  getContainerConfig: () => null,
}));

const { composeGroupClaudeMd } = await import('./claude-md-compose.js');

const GROUP: AgentGroup = {
  id: 'ag-test',
  name: 'Test',
  folder: 'test-group',
  agent_provider: null,
  created_at: '2026-01-01T00:00:00.000Z',
};

beforeEach(() => {
  fs.rmSync(TEST_ROOT, { recursive: true, force: true });
  fs.mkdirSync(TEST_GROUPS_DIR, { recursive: true });
});

afterEach(() => {
  fs.rmSync(TEST_ROOT, { recursive: true, force: true });
});

function readComposed(): string {
  return fs.readFileSync(path.join(TEST_GROUPS_DIR, GROUP.folder, 'CLAUDE.md'), 'utf-8');
}

describe('composeGroupClaudeMd CLAUDE.local.md import', () => {
  it('always imports @./CLAUDE.local.md', () => {
    composeGroupClaudeMd(GROUP);
    expect(readComposed()).toContain('@./CLAUDE.local.md');
  });

  it('creates CLAUDE.local.md if missing so the import is never dangling', () => {
    composeGroupClaudeMd(GROUP);
    const localPath = path.join(TEST_GROUPS_DIR, GROUP.folder, 'CLAUDE.local.md');
    expect(fs.existsSync(localPath)).toBe(true);
  });

  it('imports CLAUDE.local.md after the shared base and after fragments', () => {
    composeGroupClaudeMd(GROUP);
    const body = readComposed();
    const sharedIdx = body.indexOf('@./.claude-shared.md');
    const localIdx = body.indexOf('@./CLAUDE.local.md');
    expect(sharedIdx).toBeGreaterThanOrEqual(0);
    expect(localIdx).toBeGreaterThan(sharedIdx);
  });

  it('is idempotent — re-running produces the same body', () => {
    composeGroupClaudeMd(GROUP);
    const first = readComposed();
    composeGroupClaudeMd(GROUP);
    const second = readComposed();
    expect(second).toBe(first);
  });
});
