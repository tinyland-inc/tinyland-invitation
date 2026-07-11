import { readFileSync } from 'node:fs';
import { describe, expect, it } from 'vitest';

const readRepoFile = (path: string): string =>
  readFileSync(new URL(`../${path}`, import.meta.url), 'utf8');

describe('release version parity', () => {
  it('keeps npm, Bzlmod, and Bazel package versions aligned', () => {
    const packageVersion = JSON.parse(readRepoFile('package.json')).version as string;
    const moduleFile = readRepoFile('MODULE.bazel');
    const buildFile = readRepoFile('BUILD.bazel');
    const moduleBlock = moduleFile.match(/module\([\s\S]*?\n\)/)?.[0];
    const npmPackageBlock = buildFile.match(/npm_package\([\s\S]*?\n\)/)?.[0];

    expect(moduleBlock).toContain(`version = "${packageVersion}"`);
    expect(npmPackageBlock).toContain(`version = "${packageVersion}"`);
  });
});
