import assert from 'node:assert/strict';
import { test } from 'node:test';
import { checkPins } from './check-pins.mjs';

const revision = '6b94dacd7fa04aa8847c62c6471a1fc5c0f6c9dc';
const older = '9c076b1e4050529406df27533e12c8e0dd1fc0db';
const source = (name, rev = revision) =>
  `git+https://git.corbet.ch/corbet-foss/${name}?rev=${rev}#${rev}`;
const pkg = (name, source = null, dependencies = []) => ({ name, source, dependencies });
const graph = (...packages) => ({
  packages: [pkg('crbk'), pkg('crlt', source('crlt')), ...packages],
});

test('accept a single revision per leaf and unrelated registry duplicates', () => {
  checkPins(graph(pkg('serde'), pkg('thiserror'), pkg('thiserror')));
});

test('reject duplicate direct and transitive Corbet packages', () => {
  assert.throws(() => checkPins(graph(pkg('crlt', source('crlt', older)))), /duplicated/);
  assert.throws(() => checkPins(graph(
    pkg('csgn', source('csgn')), pkg('csgn', source('csgn', older)),
  )), /duplicated/);
  assert.throws(() => checkPins(graph(pkg('crlt'))), /duplicated/);
});

test('reject other branches, tags, unqualified and abbreviated revisions', () => {
  for (const query of ['branch=develop', 'tag=v1', '', `rev=${revision.slice(0, 7)}`]) {
    const floating = `git+https://git.corbet.ch/corbet-foss/csgn?${query}#${revision}`;
    assert.throws(() => checkPins(graph(pkg('csgn', floating))), /revision pin/);
  }
});

test('reject a resolved revision different from its pin', () => {
  const mismatch = source('csgn').replace(`#${revision}`, `#${older}`);
  assert.throws(() => checkPins(graph(pkg('csgn', mismatch))), /revision pin/);
});

test('accept main declarations with a unique complete resolution', () => {
  const dependency = { source: 'git+https://git.corbet.ch/corbet-foss/cpns?branch=main' };
  checkPins(graph(
    pkg('cgrd', source('cgrd'), [dependency]),
    pkg('cpns', `git+https://git.corbet.ch/corbet-foss/cpns?branch=main#${revision}`),
  ));
});

test('require the crlt Git dependency', () => {
  assert.throws(() => checkPins({ packages: [pkg('crbk')] }), /Missing/);
  assert.throws(() => checkPins({ packages: [pkg('crbk'), pkg('crlt')] }), /unpinned/);
});


test('retain only exact original cchr/cmbl/cmmr v01 owners', () => {
  for (const [name, suffix] of [['cchr', ''], ['cmbl', '.git'], ['cmmr', '.git']]) {
    const repo = `https://git.corbet.ch/corbet-foss/${name}${suffix}`;
    const original = `git+${repo}?branch=v01#${revision}`;
    checkPins(graph(pkg(name, original, [{ name, source: `git+${repo}?branch=v01` }])));
    for (const invalid of [original.replace('branch=v01', 'branch=main'),
      original.replace('branch=v01', 'branch=other'),
      original.replace('branch=v01', 'branch=v01&branch=v01'),
      original.replace(repo, `${repo}.git`), original.replace(`#${revision}`, '#short')]) {
      assert.throws(() => checkPins(graph(pkg(name, invalid))), /revision pin/);
    }
    assert.throws(() => checkPins(graph(pkg('foreign', original))), /revision pin/);
    assert.throws(() => checkPins(graph(pkg(name, original), pkg(name, original))), /duplicated/);
  }
});
