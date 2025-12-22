/* eslint-disable no-console */
'use strict';

const fs = require('fs');
const path = require('path');

const createDOMPurify = require('../vendor/DOMPurify/dist/purify.cjs.js');
const { JSDOM } = require('../vendor/DOMPurify/node_modules/jsdom');

function loadExpectFixtures() {
  const text = fs.readFileSync(
    path.join(__dirname, '..', 'vendor', 'DOMPurify', 'test', 'fixtures', 'expect.mjs'),
    'utf8'
  );
  const exportIndex = text.indexOf('export default');
  if (exportIndex === -1) throw new Error('Could not find export default in expect.mjs');
  const arrayStart = text.indexOf('[', exportIndex);
  const arrayEnd = text.lastIndexOf(']');
  if (arrayStart === -1 || arrayEnd === -1) throw new Error('Could not locate JSON array in expect.mjs');
  return JSON.parse(text.slice(arrayStart, arrayEnd + 1));
}

const fixtures = loadExpectFixtures();
const xssTests = fixtures.filter((t) => /alert/.test(t.payload));

const { window } = new JSDOM(
  `<html><head></head><body><div id="qunit-fixture"></div></body></html>`,
  { runScripts: 'dangerously' }
);
require('../vendor/DOMPurify/node_modules/jquery')(window);

const DOMPurify = createDOMPurify(window);
const testSuite = require('../vendor/DOMPurify/test/test-suite');

const pendingSanitizeCalls = [];
const originalSanitize = DOMPurify.sanitize.bind(DOMPurify);
DOMPurify.sanitize = function (dirty, config) {
  const output = originalSanitize(dirty, config);
  pendingSanitizeCalls.push({ dirty, config: config ?? null, output });
  return output;
};

function isJsonSerializable(value) {
  if (value === null) return true;
  const t = typeof value;
  if (t === 'string' || t === 'number' || t === 'boolean') return true;
  if (Array.isArray(value)) return value.every(isJsonSerializable);
  if (t === 'object') {
    if (value instanceof RegExp) return true;
    // Skip DOM nodes and other host objects.
    const proto = Object.getPrototypeOf(value);
    if (proto !== Object.prototype && proto !== null) return false;
    return Object.values(value).every(isJsonSerializable);
  }
  return false;
}

function serializeValue(value) {
  if (value instanceof RegExp) {
    return { __type: 'RegExp', source: value.source, flags: value.flags };
  }
  if (Array.isArray(value)) return value.map(serializeValue);
  if (value && typeof value === 'object') {
    const out = {};
    for (const [k, v] of Object.entries(value)) {
      out[k] = serializeValue(v);
    }
    return out;
  }
  return value;
}

function isPayloadSupported(dirty) {
  if (typeof dirty === 'string') return true;
  if (Array.isArray(dirty) && dirty.every((v) => typeof v === 'string')) return true;
  return false;
}

function consumeCallForActual(actual) {
  for (let i = pendingSanitizeCalls.length - 1; i >= 0; i -= 1) {
    if (pendingSanitizeCalls[i].output === actual) {
      return pendingSanitizeCalls.splice(i, 1)[0];
    }
  }
  return null;
}

const cases = [];
const removedCases = [];

function recordCase(kind, testName, actual, expected) {
  if (typeof actual !== 'string') return;
  if (
    !(
      typeof expected === 'string' ||
      (Array.isArray(expected) && expected.every((v) => typeof v === 'string'))
    )
  ) {
    return;
  }

  // We already port `expect.mjs` directly, and Config-Flag tests are extracted separately.
  if (testName.startsWith('Sanitization test[')) return;
  if (testName.startsWith('Config-Flag tests:')) return;

  let call = consumeCallForActual(actual);
  if (!call) {
    // Tests like "Test proper handling of attributes with RETURN_DOM" do
    // `DOMPurify.sanitize(...).outerHTML` so we need to attribute to the last call.
    const last = pendingSanitizeCalls[pendingSanitizeCalls.length - 1] || null;
    if (last && typeof last.output !== 'string') {
      call = pendingSanitizeCalls.pop();
    }
  }
  if (!call) return;
  if (!isPayloadSupported(call.dirty)) return;
  if (!isJsonSerializable(call.config)) return;

  cases.push({
    name: testName,
    kind,
    payload: call.dirty,
    config: serializeValue(call.config),
    expected,
  });
}

function recordRemovedLengthCase(kind, testName, actual, expected) {
  if (typeof actual !== 'number') return;
  if (!(typeof expected === 'number' || (Array.isArray(expected) && expected.every((v) => typeof v === 'number')))) {
    return;
  }

  const call = pendingSanitizeCalls[pendingSanitizeCalls.length - 1] || null;
  if (!call) return;
  if (!isPayloadSupported(call.dirty)) return;
  if (!isJsonSerializable(call.config)) return;

  removedCases.push({
    name: testName,
    kind,
    payload: call.dirty,
    config: serializeValue(call.config),
    expected,
  });
}

global.QUnit = {
  module(_name, fn) {
    if (typeof fn === 'function') fn();
  },
  test(name, fn) {
    // Reset per-test tracking so calls from prior tests don't get misattributed.
    pendingSanitizeCalls.length = 0;

    // Skip slow / async browser-execution safety checks (not meaningful for Swift string-based port).
    if (name.startsWith('XSS test:')) return;

    // Skip stateful API tests (hooks, setConfig/clearConfig, etc.) until we have a richer harness.
    if (name.startsWith('ensure that a persistent configuration')) return;
    if (name.startsWith('ensure that a hook can add allowed tags')) return;
    if (name.startsWith('sanitize() should not throw if the original document is clobbered')) return;
    if (name.startsWith('removeHook')) return;

    const assert = {
      equal(actual, expected) {
        recordCase('equal', name, actual, expected);
        if (name.startsWith('DOMPurify.removed')) {
          recordRemovedLengthCase('equal', name, actual, expected);
        }
      },
      contains(actual, expected) {
        recordCase('contains', name, actual, expected);
        if (name.startsWith('DOMPurify.removed')) {
          recordRemovedLengthCase('contains', name, actual, expected);
        }
      },
      strictEqual(actual, expected) {
        recordCase('equal', name, actual, expected);
      },
      notEqual() {},
      ok() {},
      notOk() {},
      deepEqual() {},
      throws() {},
      async() {
        return () => {};
      },
      expect() {},
    };

    try {
      fn(assert);
    } catch (err) {
      // Some upstream tests rely on a real browser environment; skip.
    }
  },
  assert: {},
  config: {},
};

testSuite(DOMPurify, window, fixtures, xssTests);

const outPath = path.join(
  __dirname,
  '..',
  'Tests',
  'SwiftDOMPurifyTests',
  'Fixtures',
  'suite-tests.json'
);

fs.writeFileSync(outPath, JSON.stringify(cases, null, 2) + '\n', 'utf8');
console.log(`Wrote ${cases.length} cases to ${outPath}`);

const removedOutPath = path.join(
  __dirname,
  '..',
  'Tests',
  'SwiftDOMPurifyTests',
  'Fixtures',
  'removed-tests.json'
);

fs.writeFileSync(removedOutPath, JSON.stringify(removedCases, null, 2) + '\n', 'utf8');
console.log(`Wrote ${removedCases.length} cases to ${removedOutPath}`);
