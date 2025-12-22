/* eslint-disable no-console */
'use strict';

const fs = require('fs');
const path = require('path');

const createDOMPurify = require('../vendor/DOMPurify/dist/purify.cjs.js');
const { JSDOM } = require('../vendor/DOMPurify/node_modules/jsdom');

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

function recordCase(kind, testName, actual, expected) {
  if (typeof actual !== 'string') return;
  if (!(typeof expected === 'string' || (Array.isArray(expected) && expected.every((v) => typeof v === 'string')))) {
    return;
  }
  let call = consumeCallForActual(actual);
  if (!call) {
    // Config tests like RETURN_DOM do `DOMPurify.sanitize(...).outerHTML`, so the assertion
    // value is a string even though `sanitize()` returned a DOM node. In that case, the most
    // recent sanitize call is the right one to attribute.
    const last = pendingSanitizeCalls[pendingSanitizeCalls.length - 1] || null;
    if (last && typeof last.output !== 'string') {
      call = pendingSanitizeCalls.pop();
    }
  }
  if (!call) return;
  if (!isPayloadSupported(call.dirty)) return;
  if (!isJsonSerializable(call.config)) return;
  if (!isJsonSerializable(expected)) return;

  cases.push({
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
    if (!name.startsWith('Config-Flag tests')) return;
    pendingSanitizeCalls.length = 0;
    const assert = {
      equal(actual, expected) {
        recordCase('equal', name, actual, expected);
      },
      contains(actual, expected) {
        recordCase('contains', name, actual, expected);
      },
      notEqual() {},
      ok() {},
      notOk() {},
      deepEqual() {},
      throws() {},
      async() {
        return () => {};
      },
    };

    try {
      fn(assert);
    } catch (err) {
      console.warn(`Skipping test due to error: ${name}`);
      console.warn(err);
    }
  },
  assert: {},
  config: {},
};

testSuite(DOMPurify, window, [], []);

const outPath = path.join(
  __dirname,
  '..',
  'Tests',
  'SwiftDOMPurifyTests',
  'Fixtures',
  'config-tests.json'
);

fs.writeFileSync(outPath, JSON.stringify(cases, null, 2) + '\n', 'utf8');
console.log(`Wrote ${cases.length} cases to ${outPath}`);
