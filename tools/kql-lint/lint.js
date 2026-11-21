// Validates every detection query with Microsoft's official Kusto.Language parser
// (the engine behind the Kusto/Sentinel query editors) against the documented table
// schemas in schema.kql-schema. Fails on any syntax or semantic error, such as an
// unknown column, a misspelled table or an operator applied to the wrong type.
'use strict';

const fs = require('fs');
const path = require('path');
const yaml = require('js-yaml');
require('@kusto/language-service-next/bridge.js');
require('@kusto/language-service-next/Kusto.Language.Bridge.js');

const K = global.Kusto.Language;
const S = K.Symbols;

function loadGlobals(schemaFile) {
  const members = new (System.Collections.Generic.List$1(S.Symbol))();
  const lines = fs.readFileSync(schemaFile, 'utf8').split(/\r?\n/);
  for (const line of lines) {
    const m = line.match(/^(\w+):\s*(\(.+\))\s*$/);
    if (m) members.add(S.TableSymbol.From(m[2]).WithName(m[1]));
  }
  return K.GlobalState.Default.WithDatabase(new S.DatabaseSymbol.ctor('detections', members));
}

function diagnosticsFor(query, globals) {
  const code = K.KustoCode.ParseAndAnalyze(query, globals, null);
  const diags = code.GetDiagnostics();
  const out = [];
  for (let i = 0; i < diags.Count; i++) {
    const d = diags.getItem(i);
    const before = query.slice(0, d.Start);
    const line = before.split('\n').length;
    out.push({ severity: String(d.Severity), message: d.Message, line });
  }
  return out;
}

function main() {
  const dir = path.resolve(process.argv[2] || '../../detections');
  const globals = loadGlobals(path.join(__dirname, 'schema.kql-schema'));
  const files = fs.readdirSync(dir).filter((f) => f.endsWith('.yaml')).sort();
  let errorCount = 0;

  for (const file of files) {
    const rule = yaml.load(fs.readFileSync(path.join(dir, file), 'utf8'));
    const diags = diagnosticsFor(String(rule.query || ''), globals).filter((d) => d.severity === 'Error');
    if (diags.length === 0) {
      console.log(`[OK]   ${file}`);
      continue;
    }
    errorCount += diags.length;
    console.log(`[FAIL] ${file}`);
    for (const d of diags) console.log(`         query line ${d.line}: ${d.message}`);
  }

  console.log(`\n${files.length} queries checked, ${errorCount} error(s).`);
  process.exit(errorCount > 0 ? 1 : 0);
}

main();
