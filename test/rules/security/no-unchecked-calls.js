const assert = require('assert')
const linter = require('../../../lib/index')
const applyFixes = require('../../../lib/apply-fixes')
const ruleFixer = require('../../../lib/rule-fixer')
const funcWith = require('../../common/contract-builder').funcWith
const {
  assertWarnsCount,
  assertNoWarnings,
  assertErrorMessage,
  assertErrorCount,
} = require('../../common/asserts')

const RULE = 'no-unchecked-calls'

function lint(code, setup = 'warn') {
  return linter.processStr(code, { rules: { [RULE]: setup } })
}

function lintWarn(statement) {
  return lint(funcWith(statement))
}

describe('Linter - no-unchecked-calls', () => {
  describe('return value discarded (original behavior)', () => {
    it('should warn when call() return value is not checked', () => {
      const report = lintWarn('addr.call(data);')

      assertWarnsCount(report, 1)
      assertErrorMessage(report, 'not checked')
      assert.ok(!report.reports[0].message.includes('never checked'))
    })

    it('should warn when staticcall() return value is not checked', () => {
      const report = lintWarn('addr.staticcall(data);')

      assertWarnsCount(report, 1)
      assertErrorMessage(report, 'not checked')
    })

    it('should warn when delegatecall() return value is not checked', () => {
      const report = lintWarn('addr.delegatecall(data);')

      assertWarnsCount(report, 1)
      assertErrorMessage(report, 'not checked')
    })

    it('should warn when call{value} return value is not checked', () => {
      const report = lintWarn('addr.call{value: 1 ether}("");')

      assertWarnsCount(report, 1)
      assertErrorMessage(report, 'not checked')
    })

    it('should warn when parenthesized call return value is discarded', () => {
      const report = lintWarn('(addr.call(data));')

      assertWarnsCount(report, 1)
      assertErrorMessage(report, 'not checked')
    })

    it('should warn for legacy addr.call.value(1)() when return value is not checked', () => {
      const report = lintWarn('addr.call.value(1)();')

      assertWarnsCount(report, 1)
      assertErrorMessage(report, 'not checked')
    })

    it('should warn for legacy addr.call.value(1).gas(100)() when return value is not checked', () => {
      const report = lintWarn('addr.call.value(1).gas(100)();')

      assertWarnsCount(report, 1)
      assertErrorMessage(report, 'not checked')
    })

    it('should report as error when configured with error severity', () => {
      const code = funcWith('addr.call(data);')

      const report = lint(code, 'error')

      assertErrorCount(report, 1)
      assert.ok(report.reports[0].message.includes('not checked'))
    })
  })

  describe('return value captured but never checked (new behavior)', () => {
    it('should warn when tuple assignment result is never judged', () => {
      const report = lintWarn('(bool success, ) = addr.call(data);')

      assertWarnsCount(report, 1)
      assertErrorMessage(report, 'never checked')
    })

    it('should warn when tuple assignment with bytes result is never judged', () => {
      const report = lintWarn('(bool success, bytes memory result) = addr.call(data);')

      assertWarnsCount(report, 1)
      assertErrorMessage(report, 'never checked')
    })

    it('should warn when single variable declaration result is never judged', () => {
      const report = lintWarn('bool success = addr.call(data);')

      assertWarnsCount(report, 1)
      assertErrorMessage(report, 'never checked')
    })

    it('should warn when result is assigned to an existing variable and never judged', () => {
      const code = funcWith('bool success; success = addr.call(data);')

      const report = lint(code)

      assertWarnsCount(report, 1)
      assertErrorMessage(report, 'never checked')
    })

    it('should warn when tuple result is assigned to existing variables and never judged', () => {
      const code = funcWith(
        'bool success; bytes memory result; (success, result) = addr.call(data);',
      )

      const report = lint(code)

      assertWarnsCount(report, 1)
      assertErrorMessage(report, 'never checked')
    })

    it('should warn when variable is only assigned and never used', () => {
      const code = funcWith('bool success = addr.call(data); success = addr.call(otherData);')

      const report = lint(code)

      assertWarnsCount(report, 2)
      report.reports.forEach((r) => assert.ok(r.message.includes('never checked')))
    })

    it('should warn for staticcall and delegatecall captured results that are never judged', () => {
      const code = funcWith('bool a = addr.staticcall(data); (bool b, ) = addr.delegatecall(data);')

      const report = lint(code)

      assertWarnsCount(report, 2)
    })

    it('should warn for legacy addr.call.value(1)() captured result that is never judged', () => {
      const code = funcWith('(bool success, ) = addr.call.value(1)();')

      const report = lint(code)

      assertWarnsCount(report, 1)
      assertErrorMessage(report, 'never checked')
    })

    it('should report the new warning as error when configured with error severity', () => {
      const code = funcWith('bool success = addr.call(data);')

      const report = lint(code, 'error')

      assertErrorCount(report, 1)
      assert.equal(report.warningCount, 0)
      assertErrorMessage(report, 'never checked')
    })
  })

  describe('captured result that is properly judged (no regression)', () => {
    it('should not warn when tuple assignment is immediately used in require', () => {
      const code = funcWith('(bool success, ) = addr.call(data); require(success, "call failed");')

      const report = lint(code)

      assertNoWarnings(report)
    })

    it('should not warn when tuple assignment with bytes is used in require', () => {
      const code = funcWith(
        '(bool success, bytes memory result) = addr.call(data); require(success);',
      )

      const report = lint(code)

      assertNoWarnings(report)
    })

    it('should not warn when captured boolean is used inside an if statement', () => {
      const code = funcWith('bool success = addr.call(data); if (success) { revert(); }')

      const report = lint(code)

      assertNoWarnings(report)
    })

    it('should not warn when captured boolean is used inside a negated if condition', () => {
      const code = funcWith('bool success = addr.call(data); if (!success) { revert(); }')

      const report = lint(code)

      assertNoWarnings(report)
    })

    it('should not warn when captured boolean is used inside assert', () => {
      const code = funcWith('bool success = addr.call(data); assert(success);')

      const report = lint(code)

      assertNoWarnings(report)
    })

    it('should not warn when captured boolean is returned', () => {
      const code = `
contract A {
  function f() public returns (bool) {
    bool success = addr.call(data);
    return success;
  }
}`

      const report = lint(code)

      assertNoWarnings(report)
    })

    it('should not warn when captured boolean is passed as an argument to another call', () => {
      const code = funcWith('bool success = addr.call(data); handle(success);')

      const report = lint(code)

      assertNoWarnings(report)
    })

    it('should not warn when captured tuple boolean is passed as an argument', () => {
      const code = funcWith('(bool success, ) = addr.call(data); handle(success);')

      const report = lint(code)

      assertNoWarnings(report)
    })

    it('should not warn when call is directly wrapped in an if statement', () => {
      const report = lintWarn('if(addr.call(data)) {}')

      assertNoWarnings(report)
    })

    it('should not warn when call is directly wrapped in require', () => {
      const report = lintWarn('require(addr.call(data));')

      assertNoWarnings(report)
    })

    it('should not warn when call is directly wrapped in assert', () => {
      const report = lintWarn('assert(addr.call(data));')

      assertNoWarnings(report)
    })

    it('should not warn when staticcall is wrapped in require', () => {
      const report = lintWarn('require(addr.staticcall(data));')

      assertNoWarnings(report)
    })

    it('should not warn for value transfer call whose boolean is captured and checked', () => {
      const code = funcWith('(bool success, ) = addr.call{value: 1 ether}(""); require(success);')

      const report = lint(code)

      assertNoWarnings(report)
    })
  })

  describe('multiple low-level calls in the same function', () => {
    it('should only flag the unchecked call when one call is checked and another is discarded', () => {
      const code = funcWith(
        '(bool success, ) = addr.call(data); require(success); addr.call(otherData);',
      )

      const report = lint(code)

      assertWarnsCount(report, 1)
      assertErrorMessage(report, 'not checked')
      assert.ok(!report.reports[0].message.includes('never checked'))
    })

    it('should only flag the captured call that is never checked', () => {
      const code = funcWith(
        '(bool ok1, ) = addr.call(data); require(ok1); bool ok2 = addr.call(otherData);',
      )

      const report = lint(code)

      assertWarnsCount(report, 1)
      assertErrorMessage(report, 'never checked')
    })

    it('should flag both calls when both captured results are never checked', () => {
      const code = funcWith('bool ok1 = addr.call(data); bool ok2 = addr.call(otherData);')

      const report = lint(code)

      assertWarnsCount(report, 2)
      report.reports.forEach((r) => assert.ok(r.message.includes('never checked')))
    })

    it('should flag both discarded and never-checked calls independently', () => {
      const code = funcWith('addr.call(data); bool ok = addr.call(otherData);')

      const report = lint(code)

      assertWarnsCount(report, 2)
      const messages = report.reports.map((r) => r.message)
      assert.ok(messages.some((m) => m.includes('not checked') && !m.includes('never checked')))
      assert.ok(messages.some((m) => m.includes('never checked')))
    })

    it('should not flag anything when all calls to the same receiver are checked', () => {
      const code = funcWith(
        '(bool ok1, ) = addr.call(data); require(ok1); (bool ok2, ) = addr.call(otherData); require(ok2);',
      )

      const report = lint(code)

      assertNoWarnings(report)
    })
  })

  describe('autofix', () => {
    it('should provide a fix inserting a require check for the captured boolean (single var declaration)', () => {
      const code = funcWith('bool success = addr.call(data);')
      const report = lint(code)

      assertWarnsCount(report, 1)
      assert.equal(typeof report.reports[0].fix, 'function')

      const fixes = report.reports.map((r) => r.fix(ruleFixer))
      const { fixed, output } = applyFixes(fixes, code)

      assert.equal(fixed, true)
      assert.ok(output.includes('require(success);'), output)
      // original statement must be preserved
      assert.ok(output.includes('bool success = addr.call(data);'), output)
    })

    it('should provide a fix inserting a require check for tuple assignment', () => {
      const code = funcWith('(bool success, ) = addr.call(data);')
      const report = lint(code)

      assertWarnsCount(report, 1)
      assert.equal(typeof report.reports[0].fix, 'function')

      const { output } = applyFixes(
        report.reports.map((r) => r.fix(ruleFixer)),
        code,
      )

      assert.ok(output.includes('require(success);'), output)
    })

    it('should insert the require on the next line with matching indentation', () => {
      const code = `
contract A {
  function f() public {
    bool success = addr.call(data);
  }
}`
      const report = lint(code)

      const { output } = applyFixes(
        report.reports.map((r) => r.fix(ruleFixer)),
        code,
      )

      assert.ok(
        output.includes('    bool success = addr.call(data);\n    require(success);'),
        output,
      )
    })

    it('should fix multiple unchecked assignments in the same function without corrupting lines', () => {
      const code = `
contract A {
  function f() public {
    bool ok1 = addr.call(data);
    bool ok2 = addr.call(otherData);
  }
}`
      const report = lint(code)

      const { fixed, output } = applyFixes(
        report.reports.map((r) => r.fix(ruleFixer)),
        code,
      )

      assert.equal(fixed, true)
      assert.ok(output.includes('    bool ok1 = addr.call(data);\n    require(ok1);'), output)
      assert.ok(output.includes('    bool ok2 = addr.call(otherData);\n    require(ok2);'), output)
      // closing block must survive the fix
      assert.ok(output.includes('  }\n}'), output)
    })

    it('should insert the require before the closing brace when the assignment is the last statement', () => {
      const code = `contract A {
  function f() public {
    bool success = addr.call(data);
  }
}`
      const report = lint(code)

      const { output } = applyFixes(
        report.reports.map((r) => r.fix(ruleFixer)),
        code,
      )

      const expected = `contract A {
  function f() public {
    bool success = addr.call(data);
    require(success);
  }
}`
      assert.equal(output, expected)
    })

    it('should not warn and not fix when no boolean variable is captured (empty first tuple slot)', () => {
      const code = funcWith('(, bytes memory result) = addr.call(data);')
      const report = lint(code)

      assertNoWarnings(report)
      assert.equal(report.errorCount, 0)
    })

    it('should not track assignments whose target is not a simple identifier', () => {
      // member-access assignment cannot be safely named, so no report and no fix
      const code = funcWith('this.ok = addr.call(data);')
      const report = lint(code)

      assert.equal(report.warningCount + report.errorCount, 0)
    })
  })

  describe('modifier bodies', () => {
    it('should warn inside modifiers when the captured result is never checked', () => {
      const code = `
contract A {
  modifier m() {
    bool success = addr.call(data);
    _;
  }
}`
      const report = lint(code)

      assertWarnsCount(report, 1)
      assertErrorMessage(report, 'never checked')
    })

    it('should not warn inside modifiers when the captured result is checked', () => {
      const code = `
contract A {
  modifier m() {
    bool success = addr.call(data);
    require(success);
    _;
  }
}`
      const report = lint(code)

      assertNoWarnings(report)
    })
  })
})
