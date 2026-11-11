const BaseChecker = require('../base-checker')
const TreeTraversing = require('../../common/tree-traversing')
const {
  uncheckedCalls: NO_UNCHECKED_CALLS,
} = require('../../fixtureCases/security/low-level-calls')

const traversing = new TreeTraversing()

const LOW_LEVEL_CALLS = ['call', 'staticcall', 'delegatecall']

const WARN_UNCHECKED_CALLS = NO_UNCHECKED_CALLS[0]
const ALLOWED_UNCHECKED_CALLS = NO_UNCHECKED_CALLS[1]

const ruleId = 'no-unchecked-calls'
const meta = {
  type: 'security',

  docs: {
    description: 'Check return value of low-level calls (call, staticcall, delegatecall).',
    category: 'Security Rules',
    examples: {
      good: [
        {
          description: 'Return value of low-level call checked with tuple assignment',
          code: ALLOWED_UNCHECKED_CALLS.join('\n'),
        },
      ],
      bad: [
        {
          description: 'Return value of low-level call ignored',
          code: WARN_UNCHECKED_CALLS.join('\n'),
        },
      ],
    },
    notes: [
      {
        note: 'Unlike avoid-low-level-calls, this rule allows low-level calls but requires their return value to be checked.',
      },
      {
        note: 'Solhint can automatically insert a require() check for the captured boolean of an unchecked low-level call assignment using the `--fix` option.',
      },
    ],
  },

  recommended: true,
  defaultSetup: 'warn',
  fixable: true,

  schema: null,
}

class NoUncheckedCallsChecker extends BaseChecker {
  constructor(reporter, config, inputSrc) {
    super(reporter, ruleId, meta)
    this.inputSrc = inputSrc || ''
    // Stack of function/modifier scopes being analyzed, one per body.
    this.scopes = []
  }

  FunctionDefinition(node) {
    this._enterScope(node)
  }

  'FunctionDefinition:exit'(node) {
    this._exitScope(node)
  }

  ModifierDefinition(node) {
    this._enterScope(node)
  }

  'ModifierDefinition:exit'(node) {
    this._exitScope(node)
  }

  MemberAccess(node) {
    if (!LOW_LEVEL_CALLS.includes(node.memberName)) return

    // Walk up to the nearest FunctionCall (handles both addr.call(data) and addr.call{value}(data))
    const funcCall = this._outerLowLevelCall(node)
    if (!funcCall) return

    // If the final invocation is an ExpressionStatement, possibly wrapped in parentheses,
    // the return value is discarded. Other contexts consume or propagate the result.
    if (this._isDiscarded(funcCall)) {
      this.warn(node, 'Return value of low-level call is not checked.')
      return
    }

    // Track assignments that capture the return value but never judge it.
    const assignment = this._findCapturingAssignment(funcCall)
    if (assignment) {
      const scope = this._currentScope()
      if (scope) {
        scope.captures.push({
          node,
          funcCall,
          statement: assignment.statement,
          varNames: assignment.varNames,
        })
      }
    }
  }

  _enterScope(node) {
    if (!node.body) return
    this.scopes.push({ body: node.body, captures: [] })
  }

  _exitScope(node) {
    if (!node.body) return
    const scope = this.scopes.pop()
    if (!scope) return

    scope.captures.forEach((capture) => {
      const boolVars = capture.varNames.filter((entry) => entry.isBool)

      // No boolean captured (e.g. "(, bytes memory result) = ..."): nothing to judge.
      if (boolVars.length === 0) return

      const checked = boolVars.some((entry) =>
        this._isJudgedInBody(entry.name, capture.statement, scope.body),
      )

      if (!checked) {
        this._reportNeverChecked(capture, boolVars)
      }
    })
  }

  _currentScope() {
    return this.scopes.length > 0 ? this.scopes[this.scopes.length - 1] : null
  }

  _reportNeverChecked(capture, boolVars) {
    const { node, statement } = capture
    const message =
      'Return value of low-level call is assigned but never checked ' +
      '(use it in an if/require/assert condition, return it or pass it to another call).'

    const boolVarName = this._safeBoolVarName(boolVars)
    if (boolVarName) {
      this.warn(node, message, (fixer) => {
        const { range, text } = this._requireFix(statement, boolVarName)
        return fixer.replaceTextRange(range, text)
      })
    } else {
      this.warn(node, message)
    }
  }

  // Build a fix that inserts a require() on the line following the assignment.
  // lib/apply-fixes.js advances one character past every applied fix range
  // (i = range[1] + 1), so the range spans from the assignment semicolon to
  // the first content character of the line that follows; the replacement
  // reproduces that character, making the only effective change the inserted
  // require() line and leaving the rest of the file untouched.
  _requireFix(statement, varName) {
    const indentation = this._indentationOf(statement)
    const end = this._statementEnd(statement)
    const requireLine = `require(${varName});`

    const newlineIndex = this.inputSrc.indexOf('\n', end)
    if (newlineIndex === -1) {
      // No following line (assignment is the last content): emit the require
      // line after a fresh line break. The applier has nothing left to skip.
      return {
        range: [end, end],
        text: `\n${indentation}${requireLine}`,
      }
    }

    // Consume the line break, the following line's leading whitespace and its
    // first content character; reproduce all of them in the replacement text.
    const afterNewline = newlineIndex + 1
    const prefixMatch = /^[ \t]*/.exec(this.inputSrc.slice(afterNewline))
    const nextIndentation = prefixMatch ? prefixMatch[0] : ''
    const firstContentIndex = afterNewline + nextIndentation.length
    const firstContentChar = this.inputSrc[firstContentIndex] || ''

    return {
      range: [end, firstContentIndex],
      text: `\n${indentation}${requireLine}\n${nextIndentation}${firstContentChar}`,
    }
  }

  _statementEnd(statement) {
    // AST statement ranges exclude the trailing semicolon; the fix must be
    // inserted after it so the generated require() starts on the next line.
    const afterRange = this.inputSrc.slice(statement.range[1], statement.range[1] + 1)
    return afterRange === ';' ? statement.range[1] + 1 : statement.range[1]
  }

  _safeBoolVarName(boolVars) {
    // A fix is only safe when exactly one simple boolean identifier captured the result.
    if (boolVars.length !== 1) return null
    const { name } = boolVars[0]
    return typeof name === 'string' && /^[a-zA-Z_$][a-zA-Z0-9_$]*$/.test(name) ? name : null
  }

  _indentationOf(statement) {
    const src = this.inputSrc
    if (!src) return ''
    const lineStart = src.lastIndexOf('\n', statement.range[0]) + 1
    const prefix = src.slice(lineStart, statement.range[0])
    const match = /^[ \t]*/.exec(prefix)
    return match ? match[0] : ''
  }

  /**
   * A captured boolean is considered "judged" when, after its own assignment
   * statement and within the same function body, it is referenced in one of:
   *  - an if condition
   *  - a require/assert call
   *  - a return statement
   *  - arguments of another call
   */
  _isJudgedInBody(varName, ownStatement, body) {
    let found = false

    const visitIdentifier = (identifier) => {
      if (found || identifier.name !== varName) return
      if (this._isDeclarationIdentifier(identifier)) return
      if (this._isBeforeOrInside(identifier, ownStatement)) return

      if (this._isInJudgingContext(identifier)) {
        found = true
      }
    }

    this._walk(body, (n) => {
      if (n.type === 'Identifier') visitIdentifier(n)
    })

    return found
  }

  _isInJudgingContext(identifier) {
    let current = identifier

    while (current) {
      const parent = current.parent
      if (!parent) return false

      // The identifier (possibly nested in an expression) is part of an if condition.
      if (parent.type === 'IfStatement' && parent.condition === current) {
        return true
      }

      // The identifier is part of a returned expression.
      if (parent.type === 'ReturnStatement' && parent.expression === current) {
        return true
      }

      // The identifier (possibly nested in an expression) is an argument of a
      // call: require/assert directly judge the boolean, any other call still
      // propagates the value instead of silently dropping it.
      if (
        parent.type === 'FunctionCall' &&
        Array.isArray(parent.arguments) &&
        parent.arguments.includes(current)
      ) {
        return true
      }

      current = parent
    }

    return false
  }

  _isDeclarationIdentifier(identifier) {
    const parent = identifier.parent
    return (
      (parent && parent.type === 'VariableDeclaration' && parent.name === identifier.name) ||
      (parent && parent.type === 'IdentifierList')
    )
  }

  _isBeforeOrInside(identifier, statement) {
    if (identifier.range[1] <= statement.range[1]) return true
    // Identifiers nested inside the assignment statement itself (e.g. the
    // right-hand side of a re-assignment) must not count as a later judgement.
    let current = identifier
    while (current) {
      if (current === statement) return true
      current = current.parent
    }
    return false
  }

  _findCapturingAssignment(funcCall) {
    // Single variable declaration: bool ok = addr.call(data)
    // Tuple declaration:         (bool ok, ) = addr.call(data)
    let current = funcCall
    while (current.parent && current.parent.type === 'TupleExpression') {
      current = current.parent
    }

    const parent = current.parent
    if (!parent) return null

    if (parent.type === 'VariableDeclarationStatement' && parent.initialValue === current) {
      return {
        statement: parent,
        varNames: this._declaredVarNames(parent),
      }
    }

    // Assignment to an existing variable / tuple of variables:
    // ok = addr.call(data);  (ok, ) = addr.call(data);
    if (
      parent.type === 'BinaryOperation' &&
      parent.operator === '=' &&
      parent.right === current &&
      parent.parent &&
      parent.parent.type === 'ExpressionStatement'
    ) {
      const targetNames = this._assignedTargetNames(parent.left)
      if (targetNames.length === 0) return null
      return {
        statement: parent.parent,
        varNames: targetNames,
      }
    }

    return null
  }

  _declaredVarNames(statement) {
    return (statement.variables || [])
      .filter((variable) => variable && variable.name)
      .map((variable) => ({
        name: variable.name,
        isBool: this._isBoolType(variable),
      }))
  }

  _assignedTargetNames(target) {
    if (target.type === 'Identifier') {
      return [{ name: target.name, isBool: this._isBoolIdentifier(target) }]
    }

    if (target.type === 'TupleExpression') {
      return (target.components || [])
        .filter((component) => component && component.type === 'Identifier')
        .map((component) => ({
          name: component.name,
          isBool: this._isBoolIdentifier(component),
        }))
    }

    return []
  }

  _isBoolType(variable) {
    return !!(
      variable.typeName &&
      variable.typeName.type === 'ElementaryTypeName' &&
      variable.typeName.name === 'bool'
    )
  }

  _isBoolIdentifier(identifier) {
    // For plain assignments the type is not declared on the LHS node; fall back
    // to the enclosing scope's variable declarations when available.
    const declaration = this._findLocalDeclaration(identifier)
    if (declaration) return this._isBoolType(declaration)
    return false
  }

  _findLocalDeclaration(identifier) {
    const func = traversing.findParentType(identifier, 'FunctionDefinition')
    const modifier = traversing.findParentType(identifier, 'ModifierDefinition')
    const scopeBody = (func && func.body) || (modifier && modifier.body)
    if (!scopeBody) return null

    let found = null
    this._walk(scopeBody, (node) => {
      if (found) return
      if (
        node.type === 'VariableDeclaration' &&
        node.name === identifier.name &&
        this._isBoolType(node)
      ) {
        found = node
      }
    })
    return found
  }

  _outerLowLevelCall(node) {
    let funcCall = traversing.findParentType(node, 'FunctionCall')
    if (!funcCall) return null

    // Handle legacy addr.call.value(1)() / addr.call.value(1).gas(g)() patterns:
    // the first FunctionCall found is the modifier (.value/.gas), not the actual invocation.
    while (funcCall.parent) {
      const parent = funcCall.parent

      if (parent.type === 'FunctionCall' && parent.expression === funcCall) {
        funcCall = parent
        continue
      }

      if (
        parent.type === 'MemberAccess' &&
        parent.expression === funcCall &&
        parent.parent &&
        parent.parent.type === 'FunctionCall' &&
        parent.parent.expression === parent
      ) {
        funcCall = parent.parent
        continue
      }

      break
    }

    return funcCall
  }

  _isDiscarded(node) {
    let current = node

    while (current.parent && current.parent.type === 'TupleExpression') {
      current = current.parent
    }

    return current.parent && current.parent.type === 'ExpressionStatement'
  }

  // Generic AST walker (parents are attached by ast-parents).
  _walk(node, visit) {
    if (!node || typeof node.type !== 'string') return
    visit(node)

    Object.keys(node).forEach((key) => {
      if (key === 'parent' || key === 'loc' || key === 'range') return
      const value = node[key]
      if (Array.isArray(value)) {
        value.forEach((child) => this._walk(child, visit))
      } else if (value && typeof value.type === 'string') {
        this._walk(value, visit)
      }
    })
  }
}

module.exports = NoUncheckedCallsChecker
