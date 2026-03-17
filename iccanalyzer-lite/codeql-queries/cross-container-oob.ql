/**
 * @name Cross-container size mismatch causing OOB access (CWE-122)
 * @description A member variable is assigned from one container's size(),
 *              then used as a loop bound to index a DIFFERENT container
 *              via raw subscript or std::vector::operator[].
 *              If the two containers have different sizes, this causes
 *              heap-buffer-overflow.
 * @kind problem
 * @problem.severity error
 * @precision high
 * @id cpp/cross-container-oob
 * @tags security
 *       correctness
 *       external/cwe/cwe-119
 *       external/cwe/cwe-122
 */
import cpp

from
  AssignExpr assign, FunctionCall sizeCall, Variable boundVar,
  ForStmt loop, string sizeContainer, string indexContainer, int indexLine
where
  // Step 1: boundVar = someContainer.size()
  assign.getLValue().(VariableAccess).getTarget() = boundVar and
  sizeCall = assign.getRValue().getAChild*() and
  sizeCall.getTarget().hasName("size") and

  // Step 2: boundVar used as loop bound
  loop.getCondition().getAChild*().(VariableAccess).getTarget() = boundVar and

  // Step 3: Inside the loop, a DIFFERENT container is indexed
  // via raw array subscript OR std::vector::operator[]
  sizeContainer = sizeCall.getQualifier().toString() and
  (
    exists(ArrayExpr ae |
      ae.getEnclosingStmt().getParentStmt*() = loop.getStmt() and
      indexContainer = ae.getArrayBase().toString() and
      indexLine = ae.getLocation().getStartLine()
    )
    or
    exists(FunctionCall oc |
      oc.getEnclosingStmt().getParentStmt*() = loop.getStmt() and
      oc.getTarget().hasName("operator[]") and
      indexContainer = oc.getQualifier().toString() and
      indexLine = oc.getLocation().getStartLine()
    )
  ) and
  sizeContainer != indexContainer and

  // Same function scope
  assign.getEnclosingFunction() = loop.getEnclosingFunction()
select assign,
  "CWE-122: " + boundVar.getName() + " = " + sizeContainer + ".size() " +
  "but loop indexes " + indexContainer + " at line " + indexLine +
  ". If containers differ in size, this is a heap-buffer-overflow."
