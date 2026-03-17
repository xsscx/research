/**
 * @name Float-to-integer cast without NaN/Inf check
 * @description Casting float/double values to integer types without checking
 *              for NaN or Inf produces undefined behavior.
 * @kind problem
 * @problem.severity error
 * @precision medium
 * @id icc/nan-float-to-int-cast
 * @tags security
 *       external/cwe/cwe-681
 *       external/cwe/cwe-190
 */
import cpp

from CStyleCast cast, Type srcType, Type dstType
where
  (srcType instanceof FloatType or srcType instanceof DoubleType) and
  (dstType instanceof IntType or dstType.getName().matches("icUInt%") or dstType.getName().matches("unsigned%")) and
  cast.getExpr().getType() = srcType and
  cast.getType() = dstType and
  exists(File f | f = cast.getFile() | f.getBaseName().matches("Icc%")) and
  // Exclude casts in condition expressions (those are likely checks)
  not exists(IfStmt ifstmt | cast.getParent*() = ifstmt.getCondition()) and
  // Focus on Apply/Exec/Read methods where file data flows through
  exists(Function fn | fn = cast.getEnclosingFunction() |
    fn.getName().regexpMatch("Apply|Exec|Read|Interp.*")
  )
select cast, "Float-to-" + dstType.getName() + " cast in " + cast.getEnclosingFunction().getName() + " without NaN/Inf check"
