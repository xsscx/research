/**
 * @name Check GetValues functions in DB
 * @kind problem
 * @id icc/check-getvalues
 */
import cpp

from Function f
where f.getName().matches("%GetValues%") and f.getFile().getBaseName() = "IccTagBasic.cpp"
select f, f.getFile().getRelativePath() + ":" + f.getLocation().getStartLine().toString()
