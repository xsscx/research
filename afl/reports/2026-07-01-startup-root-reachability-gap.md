# AFL Startup Root Reachability Gap

- Date: 2026-07-01
- Scope: Covered-unreachable constructor anomalies in AFL coverage reports.
- Local audit helper: `afl/startup-roots.sh`

## Modeled Path

The static reachability analyzer should include C/C++ startup roots in addition
to `main`:

```text
ELF loader / C runtime startup
  -> executable .init_array
    -> _GLOBAL__sub_I_IccSolve.cpp
      -> __cxx_global_var_init
        -> CIccSimpleMatrixSolver::CIccSimpleMatrixSolver()
      -> __cxx_global_var_init.1
        -> CIccSimpleMatrixInverter::CIccSimpleMatrixInverter()
  -> main(...)
```

## Evidence

`IccSolve.cpp.o` contains a `.rela.init_array` relocation:

```text
.rela.init_array:
  .text.startup + 60
```

`nm` maps `.text.startup + 60` to:

```text
_GLOBAL__sub_I_IccSolve.cpp
```

The `_GLOBAL__sub_I_IccSolve.cpp` disassembly calls both static initialization
helpers:

```text
_GLOBAL__sub_I_IccSolve.cpp:
  call __cxx_global_var_init
  call __cxx_global_var_init.1
```

Those helpers call:

```text
__cxx_global_var_init:
  call CIccSimpleMatrixSolver::CIccSimpleMatrixSolver()

__cxx_global_var_init.1:
  call CIccSimpleMatrixInverter::CIccSimpleMatrixInverter()
```

The linked executable also contains `.init_array`,
`_GLOBAL__sub_I_IccSolve.cpp`,
`CIccSimpleMatrixSolver::CIccSimpleMatrixSolver()`, and
`CIccSimpleMatrixInverter::CIccSimpleMatrixInverter()`.

## Analyzer Fix

The upstream static reachability analyzer currently seeds from `main`, which
misses static initialization roots. It should also seed from:

- ELF `.preinit_array`
- ELF `.init_array`
- legacy `_init`
- compiler-generated `_GLOBAL__sub_I_*` functions reachable from those arrays

Once `.init_array` entries are roots, the two IccSolve constructors should move
from `statically_unreachable` to `statically_reachable via static
initialization`.

## Local Verification

Use the AFL helper against the object file or an unstripped executable:

```bash
./afl/startup-roots.sh iccDEV/Build/Cmake/IccProfLib/CMakeFiles/IccProfLib2-static.dir/home/h02332/po/research/iccDEV/IccProfLib/IccSolve.cpp.o
```

Expected signal:

```text
.rela.init_array ... .text.startup + 60
_GLOBAL__sub_I_IccSolve.cpp
__cxx_global_var_init
__cxx_global_var_init.1
CIccSimpleMatrixSolver::CIccSimpleMatrixSolver()
CIccSimpleMatrixInverter::CIccSimpleMatrixInverter()
```
