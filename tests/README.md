# libhydrogen integration tests

To test integration between SecretBox and libhydrogen there is an MSVC project to compile the libhydrogen source to a dll. The Tests project then contains some interop code to P/Invoke into the libhydrogen dll.

## How it works

1. The build order has been set to build the Libhydrogen project before the Tests project. 
1. The Tests project has a custom PreBuild step to copy Libhydrogen.dll to the output folder of the Tests project. This can be found in Project Settings > Build Events.

## Pulling the latest source

The libhydrogen source code exists as a git submodule under `tests\libhydrogen\libhydrogen`.
To pull the latest source run:

```
cd tests\libhydrogen\libhydrogen
git pull
```

or alternatively from the root of the SecretBox project run

```
git submodule update --remote libhydrogen
```

## Adding functions to `LibhydrogenInterop`

When adding a new function to `LibhydrogenInterop` also add the function to `LibhydrogenExports.def`.

At the time of creating this project libhydrogen didn't (and may still not have) have any MSVC support, and none of the exports in hydrogen.h have `__declspec(dllexport)`.
Rather than edit the source and having to merge each time new changes come in, the exported functions are defined in a def file: `tests\libhydrogen\LibhydrogenExports.def`.

## Libhydrogen project notes

Some project configuration settings had to be changed to get libhydrogen to build:
1. Precompiled headers was set to 'No precompiled headers'.
1. SDL checks were set to 'No'.
1. The warnings 4197;4146 were suppressed.

The Output and Intermediate directories were also set to the custom values 'bin\' and '$(BaseIntermediateOutputPath)' respectively. This was to ensure that the dll gets output to a consistent location so that the PreBuild task in the Tests project can copy over the dll to its output folder.
