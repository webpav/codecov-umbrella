# `absorb-repo.sh`

This script absorbs a repository into the monorepo in a way that (mostly) preserves its history. History will be rewritten so that the repository's contents will be, or "will have always been", in a subdirectory, but otherwise the authors and dates of each commit will be preserved. Operations like `git blame` can continue past the point where the repository was absorbed.

Example usage:
```
$ ./absorb-repo.sh worker git@github.com:codecov/worker.git apps/worker
```
