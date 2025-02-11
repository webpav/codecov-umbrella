# `git-filter-repo`

Upstream project: https://github.com/newren/git-filter-repo

`git-filter-repo` is a replacement for the stock `git filter-branch` command
recommended by [the Git project itself](https://git-scm.com/docs/git-filter-branch#_warning).

The copy of the core `git-filter-repo` script included here is not modified.

Usage example:
```
# Rewrite the history of `local-worker-main` so that all repository content is placed in `apps/worker`
$ PATH="$PATH:." git filter-repo --force --refs local-worker-main --to-subdirectory-filter apps/worker
```
