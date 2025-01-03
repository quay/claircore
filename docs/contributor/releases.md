# Releases

Claircore releases are cut as and when they are needed.

Traditionally releases are always cut from the `main` branch so as not to complicate
the release process, however, on rare occasions when a fix is time-sensitive then
cutting a release from a release branch is possible.

## Process

> **_NOTE:_** Ensure changelog entries have been created for the relevant commits.
> (see [Changelog documentation](./changelog.md))

### From main

```sh
.github/scripts/prepare-release -b main -r upstream v1.x.x
```

Follow the `prepare-release` command's instructions to merge changelog updates and release the tag.

### From release branch

First create the relevant release branch (e.g if you are releasing `v1.6.1` create `release-1.6` from the
previous tag (in this case `v1.6.0`)). Then backport any commits and push up the release branch.

```sh
git branch release-1.x v1.x.x
git cherry-pick -x {commit sha}
git push upstream release-1.x
```

Finally, prepare the release specifying the release branch.

```sh
.github/scripts/prepare-release -b release-1.x -r upstream v1.x.x
```

Follow the `prepare-release` command's instructions to merge changelog updates and release the tag.
