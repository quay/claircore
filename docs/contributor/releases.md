# Releases

Claircore releases are cut when they are needed, as judged by the maintainers.

Releases are made from the `main` branch.
On rare occasions when a fix is time-sensitive, it is possible to create a release branch and make a release from it.

## Process

> **_NOTE:_** Ensure changelog entries have been created for the relevant commits.
> (see [Changelog documentation](./changelog.md))

### From main

```sh
NEW_VERSION=v0.999.999
.github/scripts/prepare-release -b main -r upstream "$NEW_VERSION"
```

Follow the `prepare-release` command's instructions to merge changelog updates and release the tag.

### From release branch

First, create the relevant release branch.
For example, if you are releasing `v0.999.1` create `release-v0.999` from the previous tag (in this case, `v0.999.0`).
Next, cherry-pick any needed commits with the `-x` flag to keep a reference to the original commit.
This may involve rewriting the changes.
Once the backports are done, push the release branch.

```sh
LAST_MINOR=v0.999.0
BRANCH=release-${LAST_MINOR%.*} # e.g. release-v0.999
git branch $BRANCH $LAST_MINOR
TO_BACKPORT=beefc0ffee # Use the commit digest of the original commit
git cherry-pick -x $TO_BACKPORT
git push upstream $BRANCH
```

Finally, prepare the release specifying the release branch.

```sh
LAST_MINOR=v0.999.0
NEW_VERSION=v0.999.1
BRANCH=release-${LAST_MINOR%.*} # e.g. release-v0.999
.github/scripts/prepare-release -b $BRANCH -r upstream $NEW_VERSION
```

Follow the `prepare-release` command's instructions to merge changelog updates and release the tag.
