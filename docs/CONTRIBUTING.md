# How to contribute

The preferred workflow is to fork the `quay/claircore` repository, push a feature branch to the new fork, then open a pull request.
All pull requests should be targeted to the `main` branch outside of exceptional circumstances.

## Testing

As many tests as possible should run with the standard `go test` invocations.
Adding the special tag `integration` (e.g. `go test -tags integration ./...`) will also run "integration" tests.
The project interprets "integration" tests to mean any test that would need external resources, such as:

- External web servers
- External network access
- Out-of-process databases
- Large test fixtures

After at least one run with the `integration` tag, the tests should cache needed resources and run as many tests as possible.
See also the [`test/integration`][doc-integration] package.

## Pull Requests

The Pull Request (PR) is the unit of code review.
Claircore's review flow treats a feature branch as a stack of patches to be applied.
That is to say, the feature branch should be rebased onto the target branch and have well-organized commits.
Merge commits are disallowed.
If the author would prefer to not rewrite commit history while working through reviews, [fixup commits] are the suggested way to achieve that.
As many requirements as possible are enforced by CI, like:

- Commits being signed off
- Commit messages having a properly formed subject
- Go modules being tidied

Please use the "draft" option if the branch is not ready.
Please enable the "allow edits by maintainers" option.

The maintainers may rebase, push, and merge contributors' branches.
This may necessitate doing a `git reset <remote>/<branch>` to update a local branch.

## Conventions

Git commits should be formatted like "subject: summary" and avoid going over 80 characters per line.
The "subject" is usually the package affected by the commit (like `jar` or `rhel` -- the relative path isn't needed) but sometimes a broader category (like `docs`, `all`, or `cicd`) is OK.

All the helper scripts should handle the "normal" convention (`origin` is `quay/claircore` and `fork` is one's personal fork) and the "British" convention (`origin` is one's personal fork and `upstream` is `quay/claircore`).

More detailed contributor documentation can be found in [the project documentation][docs].

[doc-integration]: https://pkg.go.dev/github.com/quay/claircore/test/integration
[fixup commits]: https://git-scm.com/docs/git-commit#Documentation/git-commit.txt---fixupamendrewordltcommitgt
[docs]: https://quay.github.io/claircore/contributor.html
