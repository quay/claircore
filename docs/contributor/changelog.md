The claircore project has switched from a [`git log`][log1] based changelog to a
[`git notes`][notes1] based changelog.

This has the benefit of making the changelog more human-friendly, as it can have
prose describing changes now, but makes adding entries a bit more involved. A
full understanding of `git notes` is helpful for working with the changelog, but
not required. If the reader has worked with the `notes` feature before, the
changelog entries are stored under the `changelog` ref. For other users, there
are some helper scripts in `.github/scripts`.

### Basics of `git notes`

`Git notes` is a mechanism for storing additional information alongside commits
without modifying the commits. It does this by creating a ref full of files
named after the commits, with their contents being the notes. This scheme
requires some special care and tooling -- see [the documentation][notes1] for
more information.

### Helper scripts

The primary helper script is `changelog-edit`. It allows a user to sync down
notes, edit an entry, or both. See the output of the `h` flag for more
information.

The other script of interest is `changelog-render`, which can be used to render
out the changelog on demand, assuming the changelog notes have been pulled
locally.

The `changelog-update` script uses `changelog-render` to add to the
`CHANGELOG.md` file in the repository root.

### Formatting

Broadly, changelog entries should be formatted like commit messages without any
trailers. Entries are turned into list items, with the subject being the bullet
point and the body of the entry being the "body" of the item, or hidden behind
`details` elements when using HTML-enabled output.

The entries are almost always rendered as markdown, so using minimal markdown is
OK. Anything requiring excessive markdown is probably better served as
documentation proper, rather than a changelog entry.

[log1]: https://git-scm.com/docs/git-log
[notes1]: https://git-scm.com/docs/git-notes
