# Commit Style

The Claircore project utilizes well structured commits to keep the history useful and help with release automation.
We suggest signing off on your commits as well.

A typical commit will take on the following structure:

```
<scope>: <subject>

<body>
Fixes #1
Pull Request #2

Signed-Off By: <email>
```

The header of the commit is regexp checked before commit and your commit will be kicked back if it does not conform.

## Scope

This is the section of code this commit influences. 

You will often see scopes such as "notifier", "auth", "chore", "cicd".

## Subject

Subject is a short and concise summary of the change the commit is introducing. It should be a sentence fragment without starting capitalization and ending punctuation and limited to about 60 characters, to allow for the scope prefix and decoration in the git log.

## Body

Body should be full of detail.

Explain what this commit is doing and why it is necessary.

You may include references to issues and pull requests as well.
